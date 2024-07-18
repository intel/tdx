// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/mmu_context.h>

#include <asm/fpu/xcr.h>
#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "common.h"
#include "mmu.h"
#include "tdx.h"
#include "vmx.h"
#include "x86.h"
#include "mmu/spte.h"
#include "common.h"
#include "posted_intr.h"

#include <trace/events/kvm.h>
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/* TDX KeyID pool */
static DEFINE_IDA(tdx_guest_keyid_pool);

static int tdx_guest_keyid_alloc(void)
{
	return ida_alloc_range(&tdx_guest_keyid_pool, tdx_guest_keyid_start,
			       tdx_guest_keyid_start + tdx_nr_guest_keyids - 1,
			       GFP_KERNEL);
}

static void tdx_guest_keyid_free(int keyid)
{
	ida_free(&tdx_guest_keyid_pool, keyid);
}

struct tdx_info {
	u64 features0;
	u64 attributes_fixed0;
	u64 attributes_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;

	u16 max_vcpus_per_td;
	u8 nr_tdcs_pages;
	u8 nr_tdcx_pages;

	u16 num_cpuid_config;
	/* This must the last member. */
	DECLARE_FLEX_ARRAY(struct kvm_tdx_cpuid_config, cpuid_configs);
};

/* Info about the TDX module. */
static struct tdx_info *tdx_info;

int tdx_vm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	int r;

	switch (cap->cap) {
	case KVM_CAP_MAX_VCPUS: {
		if (cap->flags || cap->args[0] == 0)
			return -EINVAL;
		if (cap->args[0] > KVM_MAX_VCPUS ||
		    cap->args[0] > tdx_info->max_vcpus_per_td)
			return -E2BIG;

		mutex_lock(&kvm->lock);
		if (kvm->created_vcpus)
			r = -EBUSY;
		else {
			kvm->max_vcpus = cap->args[0];
			r = 0;
		}
		mutex_unlock(&kvm->lock);
		break;
	}
	default:
		r = -EINVAL;
		break;
	}
	return r;
}

/*
 * Some TDX SEAMCALLs (TDH.MNG.CREATE, TDH.PHYMEM.CACHE.WB,
 * TDH.MNG.KEY.RECLAIMID, TDH.MNG.KEY.FREEID etc) tries to acquire a global lock
 * internally in TDX module.  If failed, TDX_OPERAND_BUSY is returned without
 * spinning or waiting due to a constraint on execution time.  It's caller's
 * responsibility to avoid race (or retry on TDX_OPERAND_BUSY).  Use this mutex
 * to avoid race in TDX module because the kernel knows better about scheduling.
 */
static DEFINE_MUTEX(tdx_lock);
static struct mutex *tdx_mng_key_config_lock;

/*
 * A per-CPU list of TD vCPUs associated with a given CPU.  Used when a CPU
 * is brought down to invoke TDH_VP_FLUSH on the appropriate TD vCPUS.
 * Protected by interrupt mask.  This list is manipulated in process context
 * of vCPU and IPI callback.  See tdx_flush_vp_on_cpu().
 */
static DEFINE_PER_CPU(struct list_head, associated_tdvcpus);

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	return pa | ((hpa_t)hkid << boot_cpu_data.x86_phys_bits);
}

static __always_inline unsigned long tdexit_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rcx_read(vcpu);
}

static __always_inline unsigned long tdexit_ext_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rdx_read(vcpu);
}

static __always_inline unsigned long tdexit_gpa(struct kvm_vcpu *vcpu)
{
	return kvm_r8_read(vcpu);
}

static __always_inline unsigned long tdexit_intr_info(struct kvm_vcpu *vcpu)
{
	return kvm_r9_read(vcpu);
}

#define BUILD_TDVMCALL_ACCESSORS(param, gpr)				\
static __always_inline							\
unsigned long tdvmcall_##param##_read(struct kvm_vcpu *vcpu)		\
{									\
	return kvm_##gpr##_read(vcpu);					\
}									\
static __always_inline void tdvmcall_##param##_write(struct kvm_vcpu *vcpu, \
						     unsigned long val)	\
{									\
	kvm_##gpr##_write(vcpu, val);					\
}
BUILD_TDVMCALL_ACCESSORS(a0, r12);
BUILD_TDVMCALL_ACCESSORS(a1, r13);
BUILD_TDVMCALL_ACCESSORS(a2, r14);
BUILD_TDVMCALL_ACCESSORS(a3, r15);

static __always_inline unsigned long tdvmcall_exit_type(struct kvm_vcpu *vcpu)
{
	return kvm_r10_read(vcpu);
}
static __always_inline unsigned long tdvmcall_leaf(struct kvm_vcpu *vcpu)
{
	return kvm_r11_read(vcpu);
}
static __always_inline void tdvmcall_set_return_code(struct kvm_vcpu *vcpu,
						     long val)
{
	kvm_r10_write(vcpu, val);
}
static __always_inline void tdvmcall_set_return_val(struct kvm_vcpu *vcpu,
						    unsigned long val)
{
	kvm_r11_write(vcpu, val);
}

static inline bool is_td_vcpu_created(struct vcpu_tdx *tdx)
{
	return tdx->td_vcpu_created;
}

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr_pa;
}

static inline void tdx_hkid_free(struct kvm_tdx *kvm_tdx)
{
	tdx_guest_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
}

static inline bool is_hkid_assigned(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->hkid > 0;
}

static inline bool is_td_finalized(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->finalized;
}

static inline void tdx_disassociate_vp(struct kvm_vcpu *vcpu)
{
	lockdep_assert_irqs_disabled();

	list_del(&to_tdx(vcpu)->cpu_list);

	/*
	 * Ensure tdx->cpu_list is updated before setting vcpu->cpu to -1,
	 * otherwise, a different CPU can see vcpu->cpu = -1 and add the vCPU
	 * to its list before it's deleted from this CPU's list.
	 */
	smp_wmb();

	vcpu->cpu = -1;
}

static void tdx_disassociate_vp_arg(void *vcpu)
{
	tdx_disassociate_vp(vcpu);
}

static void tdx_disassociate_vp_on_cpu(struct kvm_vcpu *vcpu)
{
	int cpu = vcpu->cpu;

	if (unlikely(cpu == -1))
		return;

	smp_call_function_single(cpu, tdx_disassociate_vp_arg, vcpu, 1);
}

static void tdx_clear_page(unsigned long page_pa)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	void *page = __va(page_pa);
	unsigned long i;

	/*
	 * When re-assign one page from old keyid to a new keyid, MOVDIR64B is
	 * required to clear/write the page with new keyid to prevent integrity
	 * error when read on the page with new keyid.
	 *
	 * clflush doesn't flush cache with HKID set.  The cache line could be
	 * poisoned (even without MKTME-i), clear the poison bit.
	 */
	for (i = 0; i < PAGE_SIZE; i += 64)
		movdir64b(page + i, zero_page);
	/*
	 * MOVDIR64B store uses WC buffer.  Prevent following memory reads
	 * from seeing potentially poisoned cache.
	 */
	__mb();
}

static u64 ____tdx_reclaim_page(hpa_t pa, u64 *rcx, u64 *rdx, u64 *r8)
{
	u64 err;

	do {
		err = tdh_phymem_page_reclaim(pa, rcx, rdx, r8);
		/*
		 * TDH.PHYMEM.PAGE.RECLAIM is allowed only when TD is shutdown.
		 * state.  i.e. destructing TD.
		 * TDH.PHYMEM.PAGE.RECLAIM requires TDR and target page.
		 * Because we're destructing TD, it's rare to contend with TDR.
		 */
	} while (unlikely(err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX) ||
			  err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_TDR)));
	return err;
}

static int __tdx_reclaim_page(hpa_t pa)
{
	u64 err, rcx, rdx, r8;

	err = ____tdx_reclaim_page(pa, &rcx, &rdx, &r8);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error_3(TDH_PHYMEM_PAGE_RECLAIM, err, rcx, rdx, r8);
		return -EIO;
	}

	return 0;
}

static int tdx_reclaim_page(hpa_t pa)
{
	int r;

	r = __tdx_reclaim_page(pa);
	if (!r)
		tdx_clear_page(pa);
	return r;
}

static void tdx_reclaim_control_page(unsigned long td_page_pa)
{
	/*
	 * TDCX are being reclaimed.  TDX module maps TDCX with HKID
	 * assigned to the TD.  Here the cache associated to the TD
	 * was already flushed by TDH.PHYMEM.CACHE.WB before here, So
	 * cache doesn't need to be flushed again.
	 */
	if (tdx_reclaim_page(td_page_pa))
		/*
		 * Leak the page on failure:
		 * tdx_reclaim_page() returns an error if and only if there's an
		 * unexpected, fatal error, e.g. a SEAMCALL with bad params,
		 * incorrect concurrency in KVM, a TDX Module bug, etc.
		 * Retrying at a later point is highly unlikely to be
		 * successful.
		 * No log here as tdx_reclaim_page() already did.
		 */
		return;
	free_page((unsigned long)__va(td_page_pa));
}

struct tdx_flush_vp_arg {
	struct kvm_vcpu *vcpu;
	u64 err;
};

static void tdx_flush_vp(void *_arg)
{
	struct tdx_flush_vp_arg *arg = _arg;
	struct kvm_vcpu *vcpu = arg->vcpu;
	u64 err;

	arg->err = 0;
	lockdep_assert_irqs_disabled();

	/* Task migration can race with CPU offlining. */
	if (unlikely(vcpu->cpu != raw_smp_processor_id()))
		return;

	/*
	 * No need to do TDH_VP_FLUSH if the vCPU hasn't been initialized.  The
	 * list tracking still needs to be updated so that it's correct if/when
	 * the vCPU does get initialized.
	 */
	if (is_td_vcpu_created(to_tdx(vcpu))) {
		/*
		 * No need to retry.  TDX Resources needed for TDH.VP.FLUSH are:
		 * TDVPR as exclusive, TDR as shared, and TDCS as shared.  This
		 * vp flush function is called when destructing vCPU/TD or vCPU
		 * migration.  No other thread uses TDVPR in those cases.
		 */
		err = tdh_vp_flush(to_tdx(vcpu));
		if (unlikely(err && err != TDX_VCPU_NOT_ASSOCIATED)) {
			/*
			 * This function is called in IPI context. Do not use
			 * printk to avoid console semaphore.
			 * The caller prints out the error message, instead.
			 */
			if (err)
				arg->err = err;
		}
	}

	tdx_disassociate_vp(vcpu);
}

static void tdx_flush_vp_on_cpu(struct kvm_vcpu *vcpu)
{
	struct tdx_flush_vp_arg arg = {
		.vcpu = vcpu,
	};
	int cpu = vcpu->cpu;

	if (unlikely(cpu == -1))
		return;

	smp_call_function_single(cpu, tdx_flush_vp, &arg, 1);
	if (KVM_BUG_ON(arg.err, vcpu->kvm))
		pr_tdx_error(TDH_VP_FLUSH, arg.err);
}

void tdx_hardware_disable(void)
{
	int cpu = raw_smp_processor_id();
	struct list_head *tdvcpus = &per_cpu(associated_tdvcpus, cpu);
	struct tdx_flush_vp_arg arg;
	struct vcpu_tdx *tdx, *tmp;
	unsigned long flags;

	lockdep_assert_preemption_disabled();

	local_irq_save(flags);
	/* Safe variant needed as tdx_disassociate_vp() deletes the entry. */
	list_for_each_entry_safe(tdx, tmp, tdvcpus, cpu_list) {
		arg.vcpu = &tdx->vcpu;
		tdx_flush_vp(&arg);
	}
	local_irq_restore(flags);
}

static void tdx_do_tdh_phymem_cache_wb(void *unused)
{
	u64 err = 0;

	do {
		err = tdh_phymem_cache_wb(!!err);
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	/* Other thread may have done for us. */
	if (err == TDX_NO_HKID_READY_TO_WBCACHE)
		err = TDX_SUCCESS;
	if (WARN_ON_ONCE(err))
		pr_tdx_error(TDH_PHYMEM_CACHE_WB, err);
}

static int __tdx_mmu_release_hkid(struct kvm *kvm)
{
	bool packages_allocated, targets_allocated;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages, targets;
	struct kvm_vcpu *vcpu;
	unsigned long j;
	int i, ret = 0;
	u64 err;

	if (!is_hkid_assigned(kvm_tdx))
		return 0;

	if (!is_td_created(kvm_tdx)) {
		tdx_hkid_free(kvm_tdx);
		return 0;
	}

	packages_allocated = zalloc_cpumask_var(&packages, GFP_KERNEL);
	targets_allocated = zalloc_cpumask_var(&targets, GFP_KERNEL);
	cpus_read_lock();

	kvm_for_each_vcpu(j, vcpu, kvm)
		tdx_flush_vp_on_cpu(vcpu);

	/*
	 * We can destroy multiple guest TDs simultaneously.  Prevent
	 * tdh_phymem_cache_wb from returning TDX_BUSY by serialization.
	 */
	mutex_lock(&tdx_lock);

	/*
	 * Go through multiple TDX HKID state transitions with three SEAMCALLs
	 * to make TDH.PHYMEM.PAGE.RECLAIM() usable.  Make the transition atomic
	 * to other functions to operate private pages and Secure-EPT pages.
	 *
	 * Avoid race for kvm_gmem_release() to call kvm_mmu_unmap_gfn_range().
	 * This function is called via mmu notifier, mmu_release().
	 * kvm_gmem_release() is called via fput() on process exit.
	 */
	write_lock(&kvm->mmu_lock);

	err = tdh_mng_vpflushdone(kvm_tdx);
	if (err == TDX_FLUSHVP_NOT_DONE) {
		ret = -EBUSY;
		goto out;
	}
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_VPFLUSHDONE, err);
		pr_err("tdh_mng_vpflushdone() failed. HKID %d is leaked.\n",
		       kvm_tdx->hkid);
		ret = -EIO;
		goto out;
	}

	for_each_online_cpu(i) {
		if (packages_allocated &&
		    cpumask_test_and_set_cpu(topology_physical_package_id(i),
					     packages))
			continue;
		if (targets_allocated)
			cpumask_set_cpu(i, targets);
	}
	if (targets_allocated)
		on_each_cpu_mask(targets, tdx_do_tdh_phymem_cache_wb, NULL, true);
	else
		on_each_cpu(tdx_do_tdh_phymem_cache_wb, NULL, true);
	/*
	 * In the case of error in tdx_do_tdh_phymem_cache_wb(), the following
	 * tdh_mng_key_freeid() will fail.
	 */
	err = tdh_mng_key_freeid(kvm_tdx);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err);
		pr_err("tdh_mng_key_freeid() failed. HKID %d is leaked.\n",
		       kvm_tdx->hkid);
		ret = -EIO;
	} else
		tdx_hkid_free(kvm_tdx);

out:
	write_unlock(&kvm->mmu_lock);
	mutex_unlock(&tdx_lock);
	cpus_read_unlock();
	free_cpumask_var(targets);
	free_cpumask_var(packages);

	return ret;
}

void tdx_mmu_release_hkid(struct kvm *kvm)
{
	while (__tdx_mmu_release_hkid(kvm) == -EBUSY)
		;
}

void tdx_vm_free(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;
	int i;

	/*
	 * tdx_mmu_release_hkid() failed to reclaim HKID.  Something went wrong
	 * heavily with TDX module.  Give up freeing TD pages.  As the function
	 * already warned, don't warn it again.
	 */
	if (is_hkid_assigned(kvm_tdx))
		return;

	if (kvm_tdx->tdcs_pa) {
		for (i = 0; i < tdx_info->nr_tdcs_pages; i++) {
			if (kvm_tdx->tdcs_pa[i])
				tdx_reclaim_control_page(kvm_tdx->tdcs_pa[i]);
		}
		kfree(kvm_tdx->tdcs_pa);
		kvm_tdx->tdcs_pa = NULL;
	}

	if (!kvm_tdx->tdr_pa)
		return;
	if (__tdx_reclaim_page(kvm_tdx->tdr_pa))
		return;
	/*
	 * TDX module maps TDR with TDX global HKID.  TDX module may access TDR
	 * while operating on TD (Especially reclaiming TDCS).  Cache flush with
	 * TDX global HKID is needed.
	 */
	err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(kvm_tdx->tdr_pa,
						     tdx_global_keyid));
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err);
		return;
	}
	tdx_clear_page(kvm_tdx->tdr_pa);

	free_page((unsigned long)__va(kvm_tdx->tdr_pa));
	kvm_tdx->tdr_pa = 0;
}

static int tdx_do_tdh_mng_key_config(void *param)
{
	struct kvm_tdx *kvm_tdx = param;
	u64 err;

	do {
		err = tdh_mng_key_config(kvm_tdx);

		/*
		 * If it failed to generate a random key, retry it because this
		 * is typically caused by an entropy error of the CPU's random
		 * number generator.
		 */
	} while (err == TDX_KEY_GENERATION_FAILED);

	if (KVM_BUG_ON(err, &kvm_tdx->kvm)) {
		pr_tdx_error(TDH_MNG_KEY_CONFIG, err);
		return -EIO;
	}

	return 0;
}

int tdx_vm_init(struct kvm *kvm)
{
	kvm->arch.has_private_mem = true;

	/*
	 * Because guest TD is protected, VMM can't parse the instruction in TD.
	 * Instead, guest uses MMIO hypercall.  For unmodified device driver,
	 * #VE needs to be injected for MMIO and #VE handler in TD converts MMIO
	 * instruction into MMIO hypercall.
	 *
	 * SPTE value for MMIO needs to be setup so that #VE is injected into
	 * TD instead of triggering EPT MISCONFIG.
	 * - RWX=0 so that EPT violation is triggered.
	 * - suppress #VE bit is cleared to inject #VE.
	 */
	kvm_mmu_set_mmio_spte_value(kvm, 0);

	/*
	 * This function initializes only KVM software construct.  It doesn't
	 * initialize TDX stuff, e.g. TDCS, TDR, TDCX, HKID etc.
	 * It is handled by KVM_TDX_INIT_VM, __tdx_td_init().
	 */

	/*
	 * TDX has its own limit of the number of vcpus in addition to
	 * KVM_MAX_VCPUS.
	 */
	kvm->max_vcpus = min(kvm->max_vcpus, tdx_info->max_vcpus_per_td);
	return 0;
}

u8 tdx_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	if (is_mmio)
		return MTRR_TYPE_UNCACHABLE << VMX_EPT_MT_EPTE_SHIFT;

	if (!kvm_arch_has_noncoherent_dma(vcpu->kvm))
		return (MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT) | VMX_EPT_IPAT_BIT;

	/* TDX enforces CR0.CD = 0 and KVM MTRR emulation enforces writeback. */
	return MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT;
}

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/* TDX only supports x2APIC, which requires an in-kernel local APIC. */
	if (!vcpu->arch.apic)
		return -EINVAL;

	fpstate_set_confidential(&vcpu->arch.guest_fpu);
	vcpu->arch.apic->guest_apic_protected = true;
	INIT_LIST_HEAD(&tdx->pi_wakeup_list);

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.switch_db_regs = KVM_DEBUGREG_AUTO_SWITCH;
	vcpu->arch.cr0_guest_owned_bits = -1ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;

	vcpu->arch.tsc_offset = to_kvm_tdx(vcpu->kvm)->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	/*
	 * TODO: support off-TD debug.  If TD DEBUG is enabled, guest state
	 * can be accessed. guest_state_protected = false. and kvm ioctl to
	 * access CPU states should be usable for user space VMM (e.g. qemu).
	 *
	 * vcpu->arch.guest_state_protected =
	 *	!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTR_DEBUG);
	 */
	vcpu->arch.guest_state_protected = true;

	if ((kvm_tdx->xfam & XFEATURE_MASK_XTILE) == XFEATURE_MASK_XTILE)
		vcpu->arch.xfd_no_write_intercept = true;

	tdx->host_state_need_save = true;
	tdx->host_state_need_restore = false;

	tdx->pi_desc.nv = POSTED_INTR_VECTOR;
	__pi_set_sn(&tdx->pi_desc);

	return 0;
}

void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	vmx_vcpu_pi_load(vcpu, cpu);
	if (vcpu->cpu == cpu)
		return;

	tdx_flush_vp_on_cpu(vcpu);

	local_irq_disable();
	/*
	 * Pairs with the smp_wmb() in tdx_disassociate_vp() to ensure
	 * vcpu->cpu is read before tdx->cpu_list.
	 */
	smp_rmb();

	list_add(&tdx->cpu_list, &per_cpu(associated_tdvcpus, cpu));
	local_irq_enable();
}

bool tdx_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	/*
	 * KVM can't get the interrupt status of TDX guest and assumes interrupt
	 * is always allowed unless TDX guest calls TDVMCALL with HLT, which
	 * passes the interrupt block flag.
	 */
	if (to_tdx(vcpu)->exit_reason.basic != EXIT_REASON_TDCALL ||
	    tdvmcall_exit_type(vcpu) || tdvmcall_leaf(vcpu) != EXIT_REASON_HLT)
	    return true;

	return !tdvmcall_a0_read(vcpu);
}

bool tdx_protected_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	u64 vcpu_state_details;

	if (pi_has_pending_interrupt(vcpu))
		return true;

	vcpu_state_details =
		td_state_non_arch_read64(to_tdx(vcpu), TD_VCPU_STATE_DETAILS_NON_ARCH);

	return tdx_vcpu_state_details_intr_pending(vcpu_state_details);
}

/*
 * Compared to vmx_prepare_switch_to_guest(), there is not much to do
 * as SEAMCALL/SEAMRET calls take care of most of save and restore.
 */
void tdx_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (!tdx->host_state_need_save)
		return;

	if (likely(is_64bit_mm(current->mm)))
		tdx->msr_host_kernel_gs_base = current->thread.gsbase;
	else
		tdx->msr_host_kernel_gs_base = read_msr(MSR_KERNEL_GS_BASE);

	tdx->host_state_need_save = false;
}

static void tdx_prepare_switch_to_host(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	tdx->host_state_need_save = true;
	if (!tdx->host_state_need_restore)
		return;

	++vcpu->stat.host_state_reload;

	wrmsrl(MSR_KERNEL_GS_BASE, tdx->msr_host_kernel_gs_base);
	tdx->host_state_need_restore = false;
}

void tdx_vcpu_put(struct kvm_vcpu *vcpu)
{
	vmx_vcpu_pi_put(vcpu);
	tdx_prepare_switch_to_host(vcpu);
}

void tdx_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	/*
	 * When destroying VM, kvm_unload_vcpu_mmu() calls vcpu_load() for every
	 * vCPU after they already disassociated from the per-CPU list by
	 * tdx_mmu_release_hkid().  Disassociate them again, otherwise the
	 * freed vCPU data will be accessed during list_{del,add}() on
	 * associated_tdvcpus list later.
	 */
	tdx_disassociate_vp_on_cpu(vcpu);

	/*
	 * This methods can be called when vcpu allocation/initialization
	 * failed. So it's possible that hkid, tdvpx and tdvpr are not assigned
	 * yet.
	 */
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm)))
		return;

	if (tdx->tdcx_pa) {
		for (i = 0; i < tdx_info->nr_tdcx_pages; i++) {
			if (tdx->tdcx_pa[i])
				tdx_reclaim_control_page(tdx->tdcx_pa[i]);
		}
		kfree(tdx->tdcx_pa);
		tdx->tdcx_pa = NULL;
	}
	if (tdx->tdvpr_pa) {
		tdx_reclaim_control_page(tdx->tdvpr_pa);
		tdx->tdvpr_pa = 0;
	}
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{

	/* vcpu_deliver_init method silently discards INIT event. */
	if (init_event)
		return;
	if (is_td_vcpu_created(to_tdx(vcpu)))
		return;

	/*
	 * Don't update mp_state to runnable because more initialization
	 * is needed by TDX_VCPU_INIT.
	 */
}

static void tdx_complete_interrupts(struct kvm_vcpu *vcpu)
{
	/* Avoid costly SEAMCALL if no NMI was injected. */
	if (vcpu->arch.nmi_injected)
		vcpu->arch.nmi_injected = td_management_read8(to_tdx(vcpu),
							      TD_VCPU_PEND_NMI);
}

struct tdx_uret_msr {
	u32 msr;
	unsigned int slot;
	u64 defval;
};

static struct tdx_uret_msr tdx_uret_msrs[] = {
	{.msr = MSR_SYSCALL_MASK, .defval = 0x20200 },
	{.msr = MSR_STAR,},
	{.msr = MSR_LSTAR,},
	{.msr = MSR_TSC_AUX,},
};
static int tdx_uret_tsx_ctrl_slot;

static void tdx_user_return_msr_update_cache(struct kvm_vcpu *vcpu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++)
		kvm_user_return_msr_update_cache(tdx_uret_msrs[i].slot,
						 tdx_uret_msrs[i].defval);
	/*
	 * TSX_CTRL is reset to 0 if guest TSX is supported. Otherwise
	 * preserved.
	 */
	if (to_kvm_tdx(vcpu->kvm)->tsx_supported && tdx_uret_tsx_ctrl_slot != -1)
		kvm_user_return_msr_update_cache(tdx_uret_tsx_ctrl_slot, 0);
}

static void tdx_restore_host_xsave_state(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	if (static_cpu_has(X86_FEATURE_XSAVE) &&
	    host_xcr0 != (kvm_tdx->xfam & kvm_caps.supported_xcr0))
		xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
	if (static_cpu_has(X86_FEATURE_XSAVES) &&
	    /* PT can be exposed to TD guest regardless of KVM's XSS support */
	    host_xss != (kvm_tdx->xfam &
			 (kvm_caps.supported_xss | XFEATURE_MASK_PT |
			  XFEATURE_MASK_CET_USER | XFEATURE_MASK_CET_KERNEL)))
		wrmsrl(MSR_IA32_XSS, host_xss);
	if (static_cpu_has(X86_FEATURE_PKU) &&
	    (kvm_tdx->xfam & XFEATURE_MASK_PKRU))
		write_pkru(vcpu->arch.host_pkru);
}

static void tdx_vcpu_enter_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct tdx_module_args args;

	guest_state_enter_irqoff();

	/*
	 * TODO: optimization:
	 * - Eliminate copy between args and vcpu->arch.regs.
	 * - copyin/copyout registers only if (tdx->tdvmvall.regs_mask != 0)
	 *   which means TDG.VP.VMCALL.
	 */
	args = (struct tdx_module_args) {
		.rcx = tdx->tdvpr_pa,
#define REG(reg, REG)	.reg = vcpu->arch.regs[VCPU_REGS_ ## REG]
		REG(rdx, RDX),
		REG(r8,  R8),
		REG(r9,  R9),
		REG(r10, R10),
		REG(r11, R11),
		REG(r12, R12),
		REG(r13, R13),
		REG(r14, R14),
		REG(r15, R15),
		REG(rbx, RBX),
		REG(rdi, RDI),
		REG(rsi, RSI),
#undef REG
	};

	tdx->exit_reason.full = __seamcall_saved_ret(TDH_VP_ENTER, &args);

#define REG(reg, REG)	vcpu->arch.regs[VCPU_REGS_ ## REG] = args.reg
	REG(rcx, RCX);
	REG(rdx, RDX);
	REG(r8,  R8);
	REG(r9,  R9);
	REG(r10, R10);
	REG(r11, R11);
	REG(r12, R12);
	REG(r13, R13);
	REG(r14, R14);
	REG(r15, R15);
	REG(rbx, RBX);
	REG(rdi, RDI);
	REG(rsi, RSI);
#undef REG

	WARN_ON_ONCE(!kvm_rebooting &&
		     (tdx->exit_reason.full & TDX_SW_ERROR) == TDX_SW_ERROR);

	if ((u16)tdx->exit_reason.basic == EXIT_REASON_EXCEPTION_NMI &&
	    is_nmi(tdexit_intr_info(vcpu))) {
		kvm_before_interrupt(vcpu, KVM_HANDLING_NMI);
		vmx_do_nmi_irqoff();
		kvm_after_interrupt(vcpu);
	}
	guest_state_exit_irqoff();
}

fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu, bool force_immediate_exit)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/* tdx exit handle takes care of this error case. */
	if (unlikely(!tdx->initialized))
		return EXIT_FASTPATH_EXIT_HANDLED;
	if (unlikely(vcpu->kvm->vm_bugged)) {
		tdx->exit_reason.full = TDX_NON_RECOVERABLE_VCPU;
		return EXIT_FASTPATH_NONE;
	}

	trace_kvm_entry(vcpu, force_immediate_exit);

	if (pi_test_on(&tdx->pi_desc)) {
		apic->send_IPI_self(POSTED_INTR_VECTOR);

		kvm_wait_lapic_expire(vcpu);
	}

	tdx_vcpu_enter_exit(vcpu);

	tdx_user_return_msr_update_cache(vcpu);
	tdx_restore_host_xsave_state(vcpu);
	tdx->host_state_need_restore = true;

	vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;
	trace_kvm_exit(vcpu, KVM_ISA_VMX);

	tdx_complete_interrupts(vcpu);

	return EXIT_FASTPATH_NONE;
}

void tdx_inject_nmi(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.nmi_injections;
	td_management_write8(to_tdx(vcpu), TD_VCPU_PEND_NMI, 1);
}

void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	u16 exit_reason = tdx->exit_reason.basic;

	if (exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(vcpu,
						     tdexit_intr_info(vcpu));
	else if (exit_reason == EXIT_REASON_EXCEPTION_NMI)
		vmx_handle_exception_irqoff(vcpu, tdexit_intr_info(vcpu));
}

static int tdx_handle_exception_nmi(struct kvm_vcpu *vcpu)
{
	u32 intr_info = tdexit_intr_info(vcpu);

	/*
	 * Machine checks are handled by vmx_handle_exception_irqoff(), or by
	 * tdx_handle_exit() if a #MC occurs on VM-Entry.  NMIs are handled by
	 * tdx_vcpu_enter_exit().
	 */
	if (is_nmi(intr_info) || is_machine_check(intr_info))
		return 1;

	kvm_pr_unimpl("unexpected exception 0x%x(exit_reason 0x%llx qual 0x%lx)\n",
		intr_info,
		to_tdx(vcpu)->exit_reason.full, tdexit_exit_qual(vcpu));

	vcpu->run->exit_reason = KVM_EXIT_EXCEPTION;
	vcpu->run->ex.exception = intr_info & INTR_INFO_VECTOR_MASK;
	vcpu->run->ex.error_code = 0;

	return 0;
}

static int tdx_handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int tdx_handle_triple_fault(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	vcpu->mmio_needed = 0;
	return 0;
}

static int tdx_emulate_vmcall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;

	/*
	 * ABI for KVM tdvmcall argument:
	 * In Guest-Hypervisor Communication Interface(GHCI) specification,
	 * Non-zero leaf number (R10 != 0) is defined to indicate
	 * vendor-specific.  KVM uses this for KVM hypercall.  NOTE: KVM
	 * hypercall number starts from one.  Zero isn't used for KVM hypercall
	 * number.
	 *
	 * R10: KVM hypercall number
	 * arguments: R11, R12, R13, R14.
	 */
	nr = kvm_r10_read(vcpu);
	a0 = kvm_r11_read(vcpu);
	a1 = kvm_r12_read(vcpu);
	a2 = kvm_r13_read(vcpu);
	a3 = kvm_r14_read(vcpu);

	ret = __kvm_emulate_hypercall(vcpu, nr, a0, a1, a2, a3, true, 0);

	tdvmcall_set_return_code(vcpu, ret);

	if ((vcpu->kvm->arch.hypercall_exit_enabled & (1 << nr)) && !ret)
		return 0;
	return 1;
}

static int tdx_complete_vp_vmcall(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx_vmcall *tdx_vmcall = &vcpu->run->tdx.u.vmcall;
	__u64 reg_mask = kvm_rcx_read(vcpu);

#define COPY_REG(MASK, REG)							\
	do {									\
		if (reg_mask & TDX_VMCALL_REG_MASK_ ## MASK)			\
			kvm_## REG ## _write(vcpu, tdx_vmcall->out_ ## REG);	\
	} while (0)


	COPY_REG(R10, r10);
	COPY_REG(R11, r11);
	COPY_REG(R12, r12);
	COPY_REG(R13, r13);
	COPY_REG(R14, r14);
	COPY_REG(R15, r15);
	COPY_REG(RBX, rbx);
	COPY_REG(RDI, rdi);
	COPY_REG(RSI, rsi);
	COPY_REG(R8, r8);
	COPY_REG(R9, r9);
	COPY_REG(RDX, rdx);

#undef COPY_REG

	return 1;
}

static int tdx_vp_vmcall_to_user(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx_vmcall *tdx_vmcall = &vcpu->run->tdx.u.vmcall;
	__u64 reg_mask;

	vcpu->arch.complete_userspace_io = tdx_complete_vp_vmcall;
	memset(tdx_vmcall, 0, sizeof(*tdx_vmcall));

	vcpu->run->exit_reason = KVM_EXIT_TDX;
	vcpu->run->tdx.type = KVM_EXIT_TDX_VMCALL;

	reg_mask = kvm_rcx_read(vcpu);
	tdx_vmcall->reg_mask = reg_mask;

#define COPY_REG(MASK, REG)							\
	do {									\
		if (reg_mask & TDX_VMCALL_REG_MASK_ ## MASK) {			\
			tdx_vmcall->in_ ## REG = kvm_ ## REG ## _read(vcpu);	\
			tdx_vmcall->out_ ## REG = tdx_vmcall->in_ ## REG;	\
		}								\
	} while (0)


	COPY_REG(R10, r10);
	COPY_REG(R11, r11);
	COPY_REG(R12, r12);
	COPY_REG(R13, r13);
	COPY_REG(R14, r14);
	COPY_REG(R15, r15);
	COPY_REG(RBX, rbx);
	COPY_REG(RDI, rdi);
	COPY_REG(RSI, rsi);
	COPY_REG(R8, r8);
	COPY_REG(R9, r9);
	COPY_REG(RDX, rdx);

#undef COPY_REG

	/* notify userspace to handle the request */
	return 0;
}

static int tdx_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	/* EAX and ECX for cpuid is stored in R12 and R13. */
	eax = tdvmcall_a0_read(vcpu);
	ecx = tdvmcall_a1_read(vcpu);

	kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, false);

	tdvmcall_a0_write(vcpu, eax);
	tdvmcall_a1_write(vcpu, ebx);
	tdvmcall_a2_write(vcpu, ecx);
	tdvmcall_a3_write(vcpu, edx);

	tdvmcall_set_return_code(vcpu, TDVMCALL_SUCCESS);

	return 1;
}

static int tdx_emulate_hlt(struct kvm_vcpu *vcpu)
{
	tdvmcall_set_return_code(vcpu, TDVMCALL_SUCCESS);
	return kvm_emulate_halt_noskip(vcpu);
}

static int tdx_complete_pio_out(struct kvm_vcpu *vcpu)
{
	vcpu->arch.pio.count = 0;
	tdvmcall_set_return_code(vcpu, TDVMCALL_SUCCESS);
	tdvmcall_set_return_val(vcpu, 0);
	return 1;
}

static int tdx_complete_pio_in(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	int ret;

	ret = ctxt->ops->pio_in_emulated(ctxt, vcpu->arch.pio.size,
					 vcpu->arch.pio.port, &val, 1);

	WARN_ON_ONCE(!ret);

	tdvmcall_set_return_code(vcpu, TDVMCALL_SUCCESS);
	tdvmcall_set_return_val(vcpu, val);

	return 1;
}

static int tdx_emulate_io(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	unsigned int port;
	int size, ret;
	bool write;

	++vcpu->stat.io_exits;

	size = tdvmcall_a0_read(vcpu);
	write = tdvmcall_a1_read(vcpu);
	port = tdvmcall_a2_read(vcpu);

	if (size != 1 && size != 2 && size != 4) {
		tdvmcall_set_return_code(vcpu, TDVMCALL_INVALID_OPERAND);
		return 1;
	}

	if (write) {
		val = tdvmcall_a3_read(vcpu);
		ret = ctxt->ops->pio_out_emulated(ctxt, size, port, &val, 1);
	} else {
		ret = ctxt->ops->pio_in_emulated(ctxt, size, port, &val, 1);
	}

	if (ret) {
		tdvmcall_set_return_val(vcpu, val);
	} else {
		if (write)
			vcpu->arch.complete_userspace_io = tdx_complete_pio_out;
		else
			vcpu->arch.complete_userspace_io = tdx_complete_pio_in;
	}

	return ret;
}

static int tdx_complete_mmio(struct kvm_vcpu *vcpu)
{
	unsigned long val = 0;
	gpa_t gpa;
	int size;

	vcpu->mmio_needed = 0;

	if (!vcpu->mmio_is_write) {
		gpa = vcpu->mmio_fragments[0].gpa;
		size = vcpu->mmio_fragments[0].len;

		memcpy(&val, vcpu->run->mmio.data, size);
		tdvmcall_set_return_val(vcpu, val);
		trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	}
	return 1;
}

static inline int tdx_mmio_write(struct kvm_vcpu *vcpu, gpa_t gpa, int size,
				 unsigned long val)
{
	if (kvm_iodevice_write(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_write(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	trace_kvm_mmio(KVM_TRACE_MMIO_WRITE, size, gpa, &val);
	return 0;
}

static inline int tdx_mmio_read(struct kvm_vcpu *vcpu, gpa_t gpa, int size)
{
	unsigned long val;

	if (kvm_iodevice_read(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_read(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	tdvmcall_set_return_val(vcpu, val);
	trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	return 0;
}

static int tdx_emulate_mmio(struct kvm_vcpu *vcpu)
{
	struct kvm_memory_slot *slot;
	int size, write, r;
	unsigned long val;
	gpa_t gpa;

	size = tdvmcall_a0_read(vcpu);
	write = tdvmcall_a1_read(vcpu);
	gpa = tdvmcall_a2_read(vcpu);
	val = write ? tdvmcall_a3_read(vcpu) : 0;

	if (size != 1 && size != 2 && size != 4 && size != 8)
		goto error;
	if (write != 0 && write != 1)
		goto error;

	/* Strip the shared bit, allow MMIO with and without it set. */
	gpa = gpa & ~gfn_to_gpa(kvm_gfn_direct_bits(vcpu->kvm));

	if (size > 8u || ((gpa + size - 1) ^ gpa) & PAGE_MASK)
		goto error;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gpa_to_gfn(gpa));
	if (slot && !(slot->flags & KVM_MEMSLOT_INVALID))
		goto error;

	if (!kvm_io_bus_write(vcpu, KVM_FAST_MMIO_BUS, gpa, 0, NULL)) {
		trace_kvm_fast_mmio(gpa);
		return 1;
	}

	if (write)
		r = tdx_mmio_write(vcpu, gpa, size, val);
	else
		r = tdx_mmio_read(vcpu, gpa, size);
	if (!r) {
		/* Kernel completed device emulation. */
		tdvmcall_set_return_code(vcpu, TDVMCALL_SUCCESS);
		return 1;
	}

	/* Request the device emulation to userspace device model. */
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = write;
	vcpu->arch.complete_userspace_io = tdx_complete_mmio;

	vcpu->run->mmio.phys_addr = gpa;
	vcpu->run->mmio.len = size;
	vcpu->run->mmio.is_write = write;
	vcpu->run->exit_reason = KVM_EXIT_MMIO;

	if (write) {
		memcpy(vcpu->run->mmio.data, &val, size);
	} else {
		vcpu->mmio_fragments[0].gpa = gpa;
		vcpu->mmio_fragments[0].len = size;
		trace_kvm_mmio(KVM_TRACE_MMIO_READ_UNSATISFIED, size, gpa, NULL);
	}
	return 0;

error:
	tdvmcall_set_return_code(vcpu, TDVMCALL_INVALID_OPERAND);
	return 1;
}

static int tdx_emulate_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_a0_read(vcpu);
	u64 data;

	if (!kvm_msr_allowed(vcpu, index, KVM_MSR_FILTER_READ) ||
	    kvm_get_msr(vcpu, index, &data)) {
		trace_kvm_msr_read_ex(index);
		tdvmcall_set_return_code(vcpu, TDVMCALL_INVALID_OPERAND);
		return 1;
	}
	trace_kvm_msr_read(index, data);

	tdvmcall_set_return_code(vcpu, TDVMCALL_SUCCESS);
	tdvmcall_set_return_val(vcpu, data);
	return 1;
}

static int tdx_emulate_wrmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_a0_read(vcpu);
	u64 data = tdvmcall_a1_read(vcpu);

	if (!kvm_msr_allowed(vcpu, index, KVM_MSR_FILTER_WRITE) ||
	    kvm_set_msr(vcpu, index, data)) {
		trace_kvm_msr_write_ex(index, data);
		tdvmcall_set_return_code(vcpu, TDVMCALL_INVALID_OPERAND);
		return 1;
	}

	trace_kvm_msr_write(index, data);
	tdvmcall_set_return_code(vcpu, TDVMCALL_SUCCESS);
	return 1;
}

static int tdx_get_td_vm_call_info(struct kvm_vcpu *vcpu)
{
	if (tdvmcall_a0_read(vcpu))
		tdvmcall_set_return_code(vcpu, TDVMCALL_INVALID_OPERAND);
	else {
		tdvmcall_set_return_code(vcpu, TDVMCALL_SUCCESS);
		kvm_r11_write(vcpu, 0);
		tdvmcall_a0_write(vcpu, 0);
		tdvmcall_a1_write(vcpu, 0);
		tdvmcall_a2_write(vcpu, 0);
	}
	return 1;
}

static int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	if (tdvmcall_exit_type(vcpu))
		return tdx_emulate_vmcall(vcpu);

	switch (tdvmcall_leaf(vcpu)) {
	case EXIT_REASON_CPUID:
		return tdx_emulate_cpuid(vcpu);
	case EXIT_REASON_HLT:
		return tdx_emulate_hlt(vcpu);
	case EXIT_REASON_IO_INSTRUCTION:
		return tdx_emulate_io(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_emulate_mmio(vcpu);
	case EXIT_REASON_MSR_READ:
		return tdx_emulate_rdmsr(vcpu);
	case EXIT_REASON_MSR_WRITE:
		return tdx_emulate_wrmsr(vcpu);
	case TDVMCALL_GET_TD_VM_CALL_INFO:
		return tdx_get_td_vm_call_info(vcpu);
	default:
		break;
	}

	/*
	 * Unknown VMCALL.  Toss the request to the user space VMM, e.g. qemu,
	 * as it may know how to handle.
	 *
	 * Those VMCALLs require user space VMM:
	 * TDVMCALL_REPORT_FATAL_ERROR, TDVMCALL_MAP_GPA,
	 * TDVMCALL_SETUP_EVENT_NOTIFY_INTERRUPT, and TDVMCALL_GET_QUOTE.
	 */
	return tdx_vp_vmcall_to_user(vcpu);
}

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	td_vmcs_write64(to_tdx(vcpu), SHARED_EPT_POINTER, root_hpa);
}

static void tdx_unpin(struct kvm *kvm, kvm_pfn_t pfn)
{
	struct page *page = pfn_to_page(pfn);

	put_page(page);
}

static int tdx_mem_page_aug(struct kvm *kvm, gfn_t gfn,
			    enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	hpa_t hpa = pfn_to_hpa(pfn);
	gpa_t gpa = gfn_to_gpa(gfn);
	u64 entry, level_state;
	u64 err;

	err = tdh_mem_page_aug(kvm_tdx, gpa, hpa, &entry, &level_state);
	if (unlikely(err == TDX_ERROR_SEPT_BUSY)) {
		tdx_unpin(kvm, pfn);
		return -EAGAIN;
	}
	if (unlikely(err == (TDX_EPT_ENTRY_STATE_INCORRECT | TDX_OPERAND_ID_RCX))) {
		if (tdx_get_sept_level(level_state) == tdx_level &&
		    tdx_get_sept_state(level_state) == TDX_SEPT_PENDING &&
		    is_last_spte(entry, level) &&
		    spte_to_pfn(entry) == pfn &&
		    entry & VMX_EPT_SUPPRESS_VE_BIT) {
			tdx_unpin(kvm, pfn);
			WARN_ON_ONCE(!(to_kvm_tdx(kvm)->attributes &
				       TDX_TD_ATTR_SEPT_VE_DISABLE));
			return -EAGAIN;
		}
	}
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error_2(TDH_MEM_PAGE_AUG, err, entry, level_state);
		tdx_unpin(kvm, pfn);
		return -EIO;
	}

	return 0;
}

/*
 * KVM_MAP_MEMORY support to populate before finalize comes here for the initial
 * memory. Defer TDH.MEM.PAGE.ADD() until KVM_TDX_INIT_MEM_REGION.  Account the
 * number of pages only.
 */
static int tdx_mem_page_add(struct kvm *kvm, gfn_t gfn,
			    enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/*
	 * KVM_MAP_MEMORY for TD supports only 4K page because
	 * tdh_mem_page_add() supports only 4K page.
	 */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm)) {
		tdx_unpin(kvm, pfn);
		return -EINVAL;
	}

	/*
	 * KVM_TDX_INIT_MEM_REGION issues TDH.MEM.PAGE.ADD() and decrements
	 * nr_premapped
	 */
	atomic64_inc(&kvm_tdx->nr_premapped);
	return 0;
}

static int tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return -EINVAL;

	/*
	 * Because restricted mem doesn't support page migration with
	 * a_ops->migrate_page (yet), no callback isn't triggered for KVM on
	 * page migration.  Until restricted mem supports page migration,
	 * prevent page migration.
	 * TODO: Once restricted mem introduces callback on page migration,
	 * implement it and remove get_page/put_page().
	 */
	get_page(pfn_to_page(pfn));

	if (likely(is_td_finalized(kvm_tdx)))
		return tdx_mem_page_aug(kvm, gfn, level, pfn);

	return tdx_mem_page_add(kvm, gfn, level, pfn);
}

static u64 tdx_reclaim_td_page(struct kvm *kvm, hpa_t pa, enum pg_level level)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err, rcx, rdx, r8;

	err = ____tdx_reclaim_page(pa, &rcx, &rdx, &r8);
	if (unlikely(!is_td_finalized(kvm_tdx) &&
		     err == (TDX_PAGE_METADATA_INCORRECT | TDX_OPERAND_ID_RCX))) {
		/*
		 * Page is mapped by KVM_MAP_MEMORY, but not added by
		 * KVM_TDX_INIT_MEM_REGION.
		 */
		WARN_ON_ONCE(!atomic64_read(&kvm_tdx->nr_premapped));
		atomic64_dec(&kvm_tdx->nr_premapped);
		return 0;
	}
	if (unlikely(err)) {
		pr_tdx_error_3(TDH_PHYMEM_PAGE_RECLAIM, err, rcx, rdx, r8);
		return err;
	}
	return 0;
}

static int tdx_sept_drop_private_spte(struct kvm *kvm, gfn_t gfn,
				       enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = pfn_to_hpa(pfn);
	hpa_t hpa_with_hkid;
	u64 err, entry, level_state;

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return -EINVAL;

	if (unlikely(!is_hkid_assigned(kvm_tdx))) {
		/*
		 * The HKID assigned to this TD was already freed and cache
		 * was already flushed. We don't have to flush again.
		 */
		err = tdx_reclaim_td_page(kvm, hpa, level);
		if (KVM_BUG_ON(err, kvm))
			return -EIO;
		tdx_unpin(kvm, pfn);
		return 0;
	}

	do {
		/*
		 * When zapping private page, write lock is held. So no race
		 * condition with other vcpu sept operation.  Race only with
		 * TDH.VP.ENTER.
		 */
		err = tdh_mem_page_remove(kvm_tdx, gpa, tdx_level, &entry,
				&level_state);
	} while (unlikely(err == TDX_ERROR_SEPT_BUSY));
	if (unlikely(!is_td_finalized(kvm_tdx) &&
		     err == (TDX_EPT_WALK_FAILED | TDX_OPERAND_ID_RCX))) {
		/*
		 * This page was mapped with KVM_MAP_MEMORY, but
		 * KVM_TDX_INIT_MEM_REGION is not issued yet.
		 */
		if (!is_last_spte(entry, level) ||
				!(entry & VMX_EPT_RWX_MASK)) {
			WARN_ON_ONCE(!atomic64_read(&kvm_tdx->nr_premapped));
			atomic64_dec(&kvm_tdx->nr_premapped);
			tdx_unpin(kvm, pfn);
			return 0;
		}
	}
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error_2(TDH_MEM_PAGE_REMOVE, err, entry, level_state);
		return -EIO;
	}

	hpa_with_hkid = set_hkid_to_hpa(hpa, (u16)kvm_tdx->hkid);
	do {
		/*
		 * TDX_OPERAND_BUSY can happen on locking PAMT entry.  Because
		 * this page was removed above, other thread shouldn't be
		 * repeatedly operating on this page.  Just retry loop.
		 */
		err = tdh_phymem_page_wbinvd(hpa_with_hkid);
	} while (unlikely(err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX)));
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err);
		return -EIO;
	}
	tdx_clear_page(hpa);
	tdx_unpin(kvm, pfn);
	return 0;
}

static int tdx_sept_link_private_spt(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, void *private_spt)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = __pa(private_spt);
	u64 err, entry, level_state;

	err = tdh_mem_sept_add(kvm_tdx, gpa, tdx_level, hpa, &entry,
			&level_state);
	if (unlikely(err == TDX_ERROR_SEPT_BUSY))
		return -EAGAIN;
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error_2(TDH_MEM_SEPT_ADD, err, entry, level_state);
		return -EIO;
	}

	return 0;
}

static int tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn) & KVM_HPAGE_MASK(level);
	u64 err, entry, level_state;

	/* This can be called when destructing guest TD after freeing HKID. */
	if (unlikely(!is_hkid_assigned(kvm_tdx)))
		return 0;

	/* For now large page isn't supported yet. */
	WARN_ON_ONCE(level != PG_LEVEL_4K);
	err = tdh_mem_range_block(kvm_tdx, gpa, tdx_level, &entry,
			&level_state);
	if (unlikely(err == TDX_ERROR_SEPT_BUSY))
		return -EAGAIN;
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error_2(TDH_MEM_RANGE_BLOCK, err, entry, level_state);
		return -EIO;
	}
	return 0;
}

/*
 * TLB shoot down procedure:
 * There is a global epoch counter and each vcpu has local epoch counter.
 * - TDH.MEM.RANGE.BLOCK(TDR. level, range) on one vcpu
 *   This blocks the subsequenct creation of TLB translation on that range.
 *   This corresponds to clear the present bit(all RXW) in EPT entry
 * - TDH.MEM.TRACK(TDR): advances the epoch counter which is global.
 * - IPI to remote vcpus
 * - TDExit and re-entry with TDH.VP.ENTER on remote vcpus
 * - On re-entry, TDX module compares the local epoch counter with the global
 *   epoch counter.  If the local epoch counter is older than the global epoch
 *   counter, update the local epoch counter and flushes TLB.
 */
static void tdx_track(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;

	/* If TD isn't finalized, it's before any vcpu running. */
	if (unlikely(!is_td_finalized(kvm_tdx)))
		return;

	/*
	 * tdx_flush_tlb() waits for this function to issue TDH.MEM.TRACK() by
	 * the counter.  The counter is used instead of bool because multiple
	 * TDH_MEM_TRACK() can be issued concurrently by multiple vcpus.
	 *
	 * optimization: The TLB shoot down procedure described in The TDX
	 * specification is, TDH.MEM.TRACK(), send IPI to remote vcpus, confirm
	 * all remote vcpus exit to VMM, and execute vcpu, both local and
	 * remote.  Twist the sequence to reduce IPI overhead as follows.
	 *
	 * local			remote
	 * -----			------
	 * increment tdh_mem_track
	 *
	 * request KVM_REQ_TLB_FLUSH
	 * send IPI
	 *
	 *				TDEXIT to KVM due to IPI
	 *
	 *				IPI handler calls tdx_flush_tlb()
	 *                              to process KVM_REQ_TLB_FLUSH.
	 *				spin wait for tdh_mem_track == 0
	 *
	 * TDH.MEM.TRACK()
	 *
	 * decrement tdh_mem_track
	 *
	 *				complete KVM_REQ_TLB_FLUSH
	 *
	 * TDH.VP.ENTER to flush tlbs	TDH.VP.ENTER to flush tlbs
	 */
	atomic_inc(&kvm_tdx->tdh_mem_track);
	/*
	 * KVM_REQ_TLB_FLUSH waits for the empty IPI handler, ack_flush(), with
	 * KVM_REQUEST_WAIT.
	 */
	kvm_make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH);

	do {
		err = tdh_mem_track(kvm_tdx);
	} while (unlikely((err & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_BUSY));

	/* Release remote vcpu waiting for TDH.MEM.TRACK in tdx_flush_tlb(). */
	atomic_dec(&kvm_tdx->tdh_mem_track);

	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_TRACK, err);
}

static int tdx_sept_free_private_spt(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, void *private_spt)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/*
	 * The HKID assigned to this TD was already freed and cache was
	 * already flushed. We don't have to flush again.
	 */
	if (!is_hkid_assigned(kvm_tdx))
		return tdx_reclaim_page(__pa(private_spt));

	/*
	 * free_private_spt() is (obviously) called when a shadow page is being
	 * zapped.  KVM doesn't (yet) zap private SPs while the TD is active.
	 * Note: This function is for private shadow page.  Not for private
	 * guest page.   private guest page can be zapped during TD is active.
	 * shared <-> private conversion and slot move/deletion.
	 */
	KVM_BUG_ON(is_hkid_assigned(kvm_tdx), kvm);
	return -EINVAL;
}

int tdx_sept_flush_remote_tlbs(struct kvm *kvm)
{
	if (unlikely(!is_td(kvm)))
		return -EOPNOTSUPP;

	if (is_hkid_assigned(to_kvm_tdx(kvm)))
		tdx_track(kvm);

	return 0;
}

static int tdx_sept_remove_private_spte(struct kvm *kvm, gfn_t gfn,
					 enum pg_level level, kvm_pfn_t pfn)
{
	int ret;

	ret = tdx_sept_zap_private_spte(kvm, gfn, level);
	if (ret)
		return ret;

	/*
	 * TDX requires TLB tracking before dropping private page.  Do
	 * it here, although it is also done later.
	 * If hkid isn't assigned, the guest is destroying and no vcpu
	 * runs further.  TLB shootdown isn't needed.
	 *
	 * TODO: Call TDH.MEM.TRACK() only when we have called
	 * TDH.MEM.RANGE.BLOCK(), but not call TDH.MEM.TRACK() yet.
	 */
	if (is_hkid_assigned(to_kvm_tdx(kvm)))
		tdx_track(kvm);

	return tdx_sept_drop_private_spte(kvm, gfn, level, pfn);
}

void tdx_deliver_interrupt(struct kvm_lapic *apic, int delivery_mode,
			   int trig_mode, int vector)
{
	struct kvm_vcpu *vcpu = apic->vcpu;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/* TDX supports only posted interrupt.  No lapic emulation. */
	__vmx_deliver_posted_interrupt(vcpu, &tdx->pi_desc, vector);
}

static int tdx_handle_ept_violation(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qual;

	if (kvm_is_private_gpa(vcpu->kvm, tdexit_gpa(vcpu))) {
		/*
		 * Always treat SEPT violations as write faults.  Ignore the
		 * EXIT_QUALIFICATION reported by TDX-SEAM for SEPT violations.
		 * TD private pages are always RWX in the SEPT tables,
		 * i.e. they're always mapped writable.  Just as importantly,
		 * treating SEPT violations as write faults is necessary to
		 * avoid COW allocations, which will cause TDAUGPAGE failures
		 * due to aliasing a single HPA to multiple GPAs.
		 */
#define TDX_SEPT_VIOLATION_EXIT_QUAL	EPT_VIOLATION_ACC_WRITE
		exit_qual = TDX_SEPT_VIOLATION_EXIT_QUAL;
	} else {
		exit_qual = tdexit_exit_qual(vcpu);
		if (exit_qual & EPT_VIOLATION_ACC_INSTR) {
			pr_warn("kvm: TDX instr fetch to shared GPA = 0x%lx @ RIP = 0x%lx\n",
				tdexit_gpa(vcpu), kvm_rip_read(vcpu));
			vcpu->run->exit_reason = KVM_EXIT_EXCEPTION;
			vcpu->run->ex.exception = PF_VECTOR;
			vcpu->run->ex.error_code = exit_qual;
			return 0;
		}
	}

	trace_kvm_page_fault(vcpu, tdexit_gpa(vcpu), exit_qual);
	return __vmx_handle_ept_violation(vcpu, tdexit_gpa(vcpu), exit_qual);
}

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON;
	vcpu->run->internal.ndata = 2;
	vcpu->run->internal.data[0] = EXIT_REASON_EPT_MISCONFIG;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;

	return 0;
}

int tdx_handle_exit(struct kvm_vcpu *vcpu, fastpath_t fastpath)
{
	union tdx_exit_reason exit_reason = to_tdx(vcpu)->exit_reason;

	/* See the comment of tdx_seamcall_sept(). */
	if (unlikely(exit_reason.full == TDX_ERROR_SEPT_BUSY))
		return 1;

	/*
	 * TDH.VP.ENTER checks TD EPOCH which contend with TDH.MEM.TRACK and
	 * vcpu TDH.VP.ENTER.
	 */
	if (unlikely(exit_reason.full == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_TD_EPOCH)))
		return 1;

	if (unlikely(exit_reason.full == TDX_SEAMCALL_UD)) {
		kvm_spurious_fault();
		/*
		 * In the case of reboot or kexec, loop with TDH.VP.ENTER and
		 * TDX_SEAMCALL_UD to avoid unnecessarily activity.
		 */
		return 1;
	}

	if (unlikely(exit_reason.non_recoverable || exit_reason.error)) {
		if (unlikely(exit_reason.basic == EXIT_REASON_TRIPLE_FAULT))
			return tdx_handle_triple_fault(vcpu);

		kvm_pr_unimpl("TD exit 0x%llx, %d hkid 0x%x hkid pa 0x%llx\n",
			      exit_reason.full, exit_reason.basic,
			      to_kvm_tdx(vcpu->kvm)->hkid,
			      set_hkid_to_hpa(0, to_kvm_tdx(vcpu->kvm)->hkid));
		goto unhandled_exit;
	}

	/*
	 * When TDX module saw VMEXIT_REASON_FAILED_VMENTER_MC etc, TDH.VP.ENTER
	 * returns with TDX_SUCCESS | exit_reason with failed_vmentry = 1.
	 * Because TDX module maintains TD VMCS correctness, usually vmentry
	 * failure shouldn't happen.  In some corner cases it can happen.  For
	 * example
	 * - machine check during entry: EXIT_REASON_MCE_DURING_VMENTRY
	 * - TDH.VP.WR with debug TD.  VMM can corrupt TD VMCS
	 *   - EXIT_REASON_INVALID_STATE
	 *   - EXIT_REASON_MSR_LOAD_FAIL
	 */
	if (unlikely(exit_reason.failed_vmentry)) {
		pr_err("TDExit: exit_reason 0x%016llx qualification=%016lx ext_qualification=%016lx\n",
		       exit_reason.full, tdexit_exit_qual(vcpu), tdexit_ext_exit_qual(vcpu));
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= exit_reason.full;
		vcpu->run->fail_entry.cpu = vcpu->arch.last_vmentry_cpu;

		return 0;
	}

	if (unlikely(fastpath == EXIT_FASTPATH_EXIT_HANDLED)) {
		if (!to_tdx(vcpu)->initialized)
			return -EINVAL;
	}

	switch (exit_reason.basic) {
	case EXIT_REASON_EXCEPTION_NMI:
		return tdx_handle_exception_nmi(vcpu);
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return tdx_handle_external_interrupt(vcpu);
	case EXIT_REASON_TDCALL:
		return handle_tdvmcall(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_handle_ept_violation(vcpu);
	case EXIT_REASON_EPT_MISCONFIG:
		return tdx_handle_ept_misconfig(vcpu);
	case EXIT_REASON_OTHER_SMI:
		/*
		 * Unlike VMX, SMI in SEAM non-root mode (i.e. when
		 * TD guest vCPU is running) will cause VM exit to TDX module,
		 * then SEAMRET to KVM.  Once it exits to KVM, SMI is delivered
		 * and handled by kernel handler right away.
		 *
		 * The Other SMI exit can also be caused by the SEAM non-root
		 * machine check delivered via Machine Check System Management
		 * Interrupt (MSMI), but it has already been handled by the
		 * kernel machine check handler, i.e., the memory page has been
		 * marked as poisoned and it won't be freed to the free list
		 * when the TDX guest is terminated (the TDX module marks the
		 * guest as dead and prevent it from further running when
		 * machine check happens in SEAM non-root).
		 *
		 * - A MSMI will not reach here, it's handled as non_recoverable
		 *   case above.
		 * - If it's not an MSMI, no need to do anything here.
		 */
		return 1;
	default:
		break;
	}

unhandled_exit:
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON;
	vcpu->run->internal.ndata = 2;
	vcpu->run->internal.data[0] = exit_reason.full;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;
	return 0;
}

void tdx_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason,
		u64 *info1, u64 *info2, u32 *intr_info, u32 *error_code)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	*reason = tdx->exit_reason.full;

	*info1 = tdexit_exit_qual(vcpu);
	*info2 = tdexit_ext_exit_qual(vcpu);

	*intr_info = tdexit_intr_info(vcpu);
	*error_code = 0;
}

bool tdx_has_emulated_msr(u32 index)
{
	switch (index) {
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_ARCH_CAPABILITIES:
	case MSR_IA32_POWER_CTL:
	case MSR_MTRRcap:
	case MSR_IA32_CR_PAT:
	case MSR_MTRRdefType:
	case MSR_IA32_TSC_DEADLINE:
	case MSR_IA32_MISC_ENABLE:
	case MSR_PLATFORM_INFO:
	case MSR_MISC_FEATURES_ENABLES:
	case MSR_IA32_APICBASE:
	case MSR_EFER:
	case MSR_IA32_FEAT_CTL:
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_EXT_CTL:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MCx_CTL(KVM_MAX_MCE_BANKS) - 1:
	case MSR_IA32_MC0_CTL2 ... MSR_IA32_MCx_CTL2(KVM_MAX_MCE_BANKS) - 1:
		/* MSR_IA32_MCx_{CTL, STATUS, ADDR, MISC, CTL2} */
	case MSR_KVM_POLL_CONTROL:
		return true;
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0xff:
		/*
		 * x2APIC registers that are virtualized by the CPU can't be
		 * emulated, KVM doesn't have access to the virtual APIC page.
		 */
		switch (index) {
		case X2APIC_MSR(APIC_TASKPRI):
		case X2APIC_MSR(APIC_PROCPRI):
		case X2APIC_MSR(APIC_EOI):
		case X2APIC_MSR(APIC_ISR) ... X2APIC_MSR(APIC_ISR + APIC_ISR_NR):
		case X2APIC_MSR(APIC_TMR) ... X2APIC_MSR(APIC_TMR + APIC_ISR_NR):
		case X2APIC_MSR(APIC_IRR) ... X2APIC_MSR(APIC_IRR + APIC_ISR_NR):
			return false;
		default:
			return true;
		}
	default:
		return false;
	}
}

static bool tdx_is_read_only_msr(u32 index)
{
	return  index == MSR_IA32_APICBASE || index == MSR_EFER ||
		index == MSR_IA32_FEAT_CTL;
}

int tdx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	switch (msr->index) {
	case MSR_IA32_FEAT_CTL:
		/*
		 * MCE and MCA are advertised via cpuid. guest kernel could
		 * check if LMCE is enabled or not.
		 */
		msr->data = FEAT_CTL_LOCKED;
		if (vcpu->arch.mcg_cap & MCG_LMCE_P)
			msr->data |= FEAT_CTL_LMCE_ENABLED;
		return 0;
	case MSR_IA32_MCG_EXT_CTL:
		if (!msr->host_initiated && !(vcpu->arch.mcg_cap & MCG_LMCE_P))
			return 1;
		msr->data = vcpu->arch.mcg_ext_ctl;
		return 0;
	case MSR_MTRRcap:
		/*
		 * Override kvm_mtrr_get_msr() which hardcodes the value.
		 * Report SMRR = 0, WC = 0, FIX = 0 VCNT = 0 to disable MTRR
		 * effectively.
		 */
		msr->data = 0;
		return 0;
	default:
		if (!tdx_has_emulated_msr(msr->index))
			return 1;

		return kvm_get_msr_common(vcpu, msr);
	}
}

int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	switch (msr->index) {
	case MSR_IA32_MCG_EXT_CTL:
		if (!msr->host_initiated && !(vcpu->arch.mcg_cap & MCG_LMCE_P))
			return 1;
		vcpu->arch.mcg_ext_ctl = msr->data;
		return 0;
	case MSR_MTRRdefType:
		/*
		 * Allow writeback only for all memory.
		 * Because it's reported that fixed range MTRR isn't supported
		 * and VCNT=0, enforce MTRRDefType.FE = 0 and don't care
		 * variable range MTRRs. Only default memory type matters.
		 *
		 * bit 11 E: MTRR enable/disable
		 * bit 12 FE: Fixed-range MTRRs enable/disable
		 * (E, FE) = (1, 1): enable MTRR and Fixed range MTRR
		 * (E, FE) = (1, 0): enable MTRR, disable Fixed range MTRR
		 * (E, FE) = (0, *): disable all MTRRs.  all physical memory
		 *                   is UC
		 */
		if (msr->data != ((1 << 11) | MTRR_TYPE_WRBACK))
			return 1;
		return kvm_set_msr_common(vcpu, msr);
	default:
		if (tdx_is_read_only_msr(msr->index))
			return 1;

		if (!tdx_has_emulated_msr(msr->index))
			return 1;

		return kvm_set_msr_common(vcpu, msr);
	}
}

void tdx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	kvm_register_mark_available(vcpu, reg);
	switch (reg) {
	case VCPU_REGS_RSP:
	case VCPU_REGS_RIP:
	case VCPU_EXREG_PDPTR:
	case VCPU_EXREG_CR0:
	case VCPU_EXREG_CR3:
	case VCPU_EXREG_CR4:
		break;
	default:
		KVM_BUG_ON(1, vcpu->kvm);
		break;
	}
}

static int tdx_get_capabilities(struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities *caps = NULL;
	int ret = 0;

	if (cmd->flags)
		return -EINVAL;

	caps = kmalloc(sizeof(*caps), GFP_KERNEL);
	if (!caps)
		return -ENOMEM;

	user_caps = u64_to_user_ptr(cmd->data);
	if (copy_from_user(caps, user_caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}

	if (caps->nr_cpuid_configs < tdx_info->num_cpuid_config) {
		ret = -E2BIG;
		goto out;
	}

	*caps = (struct kvm_tdx_capabilities) {
		.attrs_fixed0 = tdx_info->attributes_fixed0,
		.attrs_fixed1 = tdx_info->attributes_fixed1,
		.xfam_fixed0 = tdx_info->xfam_fixed0,
		.xfam_fixed1 = tdx_info->xfam_fixed1,
		.supported_gpaw = TDX_CAP_GPAW_48 |
		((kvm_get_shadow_phys_bits() >= 52 &&
		  cpu_has_vmx_ept_5levels()) ? TDX_CAP_GPAW_52 : 0),
		.nr_cpuid_configs = tdx_info->num_cpuid_config,
		.padding = 0,
	};

	if (copy_to_user(user_caps, caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}
	if (copy_to_user(user_caps->cpuid_configs, &tdx_info->cpuid_configs,
			 tdx_info->num_cpuid_config *
			 sizeof(tdx_info->cpuid_configs[0]))) {
		ret = -EFAULT;
	}

out:
	/* kfree() accepts NULL. */
	kfree(caps);
	return ret;
}

static int setup_tdparams_eptp_controls(struct kvm_cpuid2 *cpuid,
					struct td_params *td_params)
{
	const struct kvm_cpuid_entry2 *entry;
	int max_pa = 36;

	entry = kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent, 0x80000008, 0);
	if (entry)
		max_pa = entry->eax & 0xff;

	td_params->eptp_controls = VMX_EPTP_MT_WB;
	/*
	 * No CPU supports 4-level && max_pa > 48.
	 * "5-level paging and 5-level EPT" section 4.1 4-level EPT
	 * "4-level EPT is limited to translating 48-bit guest-physical
	 *  addresses."
	 * cpu_has_vmx_ept_5levels() check is just in case.
	 */
	if (!cpu_has_vmx_ept_5levels() && max_pa > 48)
		return -EINVAL;
	if (cpu_has_vmx_ept_5levels() && max_pa > 48) {
		td_params->eptp_controls |= VMX_EPTP_PWL_5;
		td_params->exec_controls |= TDX_EXEC_CONTROL_MAX_GPAW;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
	}

	return 0;
}

static void setup_tdparams_cpuids(struct kvm_cpuid2 *cpuid,
				  struct td_params *td_params)
{
	int i;

	/*
	 * td_params.cpuid_values: The number and the order of cpuid_value must
	 * be same to the one of struct tdsysinfo.{num_cpuid_config, cpuid_configs}
	 * It's assumed that td_params was zeroed.
	 */
	for (i = 0; i < tdx_info->num_cpuid_config; i++) {
		const struct kvm_tdx_cpuid_config *c = &tdx_info->cpuid_configs[i];
		/* KVM_TDX_CPUID_NO_SUBLEAF means index = 0. */
		u32 index = c->sub_leaf == KVM_TDX_CPUID_NO_SUBLEAF ? 0 : c->sub_leaf;
		const struct kvm_cpuid_entry2 *entry =
			kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent,
					      c->leaf, index);
		struct tdx_cpuid_value *value = &td_params->cpuid_values[i];

		if (!entry)
			continue;

		/*
		 * tdsysinfo.cpuid_configs[].{eax, ebx, ecx, edx}
		 * bit 1 means it can be configured to zero or one.
		 * bit 0 means it must be zero.
		 * Mask out non-configurable bits.
		 */
		value->eax = entry->eax & c->eax;
		value->ebx = entry->ebx & c->ebx;
		value->ecx = entry->ecx & c->ecx;
		value->edx = entry->edx & c->edx;
	}
}

static int setup_tdparams_xfam(struct kvm_cpuid2 *cpuid, struct td_params *td_params)
{
	const struct kvm_cpuid_entry2 *entry;
	u64 guest_supported_xcr0;
	u64 guest_supported_xss;

	/* Setup td_params.xfam */
	entry = kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent, 0xd, 0);
	if (entry)
		guest_supported_xcr0 = (entry->eax | ((u64)entry->edx << 32));
	else
		guest_supported_xcr0 = 0;
	guest_supported_xcr0 &= kvm_caps.supported_xcr0;

	entry = kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent, 0xd, 1);
	if (entry)
		guest_supported_xss = (entry->ecx | ((u64)entry->edx << 32));
	else
		guest_supported_xss = 0;

	/*
	 * PT and CET can be exposed to TD guest regardless of KVM's XSS, PT
	 * and, CET support.
	 */
	guest_supported_xss &=
		(kvm_caps.supported_xss | XFEATURE_MASK_PT |
		 XFEATURE_MASK_CET_USER | XFEATURE_MASK_CET_KERNEL);

	td_params->xfam = guest_supported_xcr0 | guest_supported_xss;
	if (td_params->xfam & XFEATURE_MASK_LBR) {
		/*
		 * TODO: once KVM supports LBR(save/restore LBR related
		 * registers around TDENTER), remove this guard.
		 */
#define MSG_LBR	"TD doesn't support LBR yet. KVM needs to save/restore IA32_LBR_DEPTH properly.\n"
		pr_warn(MSG_LBR);
		return -EOPNOTSUPP;
	}

	return 0;
}

static bool tdparams_tsx_supported(struct kvm_cpuid2 *cpuid)
{
	const struct kvm_cpuid_entry2 *entry;
	u64 mask;
	u32 ebx;

	entry = kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent, 0x7, 0);
	if (entry)
		ebx = entry->ebx;
	else
		ebx = 0;

	mask = __feature_bit(X86_FEATURE_HLE) | __feature_bit(X86_FEATURE_RTM);
	return ebx & mask;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params,
			struct kvm_tdx_init_vm *init_vm)
{
	struct kvm_cpuid2 *cpuid = &init_vm->cpuid;
	int ret;

	if (kvm->created_vcpus)
		return -EBUSY;

	if (init_vm->attributes & TDX_TD_ATTR_PERFMON) {
		/*
		 * TODO: save/restore PMU related registers around TDENTER.
		 * Once it's done, remove this guard.
		 */
#define MSG_PERFMON	"TD doesn't support perfmon yet. KVM needs to save/restore host perf registers properly.\n"
		pr_warn(MSG_PERFMON);
		return -EOPNOTSUPP;
	}

	td_params->max_vcpus = kvm->max_vcpus;
	td_params->attributes = init_vm->attributes;
	td_params->exec_controls = TDX_CONTROL_FLAG_NO_RBP_MOD;
	td_params->tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(kvm->arch.default_tsc_khz);

	ret = setup_tdparams_eptp_controls(cpuid, td_params);
	if (ret)
		return ret;
	setup_tdparams_cpuids(cpuid, td_params);
	ret = setup_tdparams_xfam(cpuid, td_params);
	if (ret)
		return ret;

#define MEMCPY_SAME_SIZE(dst, src)				\
	do {							\
		BUILD_BUG_ON(sizeof(dst) != sizeof(src));	\
		memcpy((dst), (src), sizeof(dst));		\
	} while (0)

	MEMCPY_SAME_SIZE(td_params->mrconfigid, init_vm->mrconfigid);
	MEMCPY_SAME_SIZE(td_params->mrowner, init_vm->mrowner);
	MEMCPY_SAME_SIZE(td_params->mrownerconfig, init_vm->mrownerconfig);

	to_kvm_tdx(kvm)->tsx_supported = tdparams_tsx_supported(cpuid);
	return 0;
}

static int __tdx_td_init(struct kvm *kvm, struct td_params *td_params,
			 u64 *seamcall_err)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	unsigned long *tdcs_pa = NULL;
	unsigned long tdr_pa = 0;
	unsigned long va;
	int ret, i;
	u64 err, rcx;

	*seamcall_err = 0;
	ret = tdx_guest_keyid_alloc();
	if (ret < 0)
		return ret;
	kvm_tdx->hkid = ret;

	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		goto free_hkid;
	tdr_pa = __pa(va);

	tdcs_pa = kcalloc(tdx_info->nr_tdcs_pages, sizeof(*kvm_tdx->tdcs_pa),
			  GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!tdcs_pa)
		goto free_tdr;
	for (i = 0; i < tdx_info->nr_tdcs_pages; i++) {
		va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!va)
			goto free_tdcs;
		tdcs_pa[i] = __pa(va);
	}

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_tdcs;
	}
	cpus_read_lock();
	/*
	 * Need at least one CPU of the package to be online in order to
	 * program all packages for host key id.  Check it.
	 */
	for_each_present_cpu(i)
		cpumask_set_cpu(topology_physical_package_id(i), packages);
	for_each_online_cpu(i)
		cpumask_clear_cpu(topology_physical_package_id(i), packages);
	if (!cpumask_empty(packages)) {
		ret = -EIO;
		/*
		 * Because it's hard for human operator to figure out the
		 * reason, warn it.
		 */
#define MSG_ALLPKG	"All packages need to have online CPU to create TD. Online CPU and retry.\n"
		pr_warn_ratelimited(MSG_ALLPKG);
		goto free_packages;
	}

	/*
	 * Acquire global lock to avoid TDX_OPERAND_BUSY:
	 * TDH.MNG.CREATE and other APIs try to lock the global Key Owner
	 * Table (KOT) to track the assigned TDX private HKID.  It doesn't spin
	 * to acquire the lock, returns TDX_OPERAND_BUSY instead, and let the
	 * caller to handle the contention.  This is because of time limitation
	 * usable inside the TDX module and OS/VMM knows better about process
	 * scheduling.
	 *
	 * APIs to acquire the lock of KOT:
	 * TDH.MNG.CREATE, TDH.MNG.KEY.FREEID, TDH.MNG.VPFLUSHDONE, and
	 * TDH.PHYMEM.CACHE.WB.
	 */
	mutex_lock(&tdx_lock);
	kvm_tdx->tdr_pa = tdr_pa;
	err = tdh_mng_create(kvm_tdx, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (err == TDX_RND_NO_ENTROPY) {
		kvm_tdx->tdr_pa = 0;
		ret = -EAGAIN;
		goto free_packages;
	}
	if (WARN_ON_ONCE(err)) {
		kvm_tdx->tdr_pa = 0;
		pr_tdx_error(TDH_MNG_CREATE, err);
		ret = -EIO;
		goto free_packages;
	}

	for_each_online_cpu(i) {
		int pkg = topology_physical_package_id(i);

		if (cpumask_test_and_set_cpu(pkg, packages))
			continue;

		/*
		 * Program the memory controller in the package with an
		 * encryption key associated to a TDX private host key id
		 * assigned to this TDR.  Concurrent operations on same memory
		 * controller results in TDX_OPERAND_BUSY.  Avoid this race by
		 * mutex.
		 */
		mutex_lock(&tdx_mng_key_config_lock[pkg]);
		ret = smp_call_on_cpu(i, tdx_do_tdh_mng_key_config,
				      kvm_tdx, true);
		mutex_unlock(&tdx_mng_key_config_lock[pkg]);
		if (ret)
			break;
	}
	cpus_read_unlock();
	free_cpumask_var(packages);
	if (ret) {
		i = 0;
		goto teardown;
	}

	kvm_tdx->tdcs_pa = tdcs_pa;
	for (i = 0; i < tdx_info->nr_tdcs_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx, tdcs_pa[i]);
		if (err == TDX_RND_NO_ENTROPY) {
			/* Here it's hard to allow userspace to retry. */
			ret = -EBUSY;
			goto teardown;
		}
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err);
			ret = -EIO;
			goto teardown;
		}
	}

	err = tdh_mng_init(kvm_tdx, __pa(td_params), &rcx);
	if ((err & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_INVALID) {
		/*
		 * Because a user gives operands, don't warn.
		 * Return a hint to the user because it's sometimes hard for the
		 * user to figure out which operand is invalid.  SEAMCALL status
		 * code includes which operand caused invalid operand error.
		 */
		*seamcall_err = err;
		ret = -EINVAL;
		goto teardown;
	} else if (WARN_ON_ONCE(err)) {
		pr_tdx_error_1(TDH_MNG_INIT, err, rcx);
		ret = -EIO;
		goto teardown;
	}

	kvm_set_apicv_inhibit(kvm, APICV_INHIBIT_REASON_TDX);

	return 0;

	/*
	 * The sequence for freeing resources from a partially initialized TD
	 * varies based on where in the initialization flow failure occurred.
	 * Simply use the full teardown and destroy, which naturally play nice
	 * with partial initialization.
	 */
teardown:
	for (; i < tdx_info->nr_tdcs_pages; i++) {
		if (tdcs_pa[i]) {
			free_page((unsigned long)__va(tdcs_pa[i]));
			tdcs_pa[i] = 0;
		}
	}
	if (!kvm_tdx->tdcs_pa)
		kfree(tdcs_pa);
	tdx_mmu_release_hkid(kvm);
	tdx_vm_free(kvm);
	return ret;

free_packages:
	cpus_read_unlock();
	free_cpumask_var(packages);
free_tdcs:
	for (i = 0; i < tdx_info->nr_tdcs_pages; i++) {
		if (tdcs_pa[i])
			free_page((unsigned long)__va(tdcs_pa[i]));
	}
	kfree(tdcs_pa);
	kvm_tdx->tdcs_pa = NULL;

free_tdr:
	if (tdr_pa)
		free_page((unsigned long)__va(tdr_pa));
	kvm_tdx->tdr_pa = 0;
free_hkid:
	if (is_hkid_assigned(kvm_tdx))
		tdx_hkid_free(kvm_tdx);
	return ret;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_vm *init_vm = NULL;
	struct td_params *td_params = NULL;
	int ret;

	BUILD_BUG_ON(sizeof(*init_vm) != 8 * 1024);
	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	if (is_hkid_assigned(kvm_tdx))
		return -EINVAL;

	if (cmd->flags)
		return -EINVAL;

	init_vm = kzalloc(sizeof(*init_vm) +
			  sizeof(init_vm->cpuid.entries[0]) * KVM_MAX_CPUID_ENTRIES,
			  GFP_KERNEL);
	if (!init_vm)
		return -ENOMEM;
	if (copy_from_user(init_vm, u64_to_user_ptr(cmd->data), sizeof(*init_vm))) {
		ret = -EFAULT;
		goto out;
	}
	if (init_vm->cpuid.nent > KVM_MAX_CPUID_ENTRIES) {
		ret = -E2BIG;
		goto out;
	}
	if (copy_from_user(init_vm->cpuid.entries,
			   u64_to_user_ptr(cmd->data) + sizeof(*init_vm),
			   flex_array_size(init_vm, cpuid.entries, init_vm->cpuid.nent))) {
		ret = -EFAULT;
		goto out;
	}

	if (memchr_inv(init_vm->reserved, 0, sizeof(init_vm->reserved))) {
		ret = -EINVAL;
		goto out;
	}
	if (init_vm->cpuid.padding) {
		ret = -EINVAL;
		goto out;
	}

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL);
	if (!td_params) {
		ret = -ENOMEM;
		goto out;
	}

	ret = setup_tdparams(kvm, td_params, init_vm);
	if (ret)
		goto out;

	ret = __tdx_td_init(kvm, td_params, &cmd->error);
	if (ret)
		goto out;

	kvm_tdx->tsc_offset = td_tdcs_exec_read64(kvm_tdx, TD_TDCS_EXEC_TSC_OFFSET);
	kvm_tdx->attributes = td_params->attributes;
	kvm_tdx->xfam = td_params->xfam;

	if (td_params->exec_controls & TDX_EXEC_CONTROL_MAX_GPAW)
		kvm->arch.gfn_direct_bits = gpa_to_gfn(BIT_ULL(51));
	else
		kvm->arch.gfn_direct_bits = gpa_to_gfn(BIT_ULL(47));

out:
	/* kfree() accepts NULL. */
	kfree(init_vm);
	kfree(td_params);
	return ret;
}

void tdx_flush_tlb(struct kvm_vcpu *vcpu)
{
	/*
	 * Don't need to flush shared EPTP:
	 * "TD VCPU TLB Address Spaced Identifier" in the TDX module spec:
	 * The TLB entries for TD are tagged with:
	 *  SEAM (1 bit)
	 *  VPID
	 *  Secure EPT root (51:12 bits) with HKID = 0
	 *  PCID
	 * for *both* Secure-EPT and Shared-EPT.
	 * TLB flush with Secure-EPT root by tdx_track() results in flushing
	 * the conversion of both Secure-EPT and Shared-EPT.
	 */

	/*
	 * See tdx_track().  Wait for tlb shootdown initiater to finish
	 * TDH_MEM_TRACK() so that shared-EPT/secure-EPT TLB is flushed
	 * on the next TDENTER.
	 */
	while (atomic_read(&to_kvm_tdx(vcpu->kvm)->tdh_mem_track))
		cpu_relax();
}

void tdx_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	/*
	 * flush_tlb_current() is used only the first time for the vcpu to run.
	 * As it isn't performance critical, keep this function simple.
	 */
	tdx_track(vcpu->kvm);
}

static int tdx_td_finalizemr(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	if (!is_hkid_assigned(kvm_tdx) || is_td_finalized(kvm_tdx))
		return -EINVAL;
	/*
	 * Pages are pending for KVM_TDX_INIT_MEM_REGION to issue
	 * TDH.MEM.PAGE.ADD().
	 */
	if (atomic64_read(&kvm_tdx->nr_premapped))
		return -EINVAL;

	cmd->error = tdh_mr_finalize(kvm_tdx);
	if ((cmd->error & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_BUSY)
		return -EAGAIN;
	if (KVM_BUG_ON(cmd->error, kvm)) {
		pr_tdx_error(TDH_MR_FINALIZE, cmd->error);
		return -EIO;
	}

	kvm_tdx->finalized = true;
	return 0;
}

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;
	if (tdx_cmd.error)
		return -EINVAL;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
	case KVM_TDX_CAPABILITIES:
		r = tdx_get_capabilities(&tdx_cmd);
		break;
	case KVM_TDX_INIT_VM:
		r = tdx_td_init(kvm, &tdx_cmd);
		break;
	case KVM_TDX_FINALIZE_VM:
		r = tdx_td_finalizemr(kvm, &tdx_cmd);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &tdx_cmd, sizeof(struct kvm_tdx_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

/* VMM can pass one 64bit auxiliary data to vcpu via RCX for guest BIOS. */
static int tdx_td_vcpu_init(struct kvm_vcpu *vcpu, u64 vcpu_rcx)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long *tdcx_pa = NULL;
	unsigned long tdvpr_pa;
	unsigned long va;
	int ret, i;
	u64 err;

	if (is_td_vcpu_created(tdx))
		return -EINVAL;

	/*
	 * vcpu_free method frees allocated pages.  Avoid partial setup so
	 * that the method can't handle it.
	 */
	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		return -ENOMEM;
	tdvpr_pa = __pa(va);

	tdcx_pa = kcalloc(tdx_info->nr_tdcx_pages, sizeof(*tdx->tdcx_pa),
			   GFP_KERNEL_ACCOUNT);
	if (!tdcx_pa) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}

	tdx->tdcx_pa = tdcx_pa;
	for (i = 0; i < tdx_info->nr_tdcx_pages; i++) {
		va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!va) {
			ret = -ENOMEM;
			goto free_tdvpx;
		}
		tdcx_pa[i] = __pa(va);
	}

	tdx->tdvpr_pa = tdvpr_pa;
	err = tdh_vp_create(tdx);
	if (KVM_BUG_ON(err, vcpu->kvm)) {
		tdx->tdvpr_pa = 0;
		ret = -EIO;
		pr_tdx_error(TDH_VP_CREATE, err);
		goto free_tdvpx;
	}

	for (i = 0; i < tdx_info->nr_tdcx_pages; i++) {
		err = tdh_vp_addcx(tdx, tdcx_pa[i]);
		if (KVM_BUG_ON(err, vcpu->kvm)) {
			pr_tdx_error(TDH_VP_ADDCX, err);
			for (; i < tdx_info->nr_tdcx_pages; i++) {
				free_page((unsigned long)__va(tdcx_pa[i]));
				tdcx_pa[i] = 0;
			}
			/* vcpu_free method frees TDCX and TDR donated to TDX */
			return -EIO;
		}
	}

	if (tdx_info->features0 & MD_FIELD_ID_FEATURES0_TOPOLOGY_ENUM)
		err = tdh_vp_init_apicid(tdx, vcpu_rcx, vcpu->vcpu_id);
	else
		err = tdh_vp_init(tdx, vcpu_rcx);
	if (KVM_BUG_ON(err, vcpu->kvm)) {
		pr_tdx_error(TDH_VP_INIT, err);
		return -EIO;
	}

	vcpu->arch.apic->apicv_active = false;
	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	tdx->td_vcpu_created = true;
	return 0;

free_tdvpx:
	for (i = 0; i < tdx_info->nr_tdcx_pages; i++) {
		if (tdcx_pa[i])
			free_page((unsigned long)__va(tdcx_pa[i]));
		tdcx_pa[i] = 0;
	}
	kfree(tdcx_pa);
	tdx->tdcx_pa = NULL;
free_tdvpr:
	if (tdvpr_pa)
		free_page((unsigned long)__va(tdvpr_pa));
	tdx->tdvpr_pa = 0;

	return ret;
}

static int tdx_vcpu_init_mtrr(struct kvm_vcpu *vcpu)
{
	struct msr_data msr;
	int ret;
	int i;

	/*
	 * To avoid confusion with reporting VNCT = 0, explicitly disable
	 * vaiale-range reisters.
	 */
	for (i = 0; i < KVM_NR_VAR_MTRR; i++) {
		/* phymask */
		msr = (struct msr_data) {
			.host_initiated = true,
			.index = 0x200 + 2 * i + 1,
			.data = 0,	/* valid = 0 to disable. */
		};
		ret = kvm_set_msr_common(vcpu, &msr);
		if (ret)
			return -EINVAL;
	}

	/* Set MTRR to use writeback on reset. */
	msr = (struct msr_data) {
		.host_initiated = true,
		.index = MSR_MTRRdefType,
		/*
		 * Set E(enable MTRR)=1, FE(enable fixed range MTRR)=0, default
		 * type=writeback on reset to avoid UC.  Note E=0 means all
		 * memory is UC.
		 */
		.data = (1 << 11) | MTRR_TYPE_WRBACK,
	};
	ret = kvm_set_msr_common(vcpu, &msr);
	if (ret)
		return -EINVAL;
	return 0;
}

static int tdx_vcpu_init(struct kvm_vcpu *vcpu, struct kvm_tdx_cmd *cmd)
{
	struct msr_data apic_base_msr;
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int ret;

	if (cmd->flags)
		return -EINVAL;
	if (tdx->initialized)
		return -EINVAL;

	/*
	 * As TDX requires X2APIC, set local apic mode to X2APIC.  User space
	 * VMM, e.g. qemu, is required to set CPUID[0x1].ecx.X2APIC=1 by
	 * KVM_SET_CPUID2.  Otherwise kvm_set_apic_base() will fail.
	 */
	apic_base_msr = (struct msr_data) {
		.host_initiated = true,
		.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC |
		(kvm_vcpu_is_reset_bsp(vcpu) ? MSR_IA32_APICBASE_BSP : 0),
	};
	if (kvm_set_apic_base(vcpu, &apic_base_msr))
		return -EINVAL;

	ret = tdx_vcpu_init_mtrr(vcpu);
	if (ret)
		return ret;

	ret = tdx_td_vcpu_init(vcpu, (u64)cmd->data);
	if (ret)
		return ret;

	td_vmcs_write16(tdx, POSTED_INTR_NV, POSTED_INTR_VECTOR);
	td_vmcs_write64(tdx, POSTED_INTR_DESC_ADDR, __pa(&tdx->pi_desc));
	td_vmcs_setbit32(tdx, PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR);

	tdx->initialized = true;
	return 0;
}

struct tdx_gmem_post_populate_arg {
	struct kvm_vcpu *vcpu;
	__u32 flags;
};

static int tdx_gmem_post_populate(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
				  void __user *src, int order, void *_arg)
{
	u64 error_code = PFERR_GUEST_FINAL_MASK | PFERR_PRIVATE_ACCESS;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_gmem_post_populate_arg *arg = _arg;
	struct kvm_vcpu *vcpu = arg->vcpu;
	struct kvm_memory_slot *slot;
	gpa_t gpa = gfn_to_gpa(gfn);
	u8 level = PG_LEVEL_4K;
	struct page *page;
	kvm_pfn_t mmu_pfn;
	int ret, i;
	u64 err, entry, level_state;

	/* Pin the source page. */
	ret = get_user_pages_fast((unsigned long)src, 1, 0, &page);
	if (ret < 0)
		return ret;
	if (ret != 1)
		return -ENOMEM;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (!kvm_slot_can_be_private(slot) || !kvm_mem_is_private(kvm, gfn)) {
		ret = -EFAULT;
		goto out_put_page;
	}

	ret = kvm_tdp_map_page(vcpu, gpa, error_code, &level);
	if (ret < 0)
		goto out_put_page;

	read_lock(&kvm->mmu_lock);

	ret = kvm_tdp_mmu_get_walk_mirror_pfn(vcpu, gpa, &mmu_pfn);
	if (ret < 0)
		goto out;
	if (ret > PG_LEVEL_4K) {
		ret = -EINVAL;
		goto out;
	}
	if (mmu_pfn != pfn) {
		ret = -EAGAIN;
		goto out;
	}

	ret = 0;
	do {
		err = tdh_mem_page_add(kvm_tdx, gpa, pfn_to_hpa(pfn),
				       pfn_to_hpa(page_to_pfn(page)),
				       &entry, &level_state);
	} while (err == TDX_ERROR_SEPT_BUSY);
	if (err) {
		ret = -EIO;
		goto out;
	}

	WARN_ON_ONCE(!atomic64_read(&kvm_tdx->nr_premapped));
	atomic64_dec(&kvm_tdx->nr_premapped);

	if (arg->flags & KVM_TDX_MEASURE_MEMORY_REGION) {
		for (i = 0; i < PAGE_SIZE; i += TDX_EXTENDMR_CHUNKSIZE) {
			err = tdh_mr_extend(kvm_tdx, gpa + i, &entry,
					&level_state);
			if (err) {
				ret = -EIO;
				break;
			}
		}
	}

out:
	read_unlock(&kvm->mmu_lock);
out_put_page:
	put_page(page);
	return ret;
}

static int tdx_vcpu_init_mem_region(struct kvm_vcpu *vcpu, struct kvm_tdx_cmd *cmd)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_mem_region region;
	struct tdx_gmem_post_populate_arg arg;
	long gmem_ret;
	int idx, ret;

	if (!to_tdx(vcpu)->initialized)
		return -EINVAL;

	/* Once TD is finalized, the initial guest memory is fixed. */
	if (is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (cmd->flags & ~KVM_TDX_MEASURE_MEMORY_REGION)
		return -EINVAL;

	if (copy_from_user(&region, u64_to_user_ptr(cmd->data), sizeof(region)))
		return -EFAULT;

	if (!PAGE_ALIGNED(region.source_addr) || !PAGE_ALIGNED(region.gpa) ||
	    !region.nr_pages ||
	    region.gpa + (region.nr_pages << PAGE_SHIFT) <= region.gpa ||
	    !kvm_is_private_gpa(kvm, region.gpa) ||
	    !kvm_is_private_gpa(kvm, region.gpa + (region.nr_pages << PAGE_SHIFT)))
		return -EINVAL;

	mutex_lock(&kvm->slots_lock);
	idx = srcu_read_lock(&kvm->srcu);

	kvm_mmu_reload(vcpu);
	ret = 0;
	while (region.nr_pages) {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		arg = (struct tdx_gmem_post_populate_arg) {
			.vcpu = vcpu,
			.flags = cmd->flags,
		};
		gmem_ret = kvm_gmem_populate(kvm, gpa_to_gfn(region.gpa),
					     u64_to_user_ptr(region.source_addr),
					     1, tdx_gmem_post_populate, &arg);
		if (gmem_ret < 0) {
			ret = gmem_ret;
			break;
		}

		if (gmem_ret != 1) {
			ret = -EIO;
			break;
		}

		region.source_addr += PAGE_SIZE;
		region.gpa += PAGE_SIZE;
		region.nr_pages--;

		cond_resched();
	}

	srcu_read_unlock(&kvm->srcu, idx);
	mutex_unlock(&kvm->slots_lock);

	if (copy_to_user(u64_to_user_ptr(cmd->data), &region, sizeof(region)))
		ret = -EFAULT;
	return ret;
}

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct kvm_tdx_cmd cmd;
	int ret;

	if (!is_hkid_assigned(kvm_tdx) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.error)
		return -EINVAL;

	switch (cmd.id) {
	case KVM_TDX_INIT_VCPU:
		ret = tdx_vcpu_init(vcpu, &cmd);
		break;
	case KVM_TDX_INIT_MEM_REGION:
		ret = tdx_vcpu_init_mem_region(vcpu, &cmd);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

int tdx_gmem_private_max_mapping_level(struct kvm *kvm, kvm_pfn_t pfn)
{
	return PG_LEVEL_4K;
}

static int __init tdx_module_setup(void)
{
	struct st {
		u16 num_cpuid_config;
		u16 tdcs_base_size;
		u16 tdvps_base_size;
	} st;
	u64 tmp;
	int ret;
	u32 i;

#define TDX_INFO_MAP(_field_id, _member)		\
	TD_SYSINFO_MAP(_field_id, struct st, _member)

	struct tdx_metadata_field_mapping st_fields[] = {
		TDX_INFO_MAP(NUM_CPUID_CONFIG, num_cpuid_config),
		TDX_INFO_MAP(TDCS_BASE_SIZE, tdcs_base_size),
		TDX_INFO_MAP(TDVPS_BASE_SIZE, tdvps_base_size),
	};
#undef TDX_INFO_MAP

#define TDX_INFO_MAP(_field_id, _member)			\
	TD_SYSINFO_MAP(_field_id, struct tdx_info, _member)

	struct tdx_metadata_field_mapping fields[] = {
		TDX_INFO_MAP(FEATURES0, features0),
		TDX_INFO_MAP(ATTRS_FIXED0, attributes_fixed0),
		TDX_INFO_MAP(ATTRS_FIXED1, attributes_fixed1),
		TDX_INFO_MAP(XFAM_FIXED0, xfam_fixed0),
		TDX_INFO_MAP(XFAM_FIXED1, xfam_fixed1),
	};
#undef TDX_INFO_MAP

	ret = tdx_enable();
	if (ret)
		return ret;

	ret = tdx_sys_metadata_read(st_fields, ARRAY_SIZE(st_fields), &st);
	if (ret)
		return ret;

	tdx_info = kzalloc(sizeof(*tdx_info) +
			   sizeof(*tdx_info->cpuid_configs) * st.num_cpuid_config,
			   GFP_KERNEL);
	if (!tdx_info)
		return -ENOMEM;
	tdx_info->num_cpuid_config = st.num_cpuid_config;

	/*
	 * TDX module may not support MD_FIELD_ID_MAX_VCPUS_PER_TD depending
	 * on its version.
	 */
	tdx_info->max_vcpus_per_td = U16_MAX;
	if (!tdx_sys_metadata_field_read(MD_FIELD_ID_MAX_VCPUS_PER_TD, &tmp))
		tdx_info->max_vcpus_per_td = (u16)tmp;

	ret = tdx_sys_metadata_read(fields, ARRAY_SIZE(fields), tdx_info);
	if (ret)
		goto error_out;

	for (i = 0; i < st.num_cpuid_config; i++) {
		struct kvm_tdx_cpuid_config *c = &tdx_info->cpuid_configs[i];
		struct cpuid_st {
			u64 leaf;
			u64 eax_ebx;
			u64 ecx_edx;
		} cpuid_st;

#define TDX_INFO_MAP(_field_id, _member)			\
	TD_SYSINFO_MAP(_field_id, struct cpuid_st, _member)

		struct tdx_metadata_field_mapping cpuid_fields[] = {
			TDX_INFO_MAP(CPUID_CONFIG_LEAVES + i, leaf),
			TDX_INFO_MAP(CPUID_CONFIG_VALUES + i * 2, eax_ebx),
			TDX_INFO_MAP(CPUID_CONFIG_VALUES + i * 2 + 1, ecx_edx),
		};
#undef TDX_INFO_MAP

		ret = tdx_sys_metadata_read(cpuid_fields, ARRAY_SIZE(cpuid_fields),
					    &cpuid_st);
		if (ret)
			goto error_out;

		c->leaf = (u32)cpuid_st.leaf;
		c->sub_leaf = cpuid_st.leaf >> 32;
		c->eax = (u32)cpuid_st.eax_ebx;
		c->ebx = cpuid_st.eax_ebx >> 32;
		c->ecx = (u32)cpuid_st.ecx_edx;
		c->edx = cpuid_st.ecx_edx >> 32;
	}

	tdx_info->nr_tdcs_pages = st.tdcs_base_size / PAGE_SIZE;
	/*
	 * TDVPS = TDVPR(4K page) + TDCX(multiple 4K pages).
	 * -1 for TDVPR.
	 */
	tdx_info->nr_tdcx_pages = st.tdvps_base_size / PAGE_SIZE - 1;

	/*
	 * Make TDH.VP.ENTER preserve RBP so that the stack unwinder
	 * always work around it.  Query the feature.
	 */
	if (!(tdx_info->features0 & MD_FIELD_ID_FEATURES0_NO_RBP_MOD) &&
	    !IS_ENABLED(CONFIG_FRAME_POINTER)) {
		pr_err("Too old version of TDX module. Consider upgrade.\n");
		ret = -EOPNOTSUPP;
		goto error_out;
	}

	return 0;

error_out:
	/* kfree() accepts NULL. */
	kfree(tdx_info);
	return ret;
}

struct tdx_enabled {
	cpumask_var_t enabled;
	atomic_t err;
};

static void __init tdx_on(void *_enable)
{
	struct tdx_enabled *enable = _enable;
	int r;

	r = vmx_hardware_enable();
	if (!r) {
		cpumask_set_cpu(smp_processor_id(), enable->enabled);
		r = tdx_cpu_enable();
	}
	if (r)
		atomic_set(&enable->err, r);
}

static void __init vmx_off(void *_enabled)
{
	cpumask_var_t *enabled = (cpumask_var_t *)_enabled;

	if (cpumask_test_cpu(smp_processor_id(), *enabled))
		vmx_hardware_disable();
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	struct tdx_enabled enable = {
		.err = ATOMIC_INIT(0),
	};
	int max_pkgs;
	int r = 0;
	int i;

	if (!cpu_feature_enabled(X86_FEATURE_MOVDIR64B)) {
		pr_warn("MOVDIR64B is reqiured for TDX\n");
		return -EOPNOTSUPP;
	}
	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	/* tdx_hardware_disable() uses associated_tdvcpus. */
	for_each_possible_cpu(i)
		INIT_LIST_HEAD(&per_cpu(associated_tdvcpus, i));

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++) {
		/*
		 * Check if MSRs (tdx_uret_msrs) can be saved/restored
		 * before returning to user space.
		 *
		 * this_cpu_ptr(user_return_msrs)->registered isn't checked
		 * because the registration is done at vcpu runtime by
		 * tdx_user_return_msr_update_cache().
		 */
		tdx_uret_msrs[i].slot = kvm_find_user_return_msr(tdx_uret_msrs[i].msr);
		if (tdx_uret_msrs[i].slot == -1) {
			/* If any MSR isn't supported, it is a KVM bug */
			pr_err("MSR %x isn't included by kvm_find_user_return_msr\n",
				tdx_uret_msrs[i].msr);
			return -EIO;
		}
	}
	tdx_uret_tsx_ctrl_slot = kvm_find_user_return_msr(MSR_IA32_TSX_CTRL);
	if (tdx_uret_tsx_ctrl_slot == -1 && boot_cpu_has(X86_FEATURE_MSR_TSX_CTRL)) {
		pr_err("MSR_IA32_TSX_CTRL isn't included by kvm_find_user_return_msr\n");
		return -EIO;
	}

	max_pkgs = topology_max_packages();
	tdx_mng_key_config_lock = kcalloc(max_pkgs, sizeof(*tdx_mng_key_config_lock),
				   GFP_KERNEL);
	if (!tdx_mng_key_config_lock)
		return -ENOMEM;
	for (i = 0; i < max_pkgs; i++)
		mutex_init(&tdx_mng_key_config_lock[i]);

	if (!zalloc_cpumask_var(&enable.enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	on_each_cpu(tdx_on, &enable, true); /* TDX requires vmxon. */
	r = atomic_read(&enable.err);
	if (!r)
		r = tdx_module_setup();
	else
		r = -EIO;
	on_each_cpu(vmx_off, &enable.enabled, true);
	cpus_read_unlock();
	free_cpumask_var(enable.enabled);
	if (r)
		goto out;

	x86_ops->link_external_spt = tdx_sept_link_private_spt;
	x86_ops->free_external_spt = tdx_sept_free_private_spt;
	x86_ops->set_external_spte = tdx_sept_set_private_spte;
	x86_ops->remove_external_spte = tdx_sept_remove_private_spte;

	return 0;

out:
	/* kfree() accepts NULL. */
	kfree(tdx_mng_key_config_lock);
	tdx_mng_key_config_lock = NULL;
	return r;
}

void tdx_hardware_unsetup(void)
{
	kfree(tdx_info);
	kfree(tdx_mng_key_config_lock);
}

int tdx_offline_cpu(void)
{
	int i, curr_cpu = smp_processor_id();

	/* No TD is running.  Allow any cpu to be offline. */
	if (ida_is_empty(&tdx_guest_keyid_pool))
		return 0;

	/*
	 * In order to reclaim TDX HKID, (i.e. when deleting guest TD), need to
	 * call TDH.PHYMEM.PAGE.WBINVD on all packages to program all memory
	 * controller with pconfig.  If we have active TDX HKID, refuse to
	 * offline the last online cpu.
	 */
	for_each_online_cpu(i) {
		/*
		 * Found another online cpu on the same package.
		 * Allow to offline.
		 */
		if (i != curr_cpu && topology_physical_package_id(i) ==
				topology_physical_package_id(curr_cpu))
			return 0;
	}

	/*
	 * This is the last cpu of this package.  Don't offline it.
	 *
	 * Because it's hard for human operator to understand the
	 * reason, warn it.
	 */
#define MSG_ALLPKG_ONLINE \
	"TDX requires all packages to have an online CPU. Delete all TDs in order to offline all CPUs of a package.\n"
	pr_warn_ratelimited(MSG_ALLPKG_ONLINE);
	return -EBUSY;
}
