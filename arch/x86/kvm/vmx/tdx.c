// SPDX-License-Identifier: GPL-2.0
#include <linux/cleanup.h>
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
#include "mmu/spte.h"
#include "common.h"
#include "posted_intr.h"

#include <trace/events/kvm.h>
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define pr_tdx_error(__fn, __err)	\
	pr_err_ratelimited("SEAMCALL %s failed: 0x%llx\n", #__fn, __err)

#define __pr_tdx_error_N(__fn_str, __err, __fmt, ...)		\
	pr_err_ratelimited("SEAMCALL " __fn_str " failed: 0x%llx, " __fmt,  __err,  __VA_ARGS__)

#define pr_tdx_error_1(__fn, __err, __rcx)		\
	__pr_tdx_error_N(#__fn, __err, "rcx 0x%llx\n", __rcx)

#define pr_tdx_error_2(__fn, __err, __rcx, __rdx)	\
	__pr_tdx_error_N(#__fn, __err, "rcx 0x%llx, rdx 0x%llx\n", __rcx, __rdx)

#define pr_tdx_error_3(__fn, __err, __rcx, __rdx, __r8)	\
	__pr_tdx_error_N(#__fn, __err, "rcx 0x%llx, rdx 0x%llx, r8 0x%llx\n", __rcx, __rdx, __r8)

bool enable_tdx __ro_after_init;
module_param_named(tdx, enable_tdx, bool, 0444);

static enum cpuhp_state tdx_cpuhp_state;

static const struct tdx_sys_info *tdx_sysinfo;

#define KVM_TDX_CPUID_NO_SUBLEAF	((__u32)-1)

struct kvm_tdx_caps {
	u64 supported_attrs;
	u64 supported_xfam;

	u16 num_cpuid_config;
	/* This must the last member. */
	DECLARE_FLEX_ARRAY(struct kvm_tdx_cpuid_config, cpuid_configs);
};

static struct kvm_tdx_caps *kvm_tdx_caps;

/*
 * Some SEAMCALLs acquire the TDX module globally, and can fail with
 * TDX_OPERAND_BUSY.  Use a global mutex to serialize these SEAMCALLs.
 */
static DEFINE_MUTEX(tdx_lock);

static atomic_t nr_configured_hkid;

/*
 * A per-CPU list of TD vCPUs associated with a given CPU.  Used when a CPU
 * is brought down to invoke TDH_VP_FLUSH on the appropriate TD vCPUS.
 * Protected by interrupt mask.  This list is manipulated in process context
 * of vCPU and IPI callback.  See tdx_flush_vp_on_cpu().
 */
static DEFINE_PER_CPU(struct list_head, associated_tdvcpus);

#define TDX_ERROR_SEPT_BUSY    (TDX_OPERAND_BUSY | TDX_OPERAND_ID_SEPT)

static inline int pg_level_to_tdx_sept_level(enum pg_level level)
{
	WARN_ON_ONCE(level == PG_LEVEL_NONE);
	return level - 1;
}

/* Maximum number of retries to attempt for SEAMCALLs. */
#define TDX_SEAMCALL_RETRIES	10000

static __always_inline union vmx_exit_reason tdexit_exit_reason(struct kvm_vcpu *vcpu)
{
	return (union vmx_exit_reason)(u32)(to_tdx(vcpu)->vp_enter_ret);
}

/*
 * There is no simple way to check some bit(s) to decide whether the return
 * value of TDH.VP.ENTER has a VMX exit reason or not.  E.g.,
 * TDX_NON_RECOVERABLE_TD_WRONG_APIC_MODE has exit reason but with error bit
 * (bit 63) set, TDX_NON_RECOVERABLE_TD_CORRUPTED_MD has no exit reason but with
 * error bit cleared.
 */
static bool tdx_has_exit_reason(struct kvm_vcpu *vcpu)
{
	u64 status = to_tdx(vcpu)->vp_enter_ret & TDX_SEAMCALL_STATUS_MASK;

	return status == TDX_SUCCESS || status == TDX_NON_RECOVERABLE_VCPU ||
	       status == TDX_NON_RECOVERABLE_TD ||
	       status == TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE ||
	       status == TDX_NON_RECOVERABLE_TD_WRONG_APIC_MODE;
}

static bool tdx_check_exit_reason(struct kvm_vcpu *vcpu, u16 reason)
{
	u64 status = to_tdx(vcpu)->vp_enter_ret & TDX_SEAMCALL_STATUS_MASK;

	/*
	 * For VMX exit reasons KVM will handle, the seamcall status should be
	 * TDX_SUCCESS, except for EXIT_REASON_TRIPLE_FAULT.
	 */
	if (status == TDX_SUCCESS ||
	    (status == TDX_NON_RECOVERABLE_VCPU &&
	     reason == EXIT_REASON_TRIPLE_FAULT))
		return tdexit_exit_reason(vcpu).basic == reason;

	return false;
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

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr_pa;
}

static inline void tdx_hkid_free(struct kvm_tdx *kvm_tdx)
{
	tdx_guest_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
	atomic_dec(&nr_configured_hkid);
}

static inline bool is_hkid_assigned(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->hkid > 0;
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

static void tdx_clear_page(unsigned long page_pa)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	void *page = __va(page_pa);
	unsigned long i;

	/*
	 * The page could have been poisoned.  MOVDIR64B also clears
	 * the poison bit so the kernel can safely use the page again.
	 */
	for (i = 0; i < PAGE_SIZE; i += 64)
		movdir64b(page + i, zero_page);
	/*
	 * MOVDIR64B store uses WC buffer.  Prevent following memory reads
	 * from seeing potentially poisoned cache.
	 */
	__mb();
}

/* TDH.PHYMEM.PAGE.RECLAIM is allowed only when destroying the TD. */
static int __tdx_reclaim_page(hpa_t pa)
{
	u64 err, rcx, rdx, r8;
	int i;

	for (i = TDX_SEAMCALL_RETRIES; i > 0; i--) {
		err = tdh_phymem_page_reclaim(pa, &rcx, &rdx, &r8);

		/*
		 * TDH.PHYMEM.PAGE.RECLAIM is allowed only when TD is shutdown.
		 * state.  i.e. destructing TD.
		 * TDH.PHYMEM.PAGE.RECLAIM requires TDR and target page.
		 * Because we're destructing TD, it's rare to contend with TDR.
		 */
		switch (err) {
		case TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX:
		case TDX_OPERAND_BUSY | TDX_OPERAND_ID_TDR:
			cond_resched();
			continue;
		default:
			goto out;
		}
	}

out:
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


/*
 * Reclaim the TD control page(s) which are crypto-protected by TDX guest's
 * private KeyID.  Assume the cache associated with the TDX private KeyID has
 * been flushed.
 */
static void tdx_reclaim_control_page(unsigned long ctrl_page_pa)
{
	/*
	 * Leak the page if the kernel failed to reclaim the page.
	 * The kernel cannot use it safely anymore.
	 */
	if (tdx_reclaim_page(ctrl_page_pa))
		return;

	free_page((unsigned long)__va(ctrl_page_pa));
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
	if (to_tdx(vcpu)->td_vcpu_created) {
		/*
		 * No need to retry.  TDX Resources needed for TDH.VP.FLUSH are:
		 * TDVPR as exclusive, TDR as shared, and TDCS as shared.  This
		 * vp flush function is called when destructing vCPU/TD or vCPU
		 * migration.  No other thread uses TDVPR in those cases.
		 */
		err = tdh_vp_flush(to_tdx(vcpu)->tdvpr_pa);
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

	local_irq_save(flags);
	/* Safe variant needed as tdx_disassociate_vp() deletes the entry. */
	list_for_each_entry_safe(tdx, tmp, tdvcpus, cpu_list) {
		arg.vcpu = &tdx->vcpu;
		tdx_flush_vp(&arg);
	}
	local_irq_restore(flags);
}

static void smp_func_do_phymem_cache_wb(void *unused)
{
	u64 err = 0;
	bool resume;
	int i;

	/*
	 * TDH.PHYMEM.CACHE.WB flushes caches associated with any TDX private
	 * KeyID on the package or core.  The TDX module may not finish the
	 * cache flush but return TDX_INTERRUPTED_RESUMEABLE instead.  The
	 * kernel should retry it until it returns success w/o rescheduling.
	 */
	for (i = TDX_SEAMCALL_RETRIES; i > 0; i--) {
		resume = !!err;
		err = tdh_phymem_cache_wb(resume);
		switch (err) {
		case TDX_INTERRUPTED_RESUMABLE:
			continue;
		case TDX_NO_HKID_READY_TO_WBCACHE:
			err = TDX_SUCCESS; /* Already done by other thread */
			fallthrough;
		default:
			goto out;
		}
	}

out:
	if (WARN_ON_ONCE(err))
		pr_tdx_error(TDH_PHYMEM_CACHE_WB, err);
}

void tdx_mmu_release_hkid(struct kvm *kvm)
{
	bool packages_allocated, targets_allocated;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages, targets;
	struct kvm_vcpu *vcpu;
	unsigned long j;
	int i;
	u64 err;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	packages_allocated = zalloc_cpumask_var(&packages, GFP_KERNEL);
	targets_allocated = zalloc_cpumask_var(&targets, GFP_KERNEL);
	cpus_read_lock();

	kvm_for_each_vcpu(j, vcpu, kvm)
		tdx_flush_vp_on_cpu(vcpu);

	/*
	 * TDH.PHYMEM.CACHE.WB tries to acquire the TDX module global lock
	 * and can fail with TDX_OPERAND_BUSY when it fails to get the lock.
	 * Multiple TDX guests can be destroyed simultaneously. Take the
	 * mutex to prevent it from getting error.
	 */
	mutex_lock(&tdx_lock);

	/*
	 * Releasing HKID is in vm_destroy().
	 * After the above flushing vps, there should be no more vCPU
	 * associations, as all vCPU fds have been released at this stage.
	 */
	err = tdh_mng_vpflushdone(kvm_tdx->tdr_pa);
	if (err == TDX_FLUSHVP_NOT_DONE)
		goto out;
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MNG_VPFLUSHDONE, err);
		pr_err("tdh_mng_vpflushdone() failed. HKID %d is leaked.\n",
		       kvm_tdx->hkid);
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
		on_each_cpu_mask(targets, smp_func_do_phymem_cache_wb, NULL, true);
	else
		on_each_cpu(smp_func_do_phymem_cache_wb, NULL, true);
	/*
	 * In the case of error in smp_func_do_phymem_cache_wb(), the following
	 * tdh_mng_key_freeid() will fail.
	 */
	err = tdh_mng_key_freeid(kvm_tdx->tdr_pa);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err);
		pr_err("tdh_mng_key_freeid() failed. HKID %d is leaked.\n",
		       kvm_tdx->hkid);
	} else {
		tdx_hkid_free(kvm_tdx);
	}

out:
	mutex_unlock(&tdx_lock);
	cpus_read_unlock();
	free_cpumask_var(targets);
	free_cpumask_var(packages);
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
		for (i = 0; i < kvm_tdx->nr_tdcs_pages; i++) {
			if (!kvm_tdx->tdcs_pa[i])
				continue;

			tdx_reclaim_control_page(kvm_tdx->tdcs_pa[i]);
		}
		kfree(kvm_tdx->tdcs_pa);
		kvm_tdx->tdcs_pa = NULL;
	}

	if (!is_td_created(kvm_tdx))
		return;

	if (__tdx_reclaim_page(kvm_tdx->tdr_pa))
		return;

	/*
	 * Use a SEAMCALL to ask the TDX module to flush the cache based on the
	 * KeyID. TDX module may access TDR while operating on TD (Especially
	 * when it is reclaiming TDCS).
	 */
	err = tdh_phymem_page_wbinvd_tdr(kvm_tdx->tdr_pa);
	if (KVM_BUG_ON(err, kvm)) {
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

	/* TDX_RND_NO_ENTROPY related retries are handled by sc_retry() */
	err = tdh_mng_key_config(kvm_tdx->tdr_pa);

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
	kvm->max_vcpus = min(kvm->max_vcpus,
			tdx_sysinfo->td_conf.max_vcpus_per_td);

	return 0;
}

u8 tdx_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	if (is_mmio)
		return MTRR_TYPE_UNCACHABLE << VMX_EPT_MT_EPTE_SHIFT;

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

	vcpu->arch.tsc_offset = kvm_tdx->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTR_DEBUG);

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

bool tdx_protected_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	return pi_has_pending_interrupt(vcpu);
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
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	/*
	 * This methods can be called when vcpu allocation/initialization
	 * failed. So it's possible that hkid, tdvpx and tdvpr are not assigned
	 * yet.
	 */
	if (is_hkid_assigned(kvm_tdx))
		return;

	if (tdx->tdcx_pa) {
		for (i = 0; i < kvm_tdx->nr_vcpu_tdcx_pages; i++) {
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


static void tdx_complete_interrupts(struct kvm_vcpu *vcpu)
{
	/* Avoid costly SEAMCALL if no NMI was injected. */
	if (vcpu->arch.nmi_injected) {
		/*
		 * No need to request KVM_REQ_EVENT because PEND_NMI is still
		 * set if NMI re-injection needed.  No other event types need
		 * to be handled because TDX doesn't support injection of
		 * exception, SMI or interrupt (via event injection).
		 */
		vcpu->arch.nmi_injected = td_management_read8(to_tdx(vcpu),
							      TD_VCPU_PEND_NMI);
	}
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
	    kvm_host.xcr0 != (kvm_tdx->xfam & kvm_caps.supported_xcr0))
		xsetbv(XCR_XFEATURE_ENABLED_MASK, kvm_host.xcr0);
	if (static_cpu_has(X86_FEATURE_XSAVES) &&
	    /* PT can be exposed to TD guest regardless of KVM's XSS support */
	    kvm_host.xss != (kvm_tdx->xfam &
			 (kvm_caps.supported_xss | XFEATURE_MASK_PT |
			  XFEATURE_MASK_CET_USER | XFEATURE_MASK_CET_KERNEL)))
		wrmsrl(MSR_IA32_XSS, kvm_host.xss);
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

	tdx->vp_enter_ret = tdh_vp_enter(tdx->tdvpr_pa, &args);

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

	if (tdx_check_exit_reason(vcpu, EXIT_REASON_EXCEPTION_NMI) &&
	    is_nmi(tdexit_intr_info(vcpu))) {
		kvm_before_interrupt(vcpu, KVM_HANDLING_NMI);
		vmx_do_nmi_irqoff();
		kvm_after_interrupt(vcpu);
	}
	guest_state_exit_irqoff();
}

static fastpath_t tdx_exit_handlers_fastpath(struct kvm_vcpu *vcpu)
{
	u64 vp_enter_ret = to_tdx(vcpu)->vp_enter_ret;

	/* See the comment of tdx_seamcall_sept(). */
	if (unlikely(vp_enter_ret == TDX_ERROR_SEPT_BUSY))
		return EXIT_FASTPATH_REENTER_GUEST;
	/*
	 * TDH.VP.ENTER checks TD EPOCH which can contend with TDH.MEM.TRACK
	 * and other vCPU TDH.VP.ENTER.
	 */
	if (unlikely(vp_enter_ret == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_TD_EPOCH)))
		return EXIT_FASTPATH_REENTER_GUEST;

	return EXIT_FASTPATH_NONE;
}

fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu, bool force_immediate_exit)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/* TDX exit handle takes care of this error case. */
	if (unlikely(!tdx->initialized)) {
		/* Set to avoid collision with EXIT_REASON_EXCEPTION_NMI. */
		tdx->vp_enter_ret = TDX_SW_ERROR;
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

	return tdx_exit_handlers_fastpath(vcpu);
}

void tdx_inject_nmi(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.nmi_injections;
	td_management_write8(to_tdx(vcpu), TD_VCPU_PEND_NMI, 1);
	/*
	 * TDX doesn't support KVM to request NMI window exit.  If there is
	 * still a pending vNMI, KVM is not able to inject it along with the
	 * one pending in TDX module in a back-to-back way.  Since the previous
	 * vNMI is still pending in TDX module, i.e. it has not been delivered
	 * to TDX guest yet, it's OK to collapse the pending vNMI into the
	 * previous one.  The guest is expected to handle all the NMI sources
	 * when handling the first vNMI.
	 */
	vcpu->arch.nmi_pending = 0;
}

void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	if (tdx_check_exit_reason(vcpu, EXIT_REASON_EXTERNAL_INTERRUPT))
		vmx_handle_external_interrupt_irqoff(vcpu,
						     tdexit_intr_info(vcpu));
	else if (tdx_check_exit_reason(vcpu, EXIT_REASON_EXCEPTION_NMI))
		vmx_handle_exception_irqoff(vcpu, tdexit_intr_info(vcpu));
}

static int tdx_handle_exception_nmi(struct kvm_vcpu *vcpu)
{
	u32 intr_info = tdexit_intr_info(vcpu);

	/*
	 * Machine checks are handled by vmx_handle_exception_irqoff(), or by
	 * tdx_handle_exit() with TDX_NON_RECOVERABLE set if a #MC occurs on
	 * VM-Entry.  NMIs are handled by tdx_vcpu_enter_exit().
	 */
	if (is_nmi(intr_info) || is_machine_check(intr_info))
		return 1;

	kvm_pr_unimpl("unexpected exception 0x%x(exit_reason 0x%llx qual 0x%lx)\n",
		intr_info,
		to_tdx(vcpu)->vp_enter_ret, tdexit_exit_qual(vcpu));

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

	/* Check ret first to make sure nr is a valid KVM hypercall. */
	return !!ret || !user_exit_on_hypercall(vcpu->kvm, nr);
}

#define TDX_MAP_GPA_MAX_LEN (2 * 1024 * 1024)
static void __tdx_map_gpa(struct vcpu_tdx * tdx);

static int tdx_complete_vmcall_map_gpa(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx * tdx = to_tdx(vcpu);

	if(vcpu->run->hypercall.ret) {
		tdvmcall_set_return_code(vcpu, TDVMCALL_STATUS_INVALID_OPERAND);
		kvm_r11_write(vcpu, tdx->map_gpa_next);
		return 1;
	}

	tdx->map_gpa_next += TDX_MAP_GPA_MAX_LEN;
	if (tdx->map_gpa_next >= tdx->map_gpa_end) {
		tdvmcall_set_return_code(vcpu, TDVMCALL_STATUS_SUCCESS);
		return 1;
	}

	/*
	 * Stop processing the remaining part if there is pending interrupt.
	 * Skip checking pending virtual interrupt (reflected by
	 * TDX_VCPU_STATE_DETAILS_INTR_PENDING bit) to save a seamcall because
	 * if guest disabled interrupt, it's OK not returning back to guest
	 * due to non-NMI interrupt. Also it's rare to TDVMCALL_MAP_GPA
	 * immediately after STI or MOV/POP SS.
	 */
	if (pi_has_pending_interrupt(vcpu) ||
	    kvm_test_request(KVM_REQ_NMI, vcpu) || vcpu->arch.nmi_pending) {
		tdvmcall_set_return_code(vcpu, TDVMCALL_STATUS_RETRY);
		kvm_r11_write(vcpu, tdx->map_gpa_next);
		return 1;
	}

	__tdx_map_gpa(tdx);
	/* Forward request to userspace. */
	return 0;
}

static void __tdx_map_gpa(struct vcpu_tdx * tdx)
{
	u64 gpa = tdx->map_gpa_next;
	u64 size = tdx->map_gpa_end - tdx->map_gpa_next;

	if(size > TDX_MAP_GPA_MAX_LEN)
		size = TDX_MAP_GPA_MAX_LEN;

	tdx->vcpu.run->exit_reason       = KVM_EXIT_HYPERCALL;
	tdx->vcpu.run->hypercall.nr      = KVM_HC_MAP_GPA_RANGE;
	tdx->vcpu.run->hypercall.args[0] = gpa & ~gfn_to_gpa(kvm_gfn_direct_bits(tdx->vcpu.kvm));
	tdx->vcpu.run->hypercall.args[1] = size / PAGE_SIZE;
	tdx->vcpu.run->hypercall.args[2] = kvm_is_private_gpa(tdx->vcpu.kvm, gpa) ?
					   KVM_MAP_GPA_RANGE_ENCRYPTED :
					   KVM_MAP_GPA_RANGE_DECRYPTED;
	tdx->vcpu.run->hypercall.flags   = KVM_EXIT_HYPERCALL_LONG_MODE;

	tdx->vcpu.arch.complete_userspace_io = tdx_complete_vmcall_map_gpa;
}

static int tdx_map_gpa(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx * tdx = to_tdx(vcpu);
	u64 gpa = tdvmcall_a0_read(vcpu);
	u64 size = tdvmcall_a1_read(vcpu);
	u64 ret;

	/*
	 * Converting TDVMCALL_MAP_GPA to KVM_HC_MAP_GPA_RANGE requires
	 * userspace to enable KVM_CAP_EXIT_HYPERCALL with KVM_HC_MAP_GPA_RANGE
	 * bit set.  If not, the error code is not defined in GHCI for TDX, use
	 * TDVMCALL_STATUS_INVALID_OPERAND for this case.
	 */
	if (!(vcpu->kvm->arch.hypercall_exit_enabled & BIT(KVM_HC_MAP_GPA_RANGE))) {
		ret = TDVMCALL_STATUS_INVALID_OPERAND;
		goto error;
	}

	if (gpa + size <= gpa || !kvm_vcpu_is_legal_gpa(vcpu, gpa) ||
	    !kvm_vcpu_is_legal_gpa(vcpu, gpa + size -1) ||
	    (kvm_is_private_gpa(vcpu->kvm, gpa) !=
	     kvm_is_private_gpa(vcpu->kvm, gpa + size -1))) {
		ret = TDVMCALL_STATUS_INVALID_OPERAND;
		goto error;
	}

	if (!PAGE_ALIGNED(gpa) || !PAGE_ALIGNED(size)) {
		ret = TDVMCALL_STATUS_ALIGN_ERROR;
		goto error;
	}

	tdx->map_gpa_end = gpa + size;
	tdx->map_gpa_next = gpa;

	__tdx_map_gpa(tdx);
	/* Forward request to userspace. */
	return 0;

error:
	tdvmcall_set_return_code(vcpu, ret);
	kvm_r11_write(vcpu, gpa);
	return 1;
}

static int tdx_report_fatal_error(struct kvm_vcpu *vcpu)
{
	u64 reg_mask = kvm_rcx_read(vcpu);
	u64* opt_regs;

	/*
	 * Skip sanity checks and let userspace decide what to do if sanity
	 * checks fail.
	 */
	vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
	vcpu->run->system_event.type = KVM_SYSTEM_EVENT_TDX_FATAL;
	vcpu->run->system_event.ndata = 10;
	/* Error codes. */
	vcpu->run->system_event.data[0] = tdvmcall_a0_read(vcpu);
	/* GPA of additional information page. */
	vcpu->run->system_event.data[1] = tdvmcall_a1_read(vcpu);
	/* Information passed via registers (up to 64 bytes). */
	opt_regs = &vcpu->run->system_event.data[2];

#define COPY_REG(REG, MASK)						\
	do {								\
		if (reg_mask & MASK) {					\
			*opt_regs = kvm_ ## REG ## _read(vcpu);		\
			opt_regs++;					\
		}							\
	} while (0)

	/* The order is defined in GHCI. */
	COPY_REG(r14, BIT_ULL(14));
	COPY_REG(r15, BIT_ULL(15));
	COPY_REG(rbx, BIT_ULL(3));
	COPY_REG(rdi, BIT_ULL(7));
	COPY_REG(rsi, BIT_ULL(6));
	COPY_REG(r8, BIT_ULL(8));
	COPY_REG(r9, BIT_ULL(9));
	COPY_REG(rdx, BIT_ULL(2));
	*opt_regs = 0;

	/*
	 * Set the status code according to GHCI spec, although the vCPU may
	 * not return back to guest.
	 */
	tdvmcall_set_return_code(vcpu, TDVMCALL_STATUS_SUCCESS);

	/* Forward request to userspace. */
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

	tdvmcall_set_return_code(vcpu, TDVMCALL_STATUS_SUCCESS);

	return 1;
}

static int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	if (tdvmcall_exit_type(vcpu))
		return tdx_emulate_vmcall(vcpu);

	switch (tdvmcall_leaf(vcpu)) {
	case TDVMCALL_MAP_GPA:
		return tdx_map_gpa(vcpu);
	case TDVMCALL_REPORT_FATAL_ERROR:
		return tdx_report_fatal_error(vcpu);
	case EXIT_REASON_CPUID:
		return tdx_emulate_cpuid(vcpu);
	default:
		break;
	}

	tdvmcall_set_return_code(vcpu, TDVMCALL_STATUS_INVALID_OPERAND);
	return 1;
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

	err = tdh_mem_page_aug(kvm_tdx->tdr_pa, gpa, hpa, &entry, &level_state);
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
 * KVM_TDX_INIT_MEM_REGION calls kvm_gmem_populate() to get guest pages and
 * tdx_gmem_post_populate() to premap page table pages into private EPT.
 * Mapping guest pages into private EPT before TD is finalized should use a
 * seamcall TDH.MEM.PAGE.ADD(), which copies page content from a source page
 * from user to target guest pages to be added. This source page is not
 * available via common interface kvm_tdp_map_page(). So, currently,
 * kvm_tdp_map_page() only premaps guest pages into KVM mirrored root.
 * A counter nr_premapped is increased here to record status. The counter will
 * be decreased after TDH.MEM.PAGE.ADD() is called after the kvm_tdp_map_page()
 * in tdx_gmem_post_populate().
 */
static int tdx_mem_page_record_premap_cnt(struct kvm *kvm, gfn_t gfn,
					  enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	if (KVM_BUG_ON(kvm->arch.pre_fault_allowed, kvm))
		return -EINVAL;

	/* nr_premapped will be decreased when tdh_mem_page_add() is called. */
	atomic64_inc(&kvm_tdx->nr_premapped);
	return 0;
}

int tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
			      enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return -EINVAL;

	/*
	 * Because guest_memfd doesn't support page migration with
	 * a_ops->migrate_folio (yet), no callback is triggered for KVM on page
	 * migration.  Until guest_memfd supports page migration, prevent page
	 * migration.
	 * TODO: Once guest_memfd introduces callback on page migration,
	 * implement it and remove get_page/put_page().
	 */
	get_page(pfn_to_page(pfn));

	/*
	 * To match ordering of 'finalized' and 'pre_fault_allowed' in
	 * tdx_td_finalizemr().
	 */
	smp_rmb();
	if (likely(kvm_tdx->finalized))
		return tdx_mem_page_aug(kvm, gfn, level, pfn);

	return tdx_mem_page_record_premap_cnt(kvm, gfn, level, pfn);
}

static int tdx_sept_drop_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = pfn_to_hpa(pfn);
	u64 err, entry, level_state;

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return -EINVAL;

	if (KVM_BUG_ON(!is_hkid_assigned(kvm_tdx), kvm))
		return -EINVAL;

	do {
		/*
		 * When zapping private page, write lock is held. So no race
		 * condition with other vcpu sept operation.  Race only with
		 * TDH.VP.ENTER.
		 */
		err = tdh_mem_page_remove(kvm_tdx->tdr_pa, gpa, tdx_level, &entry,
					  &level_state);
	} while (unlikely(err == TDX_ERROR_SEPT_BUSY));
	if (unlikely(!kvm_tdx->finalized &&
		     err == (TDX_EPT_WALK_FAILED | TDX_OPERAND_ID_RCX))) {
		/*
		 * Page is mapped by KVM_TDX_INIT_MEM_REGION, but hasn't called
		 * tdh_mem_page_add().
		 */
		if (!is_last_spte(entry, level) || !(entry & VMX_EPT_RWX_MASK)) {
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

	do {
		/*
		 * TDX_OPERAND_BUSY can happen on locking PAMT entry.  Because
		 * this page was removed above, other thread shouldn't be
		 * repeatedly operating on this page.  Just retry loop.
		 */
		err = tdh_phymem_page_wbinvd_hkid(hpa, kvm_tdx->hkid);
	} while (unlikely(err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX)));
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err);
		return -EIO;
	}
	tdx_clear_page(hpa);
	tdx_unpin(kvm, pfn);
	return 0;
}

int tdx_sept_link_private_spt(struct kvm *kvm, gfn_t gfn,
			      enum pg_level level, void *private_spt)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = __pa(private_spt);
	u64 err, entry, level_state;

	err = tdh_mem_sept_add(to_kvm_tdx(kvm)->tdr_pa, gpa, tdx_level, hpa, &entry,
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

	/* For now large page isn't supported yet. */
	WARN_ON_ONCE(level != PG_LEVEL_4K);

	err = tdh_mem_range_block(kvm_tdx->tdr_pa, gpa, tdx_level, &entry, &level_state);
	if (unlikely(err == TDX_ERROR_SEPT_BUSY))
		return -EAGAIN;
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error_2(TDH_MEM_RANGE_BLOCK, err, entry, level_state);
		return -EIO;
	}
	return 0;
}

/*
 * Ensure shared and private EPTs to be flushed on all vCPUs.
 * tdh_mem_track() is the only caller that increases TD epoch. An increase in
 * the TD epoch (e.g., to value "N + 1") is successful only if no vCPUs are
 * running in guest mode with the value "N - 1".
 *
 * A successful execution of tdh_mem_track() ensures that vCPUs can only run in
 * guest mode with TD epoch value "N" if no TD exit occurs after the TD epoch
 * being increased to "N + 1".
 *
 * Kicking off all vCPUs after that further results in no vCPUs can run in guest
 * mode with TD epoch value "N", which unblocks the next tdh_mem_track() (e.g.
 * to increase TD epoch to "N + 2").
 *
 * TDX module will flush EPT on the next TD enter and make vCPUs to run in
 * guest mode with TD epoch value "N + 1".
 *
 * kvm_make_all_cpus_request() guarantees all vCPUs are out of guest mode by
 * waiting empty IPI handler ack_kick().
 *
 * No action is required to the vCPUs being kicked off since the kicking off
 * occurs certainly after TD epoch increment and before the next
 * tdh_mem_track().
 */
static void tdx_track(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;

	/* If TD isn't finalized, it's before any vcpu running. */
	if (unlikely(!kvm_tdx->finalized))
		return;

	lockdep_assert_held_write(&kvm->mmu_lock);

	do {
		err = tdh_mem_track(kvm_tdx->tdr_pa);
	} while (unlikely((err & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_BUSY));

	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_TRACK, err);

	kvm_make_all_cpus_request(kvm, KVM_REQ_OUTSIDE_GUEST_MODE);
}

int tdx_sept_free_private_spt(struct kvm *kvm, gfn_t gfn,
			      enum pg_level level, void *private_spt)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/*
	 * free_external_spt() is only called after hkid is freed when TD is
	 * tearing down.
	 * KVM doesn't (yet) zap page table pages in mirror page table while
	 * TD is active, though guest pages mapped in mirror page table could be
	 * zapped during TD is active, e.g. for shared <-> private conversion
	 * and slot move/deletion.
	 */
	if (KVM_BUG_ON(is_hkid_assigned(kvm_tdx), kvm))
		return -EINVAL;

	/*
	 * The HKID assigned to this TD was already freed and cache was
	 * already flushed. We don't have to flush again.
	 */
	return tdx_reclaim_page(__pa(private_spt));
}

int tdx_sept_remove_private_spte(struct kvm *kvm, gfn_t gfn,
				 enum pg_level level, kvm_pfn_t pfn)
{
	int ret;

	/*
	 * HKID is released when vm_free() which is after closing gmem_fd
	 * which causes gmem invalidation to zap all spte.
	 * Population is only allowed after KVM_TDX_INIT_VM.
	 */
	if (KVM_BUG_ON(!is_hkid_assigned(to_kvm_tdx(kvm)), kvm))
		return -EINVAL;

	ret = tdx_sept_zap_private_spte(kvm, gfn, level);
	if (ret)
		return ret;

	/*
	 * TDX requires TLB tracking before dropping private page.  Do
	 * it here, although it is also done later.
	 */
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

static inline bool tdx_is_sept_violation_unexpected_pending(struct kvm_vcpu *vcpu)
{
	u64 eeq = tdexit_ext_exit_qual(vcpu) & TDX_EXT_EXIT_QUAL_TYPE_MASK;
	u64 eq = tdexit_exit_qual(vcpu);

	if ((eq & EPT_VIOLATION_RWX_MASK) || (eq & EPT_VIOLATION_EXEC_FOR_RING3_LIN))
		return false;

	return eeq == TDX_EXT_EXIT_QUAL_TYPE_PENDING_EPT_VIOLATION;
}

static int tdx_handle_ept_violation(struct kvm_vcpu *vcpu)
{
	gpa_t gpa = tdexit_gpa(vcpu);
	unsigned long exit_qual;

	if (kvm_is_private_gpa(vcpu->kvm, gpa)) {
		if (tdx_is_sept_violation_unexpected_pending(vcpu)) {
			pr_warn("Guest access before accepting 0x%llx on vCPU %d\n",
				gpa, vcpu->vcpu_id);
			kvm_vm_dead(vcpu->kvm);
			return -EIO;
		}
		/*
		 * Always treat SEPT violations as write faults.  Ignore the
		 * EXIT_QUALIFICATION reported by TDX-SEAM for SEPT violations.
		 * TD private pages are always RWX in the SEPT tables,
		 * i.e. they're always mapped writable.  Just as importantly,
		 * treating SEPT violations as write faults is necessary to
		 * avoid COW allocations, which will cause TDAUGPAGE failures
		 * due to aliasing a single HPA to multiple GPAs.
		 */
		exit_qual = EPT_VIOLATION_ACC_WRITE;
	} else {
		exit_qual = tdexit_exit_qual(vcpu);
		/*
		 * Instruction fetch in TD from shared memory never causes EPT
		 * violation. Warn if such an EPT violation occurs as the CPU
		 * probably is buggy.
		 */
		if (KVM_BUG_ON(exit_qual & EPT_VIOLATION_ACC_INSTR, vcpu->kvm))
			return -EIO;
	}

	trace_kvm_page_fault(vcpu, tdexit_gpa(vcpu), exit_qual);
	return __vmx_handle_ept_violation(vcpu, tdexit_gpa(vcpu), exit_qual);
}

int tdx_handle_exit(struct kvm_vcpu *vcpu, fastpath_t fastpath)
{
	u64 vp_enter_ret = to_tdx(vcpu)->vp_enter_ret;
	union vmx_exit_reason exit_reason;

	if (unlikely(!to_tdx(vcpu)->initialized))
		return -EINVAL;

	if (fastpath != EXIT_FASTPATH_NONE)
		return 1;

	/* Handle TDX SW errors, including #UD, #GP. */
	if (unlikely((vp_enter_ret & TDX_SW_ERROR) == TDX_SW_ERROR)) {
		KVM_BUG_ON(!kvm_rebooting, vcpu->kvm);
		goto unhandled_exit;
	}

	if (unlikely(vp_enter_ret & (TDX_ERROR | TDX_NON_RECOVERABLE))) {
		int hkid = to_kvm_tdx(vcpu->kvm)->hkid;

		/* Triple fault is non-recoverable. */
		if (unlikely(tdx_check_exit_reason(vcpu, EXIT_REASON_TRIPLE_FAULT)))
			return tdx_handle_triple_fault(vcpu);

		kvm_pr_unimpl("TD vp_enter_ret 0x%llx, hkid 0x%x hkid pa 0x%llx\n",
			      vp_enter_ret, hkid,
			      (u64)(0 | (hkid << boot_cpu_data.x86_phys_bits)));
		goto unhandled_exit;
	}

	/* From now, the seamcall status should be TDX_SUCCESS. */
	WARN_ON_ONCE((vp_enter_ret & TDX_SEAMCALL_STATUS_MASK) != TDX_SUCCESS);
	exit_reason = tdexit_exit_reason(vcpu);

	switch (exit_reason.basic) {
	case EXIT_REASON_EXCEPTION_NMI:
		return tdx_handle_exception_nmi(vcpu);
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return tdx_handle_external_interrupt(vcpu);
	case EXIT_REASON_TDCALL:
		return handle_tdvmcall(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_handle_ept_violation(vcpu);
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
	vcpu->run->internal.data[0] = vp_enter_ret;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;
	return 0;
}

void tdx_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason,
		u64 *info1, u64 *info2, u32 *intr_info, u32 *error_code)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (tdx_has_exit_reason(vcpu)) {
		/*
	 	 * Encode some useful info from the the 64 bit return code
	 	 * into the 32 bit exit 'reason'. If the VMX exit reason is
	 	 * valid, just set it to those bits.
	 	 */
		*reason = (u32)tdx->vp_enter_ret;
		*info1 = tdexit_exit_qual(vcpu);
		*info2 = tdexit_ext_exit_qual(vcpu);
	} else {
		/* 
		 * When the VMX exit reason in vp_enter_ret is not valid,
		 * overload the VMX_EXIT_REASONS_FAILED_VMENTRY bit (31) to
		 * mean the vmexit code is not valid. Set the other bits to
		 * try to avoid picking a value that may someday be a valid
		 * VMX exit code.
		 */
		*reason = 0xFFFFFFFF;
		*info1 = 0;
		*info2 = 0;
	}

	*intr_info = tdexit_intr_info(vcpu);
	*error_code = 0;
}

static int tdx_get_capabilities(struct kvm_tdx_cmd *cmd)
{
	const struct tdx_sys_info_td_conf *td_conf = &tdx_sysinfo->td_conf;
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities *caps = NULL;
	int ret = 0;

	/* flags is reserved for future use */
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

	if (caps->nr_cpuid_configs < td_conf->num_cpuid_config) {
		ret = -E2BIG;
		goto out;
	}

	caps->supported_attrs = kvm_tdx_caps->supported_attrs;
	caps->supported_xfam = kvm_tdx_caps->supported_xfam;
	caps->nr_cpuid_configs = kvm_tdx_caps->num_cpuid_config;

	if (copy_to_user(user_caps, caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}

	if (copy_to_user(user_caps->cpuid_configs, &kvm_tdx_caps->cpuid_configs,
			 kvm_tdx_caps->num_cpuid_config *
			 sizeof(kvm_tdx_caps->cpuid_configs[0])))
		ret = -EFAULT;

out:
	/* kfree() accepts NULL. */
	kfree(caps);
	return ret;
}

static int setup_tdparams_eptp_controls(struct kvm_cpuid2 *cpuid,
					struct td_params *td_params)
{
	const struct kvm_cpuid_entry2 *entry;
	int guest_pa;

	entry = kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent, 0x80000008, 0);
	if (!entry)
		return -EINVAL;

	guest_pa = (entry->eax >> 16) & 0xff;

	if (guest_pa != 48 && guest_pa != 52)
		return -EINVAL;

	if (guest_pa == 52 && !cpu_has_vmx_ept_5levels())
		return -EINVAL;

	td_params->eptp_controls = VMX_EPTP_MT_WB;
	if (guest_pa == 52) {
		td_params->eptp_controls |= VMX_EPTP_PWL_5;
		td_params->config_flags |= TDX_CONFIG_FLAGS_MAX_GPAW;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
	}

	return 0;
}

static int setup_tdparams_cpuids(struct kvm_cpuid2 *cpuid,
				 struct td_params *td_params)
{
	const struct tdx_sys_info_td_conf *td_conf = &tdx_sysinfo->td_conf;
	const struct kvm_tdx_cpuid_config *c;
	const struct kvm_cpuid_entry2 *entry;
	struct tdx_cpuid_value *value;
	int i, copy_cnt = 0;

	/*
	 * td_params.cpuid_values: The number and the order of cpuid_value must
	 * be same to the one of struct tdsysinfo.{num_cpuid_config, cpuid_configs}
	 * It's assumed that td_params was zeroed.
	 */
	for (i = 0; i < td_conf->num_cpuid_config; i++) {
		c = &kvm_tdx_caps->cpuid_configs[i];
		entry = kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent,
					      c->leaf, c->sub_leaf);
		if (!entry)
			continue;

		copy_cnt++;

		value = &td_params->cpuid_values[i];
		value->eax = entry->eax;
		value->ebx = entry->ebx;
		value->ecx = entry->ecx;
		value->edx = entry->edx;

		if (c->leaf == 0x80000008)
			value->eax &= 0xff00ffff;
	}

	/*
	 * Rely on the TDX module to reject invalid configuration, but it can't
	 * check of leafs that don't have a proper slot in td_params->cpuid_values
	 * to stick then. So fail if there were entries that didn't get copied to
	 * td_params.
	 */
	if (copy_cnt != cpuid->nent)
		return -EINVAL;

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
	const struct tdx_sys_info_td_conf *td_conf = &tdx_sysinfo->td_conf;
	struct kvm_cpuid2 *cpuid = &init_vm->cpuid;
	int ret;

	if (kvm->created_vcpus)
		return -EBUSY;

	if (init_vm->attributes & ~kvm_tdx_caps->supported_attrs)
		return -EINVAL;

	if (init_vm->xfam & ~kvm_tdx_caps->supported_xfam)
		return -EINVAL;

	td_params->max_vcpus = kvm->max_vcpus;
	td_params->attributes = init_vm->attributes | td_conf->attributes_fixed1;
	td_params->xfam = init_vm->xfam | td_conf->xfam_fixed1;

	td_params->config_flags = TDX_CONFIG_FLAGS_NO_RBP_MOD;
	td_params->tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(kvm->arch.default_tsc_khz);

	ret = setup_tdparams_eptp_controls(cpuid, td_params);
	if (ret)
		return ret;

	ret = setup_tdparams_cpuids(cpuid, td_params);
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

	atomic_inc(&nr_configured_hkid);

	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		goto free_hkid;
	tdr_pa = __pa(va);

	kvm_tdx->nr_tdcs_pages = tdx_sysinfo->td_ctrl.tdcs_base_size / PAGE_SIZE;
        /* TDVPS = TDVPR(4K page) + TDCX(multiple 4K pages), -1 for TDVPR. */
	kvm_tdx->nr_vcpu_tdcx_pages = tdx_sysinfo->td_ctrl.tdvps_base_size / PAGE_SIZE - 1;


	tdcs_pa = kcalloc(kvm_tdx->nr_tdcs_pages, sizeof(*kvm_tdx->tdcs_pa),
			  GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!tdcs_pa)
		goto free_tdr;

	for (i = 0; i < kvm_tdx->nr_tdcs_pages; i++) {
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
	 * TDH.MNG.CREATE tries to grab the global TDX module and fails
	 * with TDX_OPERAND_BUSY when it fails to grab.  Take the global
	 * lock to prevent it from failure.
	 */
	mutex_lock(&tdx_lock);
	kvm_tdx->tdr_pa = tdr_pa;
	err = tdh_mng_create(kvm_tdx->tdr_pa, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);

	if (err == TDX_RND_NO_ENTROPY) {
		ret = -EAGAIN;
		goto free_packages;
	}

	if (WARN_ON_ONCE(err)) {
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
		 * controller results in TDX_OPERAND_BUSY. No locking needed
		 * beyond the cpus_read_lock() above as it serializes against
		 * hotplug and the first online CPU of the package is always
		 * used. We never have two CPUs in the same socket trying to
		 * program the key.
		 */
		ret = smp_call_on_cpu(i, tdx_do_tdh_mng_key_config,
				      kvm_tdx, true);
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
	for (i = 0; i < kvm_tdx->nr_tdcs_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx->tdr_pa, tdcs_pa[i]);
		if (err == TDX_RND_NO_ENTROPY) {
			/* Here it's hard to allow userspace to retry. */
			ret = -EBUSY;
			goto teardown_reclaim;
		}
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err);
			ret = -EIO;
			goto teardown_reclaim;
		}
	}

	err = tdh_mng_init(kvm_tdx->tdr_pa, __pa(td_params), &rcx);
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

	return 0;

	/*
	 * The sequence for freeing resources from a partially initialized TD
	 * varies based on where in the initialization flow failure occurred.
	 * Simply use the full teardown and destroy, which naturally play nice
	 * with partial initialization.
	 */
teardown:
	for (; i < kvm_tdx->nr_tdcs_pages; i++) {
		if (tdcs_pa[i]) {
			free_page((unsigned long)__va(tdcs_pa[i]));
			tdcs_pa[i] = 0;
		}
	}
	if (!kvm_tdx->tdcs_pa)
		kfree(tdcs_pa);

teardown_reclaim:
	tdx_mmu_release_hkid(kvm);
	tdx_vm_free(kvm);

	return ret;

free_packages:
	cpus_read_unlock();
	free_cpumask_var(packages);

free_tdcs:
	for (i = 0; i < kvm_tdx->nr_tdcs_pages; i++) {
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
	tdx_hkid_free(kvm_tdx);

	return ret;
}

static u64 tdx_td_metadata_field_read(struct kvm_tdx *tdx, u64 field_id,
				      u64 *data)
{
	u64 err;

	err = tdh_mng_rd(tdx->tdr_pa, field_id, data);

	return err;
}

#define TDX_MD_UNREADABLE_LEAF_MASK	GENMASK(30, 7)
#define TDX_MD_UNREADABLE_SUBLEAF_MASK	GENMASK(31, 7)

static int tdx_read_cpuid(struct kvm_vcpu *vcpu, u32 leaf, u32 sub_leaf,
			  bool sub_leaf_set, struct kvm_cpuid_entry2 *out)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	u64 field_id = TD_MD_FIELD_ID_CPUID_VALUES;
	u64 ebx_eax, edx_ecx;
	u64 err = 0;

	if (sub_leaf & TDX_MD_UNREADABLE_LEAF_MASK ||
	    sub_leaf_set & TDX_MD_UNREADABLE_SUBLEAF_MASK)
		return -EINVAL;

	/*
	 * bit 23:17, REVSERVED: reserved, must be 0;
	 * bit 16,    LEAF_31: leaf number bit 31;
	 * bit 15:9,  LEAF_6_0: leaf number bits 6:0, leaf bits 30:7 are
	 *                      implicitly 0;
	 * bit 8,     SUBLEAF_NA: sub-leaf not applicable flag;
	 * bit 7:1,   SUBLEAF_6_0: sub-leaf number bits 6:0. If SUBLEAF_NA is 1,
	 *                         the SUBLEAF_6_0 is all-1.
	 *                         sub-leaf bits 31:7 are implicitly 0;
	 * bit 0,     ELEMENT_I: Element index within field;
	 */
	field_id |= ((leaf & 0x80000000) ? 1 : 0) << 16;
	field_id |= (leaf & 0x7f) << 9;
	if (sub_leaf_set)
		field_id |= (sub_leaf & 0x7f) << 1;
	else
		field_id |= 0x1fe;

	err = tdx_td_metadata_field_read(kvm_tdx, field_id, &ebx_eax);
	if (err) //TODO check for specific errors
		goto err_out;

	out->eax = (u32) ebx_eax;
	out->ebx = (u32) (ebx_eax >> 32);

	field_id++;
	err = tdx_td_metadata_field_read(kvm_tdx, field_id, &edx_ecx);
	/*
	 * It's weird that reading edx_ecx fails while reading ebx_eax
	 * succeeded.
	 */
	if (WARN_ON_ONCE(err))
		goto err_out;

	out->ecx = (u32) edx_ecx;
	out->edx = (u32) (edx_ecx >> 32);

	out->function = leaf;
	out->index = sub_leaf;
	out->flags |= sub_leaf_set ? KVM_CPUID_FLAG_SIGNIFCANT_INDEX : 0;

	/*
	 * Work around missing support on old TDX modules, fetch
	 * guest maxpa from gfn_direct_bits.
	 */
	if (leaf == 0x80000008) {
		gpa_t gpa_bits = gfn_to_gpa(kvm_gfn_direct_bits(vcpu->kvm));
		unsigned int g_maxpa = __ffs(gpa_bits) + 1;

		out->eax &= ~0x00ff0000;
		out->eax |= g_maxpa << 16;
	}

	return 0;

err_out:
	out->eax = 0;
	out->ebx = 0;
	out->ecx = 0;
	out->edx = 0;

	return -EIO;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_vm *init_vm;
	struct td_params *td_params = NULL;
	int ret;

	BUILD_BUG_ON(sizeof(*init_vm) != 256 + sizeof_field(struct kvm_tdx_init_vm, cpuid));
	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	if (is_hkid_assigned(kvm_tdx))
		return -EINVAL;

	if (cmd->flags)
		return -EINVAL;

	init_vm = kmalloc(sizeof(*init_vm) +
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

	ret = __tdx_td_init(kvm, td_params, &cmd->hw_error);
	if (ret)
		goto out;

	kvm_tdx->tsc_offset = td_tdcs_exec_read64(kvm_tdx, TD_TDCS_EXEC_TSC_OFFSET);
	kvm_tdx->attributes = td_params->attributes;
	kvm_tdx->xfam = td_params->xfam;

	if (td_params->config_flags & TDX_CONFIG_FLAGS_MAX_GPAW)
		kvm->arch.gfn_direct_bits = gpa_to_gfn(BIT_ULL(51));
	else
		kvm->arch.gfn_direct_bits = gpa_to_gfn(BIT_ULL(47));

out:
	/* kfree() accepts NULL. */
	kfree(init_vm);
	kfree(td_params);

	return ret;
}

void tdx_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	/*
	 * flush_tlb_current() is used only the first time for the vcpu to run.
	 * As it isn't performance critical, keep this function simple.
	 */
	ept_sync_global();
}

static int tdx_td_finalizemr(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	guard(mutex)(&kvm->slots_lock);

	if (!is_hkid_assigned(kvm_tdx) || kvm_tdx->finalized)
		return -EINVAL;
	/*
	 * Pages are pending for KVM_TDX_INIT_MEM_REGION to issue
	 * TDH.MEM.PAGE.ADD().
	 */
	if (atomic64_read(&kvm_tdx->nr_premapped))
		return -EINVAL;

	cmd->hw_error = tdh_mr_finalize(kvm_tdx->tdr_pa);
	if ((cmd->hw_error & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_BUSY)
		return -EAGAIN;
	if (KVM_BUG_ON(cmd->hw_error, kvm)) {
		pr_tdx_error(TDH_MR_FINALIZE, cmd->hw_error);
		return -EIO;
	}

	kvm_tdx->finalized = true;
	/* 'finalized' must be set before 'pre_fault_allowed' */
	smp_wmb();
	kvm->arch.pre_fault_allowed = true;
	return 0;
}

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	/*
	 * Userspace should never set hw_error. It is used to fill
	 * hardware-defined error by the kernel.
	 */
	if (tdx_cmd.hw_error)
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
	const struct tdx_sys_info_features *modinfo = &tdx_sysinfo->features;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long va;
	int ret, i;
	u64 err;

	if (tdx->td_vcpu_created)
		return -EINVAL;

	/*
	 * vcpu_free method frees allocated pages.  Avoid partial setup so
	 * that the method can't handle it.
	 */
	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		return -ENOMEM;
	tdx->tdvpr_pa = __pa(va);

	tdx->tdcx_pa = kcalloc(kvm_tdx->nr_vcpu_tdcx_pages, sizeof(*tdx->tdcx_pa),
			   GFP_KERNEL_ACCOUNT);
	if (!tdx->tdcx_pa) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}

	err = tdh_vp_create(kvm_tdx->tdr_pa, tdx->tdvpr_pa);
	if (KVM_BUG_ON(err, vcpu->kvm)) {
		tdx->tdvpr_pa = 0;
		ret = -EIO;
		pr_tdx_error(TDH_VP_CREATE, err);
		goto free_tdvpx;
	}

	for (i = 0; i < kvm_tdx->nr_vcpu_tdcx_pages; i++) {
		va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!va) {
			ret = -ENOMEM;
			goto free_tdvpx;
		}
		tdx->tdcx_pa[i] = __pa(va);

		err = tdh_vp_addcx(tdx->tdvpr_pa, tdx->tdcx_pa[i]);
		if (KVM_BUG_ON(err, vcpu->kvm)) {
			pr_tdx_error(TDH_VP_ADDCX, err);
			/* vcpu_free method frees TDCX and TDR donated to TDX */
			return -EIO;
		}
	}

	if (modinfo->tdx_features0 & MD_FIELD_ID_FEATURES0_TOPOLOGY_ENUM)
		err = tdh_vp_init_apicid(tdx->tdvpr_pa, vcpu_rcx, vcpu->vcpu_id);
	else
		err = tdh_vp_init(tdx->tdvpr_pa, vcpu_rcx);

	if (KVM_BUG_ON(err, vcpu->kvm)) {
		pr_tdx_error(TDH_VP_INIT, err);
		return -EIO;
	}

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	tdx->td_vcpu_created = true;

	return 0;

free_tdvpx:
	for (i = 0; i < kvm_tdx->nr_vcpu_tdcx_pages; i++) {
		if (tdx->tdcx_pa[i])
			free_page((unsigned long)__va(tdx->tdcx_pa[i]));
		tdx->tdcx_pa[i] = 0;
	}
	kfree(tdx->tdcx_pa);
	tdx->tdcx_pa = NULL;

free_tdvpr:
	if (tdx->tdvpr_pa)
		free_page((unsigned long)__va(tdx->tdvpr_pa));
	tdx->tdvpr_pa = 0;

	return ret;
}

/* Sometimes reads multipple subleafs. Return how many enties were written. */
static int tdx_vcpu_get_cpuid_leaf(struct kvm_vcpu *vcpu, u32 leaf, int max_cnt,
				   struct kvm_cpuid_entry2 *output_e)
{
	
	int i;

	if (!max_cnt)
		return 0;

	/* First try without a subleaf */
	if (!tdx_read_cpuid(vcpu, leaf, 0, false, output_e))
		return 1;
	
	/*
	 * If the try without a subleaf failed, try reading subleafs until
	 * failure. The TDX module only supports 6 bits of subleaf index.
	 */
	for (i = 0; i < 0b111111; i++) {
		if (i > max_cnt)
			goto out;

		/* Keep reading subleafs until there is a failure. */
		if (tdx_read_cpuid(vcpu, leaf, i, true, output_e))
			return i;

		output_e++;
	}

out:
	return i;
}

static int tdx_vcpu_get_cpuid(struct kvm_vcpu *vcpu, struct kvm_tdx_cmd *cmd)
{
	struct kvm_cpuid2 __user *output, *td_cpuid;
	struct kvm_cpuid_entry2 *output_e;
	int r = 0, i = 0, leaf;

	output = u64_to_user_ptr(cmd->data);
	td_cpuid = kzalloc(sizeof(*td_cpuid) +
			sizeof(output->entries[0]) * KVM_MAX_CPUID_ENTRIES,
			GFP_KERNEL);
	if (!td_cpuid)
		return -ENOMEM;

	for (leaf = 0; leaf <= 0x1f; leaf++) {
		output_e = &td_cpuid->entries[i];
		i += tdx_vcpu_get_cpuid_leaf(vcpu, leaf,
					     KVM_MAX_CPUID_ENTRIES - i - 1,
					     output_e);
	}

	for (leaf = 0x80000000; leaf <= 0x80000008; leaf++) {
		output_e = &td_cpuid->entries[i];
		i += tdx_vcpu_get_cpuid_leaf(vcpu, leaf,
					     KVM_MAX_CPUID_ENTRIES - i - 1,
					     output_e);
	}

	td_cpuid->nent = i;

	if (copy_to_user(output, td_cpuid, sizeof(*output))) {
		r = -EFAULT;
		goto out;
	}
	if (copy_to_user(output->entries, td_cpuid->entries,
			 td_cpuid->nent * sizeof(struct kvm_cpuid_entry2)))
		r = -EFAULT;

out:
	kfree(td_cpuid);

	return r;
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
	gpa_t gpa = gfn_to_gpa(gfn);
	u8 level = PG_LEVEL_4K;
	struct page *page;
	int ret, i;
	u64 err, entry, level_state;

	/*
	 * Get the source page if it has been faulted in. Return failure if the
	 * source page has been swapped out or unmapped in primary memory.
	 */
	ret = get_user_pages_fast((unsigned long)src, 1, 0, &page);
	if (ret < 0)
		return ret;
	if (ret != 1)
		return -ENOMEM;

	if (!kvm_mem_is_private(kvm, gfn)) {
		ret = -EFAULT;
		goto out_put_page;
	}

	ret = kvm_tdp_map_page(vcpu, gpa, error_code, &level);
	if (ret < 0)
		goto out_put_page;

	read_lock(&kvm->mmu_lock);

	if (!kvm_tdp_mmu_gpa_is_mapped(vcpu, gpa)) {
		ret = -ENOENT;
		goto out;
	}

	ret = 0;
	do {
		err = tdh_mem_page_add(kvm_tdx->tdr_pa, gpa, pfn_to_hpa(pfn),
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
			err = tdh_mr_extend(kvm_tdx->tdr_pa, gpa + i, &entry,
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
	int ret;

	if (!to_tdx(vcpu)->initialized)
		return -EINVAL;

	guard(mutex)(&kvm->slots_lock);

	/* Once TD is finalized, the initial guest memory is fixed. */
	if (kvm_tdx->finalized)
		return -EINVAL;

	if (cmd->flags & ~KVM_TDX_MEASURE_MEMORY_REGION)
		return -EINVAL;

	if (copy_from_user(&region, u64_to_user_ptr(cmd->data), sizeof(region)))
		return -EFAULT;

	if (!PAGE_ALIGNED(region.source_addr) || !PAGE_ALIGNED(region.gpa) ||
	    !region.nr_pages ||
	    region.gpa + (region.nr_pages << PAGE_SHIFT) <= region.gpa ||
	    !kvm_is_private_gpa(kvm, region.gpa) ||
	    !kvm_is_private_gpa(kvm, region.gpa + (region.nr_pages << PAGE_SHIFT) - 1))
		return -EINVAL;

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

	if (copy_to_user(u64_to_user_ptr(cmd->data), &region, sizeof(region)))
		ret = -EFAULT;
	return ret;
}

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct kvm_tdx_cmd cmd;
	int ret;

	if (!is_hkid_assigned(kvm_tdx) || kvm_tdx->finalized)
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.hw_error)
		return -EINVAL;

	switch (cmd.id) {
	case KVM_TDX_INIT_VCPU:
		ret = tdx_vcpu_init(vcpu, &cmd);
		break;
	case KVM_TDX_INIT_MEM_REGION:
		ret = tdx_vcpu_init_mem_region(vcpu, &cmd);
		break;
	case KVM_TDX_GET_CPUID:
		ret = tdx_vcpu_get_cpuid(vcpu, &cmd);
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

#define KVM_SUPPORTED_TD_ATTRS (TDX_TD_ATTR_SEPT_VE_DISABLE)

static int __init setup_kvm_tdx_caps(void)
{
	const struct tdx_sys_info_td_conf *td_conf = &tdx_sysinfo->td_conf;
	u64 kvm_supported;
	int i;

	kvm_tdx_caps = kzalloc(sizeof(*kvm_tdx_caps) +
			       sizeof(struct kvm_tdx_cpuid_config) * td_conf->num_cpuid_config,
			       GFP_KERNEL);
	if (!kvm_tdx_caps)
		return -ENOMEM;

	kvm_supported = KVM_SUPPORTED_TD_ATTRS;
	if ((kvm_supported & td_conf->attributes_fixed1) != td_conf->attributes_fixed1)
		goto err;

	kvm_tdx_caps->supported_attrs = kvm_supported & td_conf->attributes_fixed0;

	kvm_supported = kvm_caps.supported_xcr0 | kvm_caps.supported_xss;

	/*
	 * PT and CET can be exposed to TD guest regardless of KVM's XSS, PT
	 * and, CET support.
	 */
	kvm_supported |= XFEATURE_MASK_PT | XFEATURE_MASK_CET_USER |
			 XFEATURE_MASK_CET_KERNEL;
	if ((kvm_supported & td_conf->xfam_fixed1) != td_conf->xfam_fixed1)
		goto err;

	kvm_tdx_caps->supported_xfam = kvm_supported & td_conf->xfam_fixed0;

	kvm_tdx_caps->num_cpuid_config = td_conf->num_cpuid_config;
	for (i = 0; i < td_conf->num_cpuid_config; i++) {
		struct kvm_tdx_cpuid_config *dest =
			&kvm_tdx_caps->cpuid_configs[i];

		dest->leaf = (u32)td_conf->cpuid_config_leaves[i];
		dest->sub_leaf = td_conf->cpuid_config_leaves[i] >> 32;
		dest->eax = (u32)td_conf->cpuid_config_values[i].eax_ebx;
		dest->ebx = td_conf->cpuid_config_values[i].eax_ebx >> 32;
		dest->ecx = (u32)td_conf->cpuid_config_values[i].ecx_edx;
		dest->edx = td_conf->cpuid_config_values[i].ecx_edx >> 32;

		if (dest->sub_leaf == KVM_TDX_CPUID_NO_SUBLEAF)
			dest->sub_leaf = 0;

		/* Work around missing support on old TDX modules */
		if (dest->leaf == 0x80000008)
			dest->eax |= 0x00ff0000;
	}

	return 0;
err:
	kfree(kvm_tdx_caps);
	return -EIO;
}

static void free_kvm_tdx_cap(void)
{
	kfree(kvm_tdx_caps);
}

static int tdx_online_cpu(unsigned int cpu)
{
	unsigned long flags;
	int r;

	/* Sanity check CPU is already in post-VMXON */
	WARN_ON_ONCE(!(cr4_read_shadow() & X86_CR4_VMXE));

	/* tdx_cpu_enable() must be called with IRQ disabled */
	local_irq_save(flags);
	r = tdx_cpu_enable();
	local_irq_restore(flags);

	return r;
}

static int tdx_offline_cpu(unsigned int cpu)
{
	int i;

	/* No TD is running.  Allow any cpu to be offline. */
	if (!atomic_read(&nr_configured_hkid))
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
		if (i != cpu && topology_physical_package_id(i) ==
				topology_physical_package_id(cpu))
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

static void __do_tdx_cleanup(void)
{
	/*
	 * Once TDX module is initialized, it cannot be disabled and
	 * re-initialized again w/o runtime update (which isn't
	 * supported by kernel).  In fact the kernel doesn't support
	 * disable (shut down) TDX module, so only need to remove the
	 * cpuhp state.
	 */
	WARN_ON_ONCE(!tdx_cpuhp_state);
	cpuhp_remove_state_nocalls(tdx_cpuhp_state);
	tdx_cpuhp_state = 0;
}

static int __init __do_tdx_bringup(void)
{
	int r;

	/*
	 * TDX-specific cpuhp callback to call tdx_cpu_enable() on all
	 * online CPUs before calling tdx_enable(), and on any new
	 * going-online CPU to make sure it is ready for TDX guest.
	 */
	r = cpuhp_setup_state_cpuslocked(CPUHP_AP_ONLINE_DYN,
					 "kvm/cpu/tdx:online",
					 tdx_online_cpu, tdx_offline_cpu);
	if (r < 0)
		return r;

	tdx_cpuhp_state = r;

	/* tdx_enable() must be called with cpus_read_lock() */
	r = tdx_enable();
	if (r)
		__do_tdx_cleanup();

	return r;
}

static int __init __tdx_bringup(void)
{
	const struct tdx_sys_info_td_conf *td_conf;
	int r, i;

	if (!tdp_mmu_enabled || !enable_mmio_caching)
		return -EOPNOTSUPP;

	if (!cpu_feature_enabled(X86_FEATURE_MOVDIR64B)) {
		pr_warn("MOVDIR64B is reqiured for TDX\n");
		return -EOPNOTSUPP;
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

	/*
	 * Enabling TDX requires enabling hardware virtualization first,
	 * as making SEAMCALLs requires CPU being in post-VMXON state.
	 */
	r = kvm_enable_virtualization();
	if (r)
		return r;

	cpus_read_lock();
	r = __do_tdx_bringup();
	cpus_read_unlock();

	if (r)
		goto tdx_bringup_err;

	/* Get TDX global information for later use */
	tdx_sysinfo = tdx_get_sysinfo();
	if (WARN_ON_ONCE(!tdx_sysinfo)) {
		r = -EINVAL;
		goto get_sysinfo_err;
	}

	/*
	 * TDX has its own limit of maximum vCPUs it can support for all
	 * TDX guests in addition to KVM_MAX_VCPUS.  Userspace needs to
	 * query TDX guest's maximum vCPUs by checking KVM_CAP_MAX_VCPU
	 * extension on per-VM basis.
	 *
	 * TDX module reports such limit via the MAX_VCPU_PER_TD global
	 * metadata.  Different modules may report different values.
	 * Some old module may also not support this metadata (in which
	 * case this limit is U16_MAX).
	 *
	 * In practice, the reported value reflects the maximum logical
	 * CPUs that ALL the platforms that the module supports can
	 * possibly have.
	 *
	 * Simply forwarding the MAX_VCPU_PER_TD to userspace could
	 * result in an unpredictable ABI.  KVM instead always advertise
	 * the number of logical CPUs the platform has as the maximum
	 * vCPUs for TDX guests.
	 *
	 * Make sure MAX_VCPU_PER_TD reported by TDX module is not
	 * smaller than the number of logical CPUs, otherwise KVM will
	 * report an unsupported value to userspace.
	 *
	 * Note, a platform with TDX enabled in the BIOS cannot support
	 * physical CPU hotplug, and TDX requires the BIOS has marked
	 * all logical CPUs in MADT table as enabled.  Just use
	 * num_present_cpus() for the number of logical CPUs.
	 */
	td_conf = &tdx_sysinfo->td_conf;
	if (td_conf->max_vcpus_per_td < num_present_cpus()) {
		pr_err("Disable TDX: MAX_VCPU_PER_TD (%u) smaller than number of logical CPUs (%u).\n",
				td_conf->max_vcpus_per_td, num_present_cpus());
		r = -EINVAL;
		goto get_sysinfo_err;
	}

	r = setup_kvm_tdx_caps();
	if (r)
		goto get_sysinfo_err;

	/*
	 * Leave hardware virtualization enabled after TDX is enabled
	 * successfully.  TDX CPU hotplug depends on this.
	 */
	return 0;

get_sysinfo_err:
	__do_tdx_cleanup();
tdx_bringup_err:
	kvm_disable_virtualization();
	return r;
}

void tdx_cleanup(void)
{
	if (enable_tdx) {
		free_kvm_tdx_cap();
		__do_tdx_cleanup();
		kvm_disable_virtualization();
	}
}

void __init tdx_bringup(void)
{
	enable_tdx = enable_tdx && !__tdx_bringup();
}
