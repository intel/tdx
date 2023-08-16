// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/mmu_context.h>
#include <linux/misc_cgroup.h>

#include <asm/fpu/xcr.h>
#include <asm/virtext.h>
#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "common.h"
#include "mmu.h"
#include "tdx.h"
#include "vmx.h"
#include "x86.h"

#include <trace/events/kvm.h>
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define TDX_MAX_NR_CPUID_CONFIGS					\
	((TDSYSINFO_STRUCT_SIZE -					\
		offsetof(struct tdsysinfo_struct, cpuid_configs))	\
		/ sizeof(struct tdx_cpuid_config))

int tdx_vm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	int r;

	switch (cap->cap) {
	case KVM_CAP_MAX_VCPUS: {
		if (cap->flags || cap->args[0] == 0)
			return -EINVAL;
		if (cap->args[0] > KVM_MAX_VCPUS)
			return -E2BIG;
		if (cap->args[0] > TDX_MAX_VCPUS)
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

struct tdx_info {
	u8 nr_tdcs_pages;
	u8 nr_tdvpx_pages;
};

/* Info about the TDX module. */
static struct tdx_info tdx_info __ro_after_init;

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
static atomic_t nr_configured_hkid;

/*
 * A per-CPU list of TD vCPUs associated with a given CPU.  Used when a CPU
 * is brought down to invoke TDH_VP_FLUSH on the approapriate TD vCPUS.
 * Protected by interrupt mask.  This list is manipulated in process context
 * of vcpu and IPI callback.  See tdx_flush_vp_on_cpu().
 */
static DEFINE_PER_CPU(struct list_head, associated_tdvcpus);

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	return pa | ((hpa_t)hkid << boot_cpu_data.x86_phys_bits);
}

static __always_inline unsigned long tdexit_exit_qual(struct kvm_vcpu *vcpu)
{
	return to_tdx(vcpu)->exit_qualification;
}

static __always_inline unsigned long tdexit_ext_exit_qual(struct kvm_vcpu *vcpu)
{
	return to_tdx(vcpu)->ext_exit_qualification;
}

static __always_inline unsigned long tdexit_gpa(struct kvm_vcpu *vcpu)
{
	return to_tdx(vcpu)->exit_gpa;
}

static __always_inline unsigned long tdexit_intr_info(struct kvm_vcpu *vcpu)
{
	return to_tdx(vcpu)->exit_intr_info;
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
	return tdx->tdvpr_pa;
}

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr_pa;
}

static inline void tdx_hkid_free(struct kvm_tdx *kvm_tdx)
{
	tdx_guest_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = 0;
	misc_cg_uncharge(MISC_CG_RES_TDX, kvm_tdx->misc_cg, 1);
	put_misc_cg(kvm_tdx->misc_cg);
	kvm_tdx->misc_cg = NULL;
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
	list_del(&to_tdx(vcpu)->cpu_list);

	/*
	 * Ensure tdx->cpu_list is updated is before setting vcpu->cpu to -1,
	 * otherwise, a different CPU can see vcpu->cpu = -1 and add the vCPU
	 * to its list before its deleted from this CPUs list.
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

static void tdx_clear_page(unsigned long page_pa, int size)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	void *page = __va(page_pa);
	unsigned long i;

	WARN_ON_ONCE(size % PAGE_SIZE);
	/*
	 * When re-assign one page from old keyid to a new keyid, MOVDIR64B is
	 * required to clear/write the page with new keyid to prevent integrity
	 * error when read on the page with new keyid.
	 *
	 * clflush doesn't flush cache with HKID set.  The cache line could be
	 * poisoned (even without MKTME-i), clear the poison bit.
	 */
	for (i = 0; i < size; i += 64)
		movdir64b(page + i, zero_page);
	/*
	 * MOVDIR64B store uses WC buffer.  Prevent following memory reads
	 * from seeing potentially poisoned cache.
	 */
	__mb();
}

static int tdx_reclaim_page(hpa_t pa, enum pg_level level,
			    bool do_wb, u16 hkid)
{
	struct tdx_module_args out;
	u64 err;

	do {
		err = tdh_phymem_page_reclaim(pa, &out);
		/*
		 * TDH.PHYMEM.PAGE.RECLAIM is allowed only when TD is shutdown.
		 * state.  i.e. destructing TD.
		 * TDH.PHYMEM.PAGE.RECLAIM requires TDR and target page.
		 * Because we're destructing TD, it's rare to contend with TDR.
		 */
	} while (unlikely(err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX)));
	if (WARN_ON_ONCE(err)) {
		pr_err("%s:%d:%s pa 0x%llx level %d hkid 0x%x do_wb %d\n",
		       __FILE__, __LINE__, __func__,
		       pa, level, hkid, do_wb);
		pr_tdx_error(TDH_PHYMEM_PAGE_RECLAIM, err, &out);
		return -EIO;
	}
	/* out.r8 == tdx sept page level */
	WARN_ON_ONCE(out.r8 != pg_level_to_tdx_sept_level(level));

	if (do_wb && level == PG_LEVEL_4K) {
		/*
		 * Only TDR page gets into this path.  No contention is expected
		 * because of the last page of TD.
		 */
		err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(pa, hkid));
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			return -EIO;
		}
	}

	tdx_set_page_present_level(pa, level);
	tdx_clear_page(pa, KVM_HPAGE_SIZE(level));
	return 0;
}

static void tdx_reclaim_td_page(unsigned long td_page_pa)
{
	WARN_ON_ONCE(!td_page_pa);

	/*
	 * TDCX are being reclaimed.  TDX module maps TDCX with HKID
	 * assigned to the TD.  Here the cache associated to the TD
	 * was already flushed by TDH.PHYMEM.CACHE.WB before here, So
	 * cache doesn't need to be flushed again.
	 */
	if (tdx_reclaim_page(td_page_pa, PG_LEVEL_4K, false, 0))
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

static void tdx_flush_vp(void *arg_)
{
	struct tdx_flush_vp_arg *arg = arg_;
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
		 * No need to retry.  TDX Resources needed for TDH.VP.FLUSH are,
		 * TDVPR as exclusive, TDR as shared, and TDCS as shared.  This
		 * vp flush function is called when destructing vcpu/TD or vcpu
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
	if (WARN_ON_ONCE(arg.err)) {
		pr_err("cpu: %d ", cpu);
		pr_tdx_error(TDH_VP_FLUSH, arg.err, NULL);
	}
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

static int tdx_do_tdh_phymem_cache_wb(void *param)
{
	u64 err = 0;

	do {
		err = tdh_phymem_cache_wb(!!err);
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	/* Other thread may have done for us. */
	if (err == TDX_NO_HKID_READY_TO_WBCACHE)
		err = TDX_SUCCESS;
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_CACHE_WB, err, NULL);
		return -EIO;
	}

	return 0;
}

void tdx_mmu_release_hkid(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	bool cpumask_allocated;
	struct kvm_vcpu *vcpu;
	unsigned long j;
	u64 err;
	int ret;
	int i;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	if (!is_td_created(kvm_tdx))
		goto free_hkid;

	kvm_for_each_vcpu(j, vcpu, kvm)
		tdx_flush_vp_on_cpu(vcpu);

	mutex_lock(&tdx_lock);
	err = tdh_mng_vpflushdone(kvm_tdx->tdr_pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_VPFLUSHDONE, err, NULL);
		pr_err("tdh_mng_vpflushdone failed. HKID %d is leaked.\n",
			kvm_tdx->hkid);
		return;
	}

	cpumask_allocated = zalloc_cpumask_var(&packages, GFP_KERNEL);
	cpus_read_lock();
	for_each_online_cpu(i) {
		if (cpumask_allocated &&
			cpumask_test_and_set_cpu(topology_physical_package_id(i),
						packages))
			continue;

		/*
		 * We can destroy multiple the guest TDs simultaneously.
		 * Prevent tdh_phymem_cache_wb from returning TDX_BUSY by
		 * serialization.
		 */
		mutex_lock(&tdx_lock);
		ret = smp_call_on_cpu(i, tdx_do_tdh_phymem_cache_wb, NULL, 1);
		mutex_unlock(&tdx_lock);
		if (ret)
			break;
	}
	cpus_read_unlock();
	free_cpumask_var(packages);

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_freeid(kvm_tdx->tdr_pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err, NULL);
		pr_err("tdh_mng_key_freeid failed. HKID %d is leaked.\n",
			kvm_tdx->hkid);
		return;
	} else
		atomic_dec(&nr_configured_hkid);

free_hkid:
	tdx_hkid_free(kvm_tdx);
}

static void __tdx_vm_free(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int i;

	/*
	 * tdx_mmu_release_hkid() failed to reclaim HKID.  Something went wrong
	 * heavily with TDX module.  Give up freeing TD pages.  As the function
	 * already warned, don't warn it again.
	 */
	if (is_hkid_assigned(kvm_tdx))
		return;

	if (kvm_tdx->tdcs_pa) {
		for (i = 0; i < tdx_info.nr_tdcs_pages; i++) {
			if (!kvm_tdx->tdcs_pa[i])
				continue;
			tdx_reclaim_td_page(kvm_tdx->tdcs_pa[i]);
			tdx_unaccount_ctl_page(kvm);
		}
		kfree(kvm_tdx->tdcs_pa);
		kvm_tdx->tdcs_pa = NULL;
	}

	if (!kvm_tdx->tdr_pa)
		return;
	/*
	 * TDX module maps TDR with TDX global HKID.  TDX module may access TDR
	 * while operating on TD (Especially reclaiming TDCS).  Cache flush with
	 * TDX global HKID is needed.
	 */
	if (tdx_reclaim_page(kvm_tdx->tdr_pa, PG_LEVEL_4K, true, tdx_global_keyid))
		return;

	tdx_unaccount_ctl_page(kvm);
	free_page((unsigned long)__va(kvm_tdx->tdr_pa));
	kvm_tdx->tdr_pa = 0;

	kfree(kvm_tdx->cpuid);
	kvm_tdx->cpuid = NULL;
}

void tdx_vm_free(struct kvm *kvm)
{
	__tdx_vm_free(kvm);
#ifdef CONFIG_KVM_TDX_ACCOUNT_PRIVATE_PAGES
	if (WARN_ON_ONCE(atomic64_read(&to_kvm_tdx(kvm)->ctl_pages) ||
			 atomic64_read(&to_kvm_tdx(kvm)->sept_pages[PG_LEVEL_512G - PG_LEVEL_4K]) ||
			 atomic64_read(&to_kvm_tdx(kvm)->sept_pages[PG_LEVEL_1G - PG_LEVEL_4K]) ||
			 atomic64_read(&to_kvm_tdx(kvm)->sept_pages[PG_LEVEL_2M - PG_LEVEL_4K]) ||
			 atomic64_read(&to_kvm_tdx(kvm)->sept_pages[PG_LEVEL_4K - PG_LEVEL_4K]) ||
			 atomic64_read(&to_kvm_tdx(kvm)->td_pages))) {
		pr_warn_ratelimited("control %lld sept 512G %lld 1G %lld 2M %lld 4K %lld td %lld pages are left\n",
				    atomic64_read(&to_kvm_tdx(kvm)->ctl_pages),
				    atomic64_read(&to_kvm_tdx(kvm)->sept_pages[PG_LEVEL_512G - PG_LEVEL_4K]),
				    atomic64_read(&to_kvm_tdx(kvm)->sept_pages[PG_LEVEL_1G - PG_LEVEL_4K]),
				    atomic64_read(&to_kvm_tdx(kvm)->sept_pages[PG_LEVEL_2M - PG_LEVEL_4K]),
				    atomic64_read(&to_kvm_tdx(kvm)->sept_pages[PG_LEVEL_4K - PG_LEVEL_4K]),
				    atomic64_read(&to_kvm_tdx(kvm)->td_pages));
	}
#endif
}

static int tdx_do_tdh_mng_key_config(void *param)
{
	hpa_t *tdr_p = param;
	u64 err;

	do {
		err = tdh_mng_key_config(*tdr_p);

		/*
		 * If it failed to generate a random key, retry it because this
		 * is typically caused by an entropy error of the CPU's random
		 * number generator.
		 */
	} while (err == TDX_KEY_GENERATION_FAILED);

	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_CONFIG, err, NULL);
		return -EIO;
	}

	return 0;
}

int tdx_vm_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

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

	/* TDH.MEM.PAGE.AUG supports up to 2MB page. */
	kvm->arch.tdp_max_page_level = PG_LEVEL_2M;

	kvm_tdx->has_range_blocked = false;

	/*
	 * This function initializes only KVM software construct.  It doesn't
	 * initialize TDX stuff, e.g. TDCS, TDR, TDCX, HKID etc.
	 * It is handled by KVM_TDX_INIT_VM, __tdx_td_init().
	 */

	/*
	 * TDX has its own limit of the number of vcpus in addition to
	 * KVM_MAX_VCPUS.
	 */
	kvm->max_vcpus = min(kvm->max_vcpus, TDX_MAX_VCPUS);

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

	/*
	 * On cpu creation, cpuid entry is blank.  Forcibly enable
	 * X2APIC feature to allow X2APIC.
	 * Because vcpu_reset() can't return error, allocation is done here.
	 */
	WARN_ON_ONCE(vcpu->arch.cpuid_entries);
	WARN_ON_ONCE(vcpu->arch.cpuid_nent);

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
	 *	!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG);
	 */
	vcpu->arch.guest_state_protected = true;

	if ((kvm_tdx->xfam & XFEATURE_MASK_XTILE) == XFEATURE_MASK_XTILE)
		vcpu->arch.xfd_no_write_intercept = true;

	tdx->host_state_need_save = true;
	tdx->host_state_need_restore = false;

	tdx->pi_desc.nv = POSTED_INTR_VECTOR;
	tdx->pi_desc.sn = 1;

	return 0;
}

int tdx_vcpu_check_cpuid(struct kvm_vcpu *vcpu, struct kvm_cpuid_entry2 *e2, int nent)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	const struct tdsysinfo_struct *tdsysinfo;
	int i;

	tdsysinfo = tdx_get_sysinfo();
	if (!tdsysinfo)
		return -EOPNOTSUPP;

	/*
	 * Simple check that new cpuid is consistent with created one.
	 * For simplicity, only trivial check.  Don't try comprehensive checks
	 * with the cpuid virtualization table in the TDX module spec.
	 */
	for (i = 0; i < tdsysinfo->num_cpuid_config; i++) {
		const struct tdx_cpuid_config *config = &tdsysinfo->cpuid_configs[i];
		u32 index = config->sub_leaf == TDX_CPUID_NO_SUBLEAF ? 0 : config->sub_leaf;
		const struct kvm_cpuid_entry2 *old =
			kvm_find_cpuid_entry2(kvm_tdx->cpuid, kvm_tdx->cpuid_nent,
					      config->leaf, index);
		const struct kvm_cpuid_entry2 *new = kvm_find_cpuid_entry2(e2, nent,
									   config->leaf, index);

		if (!!old != !!new)
			return -EINVAL;
		if (!old && !new)
			continue;

		if ((old->eax ^ new->eax) & config->eax ||
		    (old->ebx ^ new->ebx) & config->ebx ||
		    (old->ecx ^ new->ecx) & config->ecx ||
		    (old->edx ^ new->edx) & config->edx)
			return -EINVAL;
	}
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
	bool ret = pi_has_pending_interrupt(vcpu);
	union tdx_vcpu_state_details details;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (ret || vcpu->arch.mp_state != KVM_MP_STATE_HALTED)
		return true;

	if (tdx->interrupt_disabled_hlt)
		return false;

	/*
	 * This is for the case where the virtual interrupt is recognized,
	 * i.e. set in vmcs.RVI, between the STI and "HLT".  KVM doesn't have
	 * access to RVI and the interrupt is no longer in the PID (because it
	 * was "recognized".  It doesn't get delivered in the guest because the
	 * TDCALL completes before interrupts are enabled.
	 *
	 * TDX modules sets RVI while in an STI interrupt shadow.
	 * - TDExit(typically TDG.VP.VMCALL<HLT>) from the guest to TDX module.
	 *   The interrupt shadow at this point is gone.
	 * - It knows that there is an interrupt that can be delivered
	 *   (RVI > PPR && EFLAGS.IF=1, the other conditions of 29.2.2 don't
	 *    matter)
	 * - It forwards the TDExit nevertheless, to a clueless hypervisor that
	 *   has no way to glean either RVI or PPR.
	 */
	if (xchg(&tdx->buggy_hlt_workaround, 0))
		return true;

	/*
	 * This is needed for device assignment. Interrupts can arrive from
	 * the assigned devices.  Because tdx.buggy_hlt_workaround can't be set
	 * by VMM, use TDX SEAMCALL to query pending interrupts.
	 */
	details.full = td_state_non_arch_read64(tdx, TD_VCPU_STATE_DETAILS_NON_ARCH);
	return !!details.vmxip;
}

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
	 * This methods can be called when vcpu allocation/initialization
	 * failed. So it's possible that hkid, tdvpx and tdvpr are not assigned
	 * yet.
	 */
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm))) {
		WARN_ON_ONCE(tdx->tdvpx_pa);
		WARN_ON_ONCE(tdx->tdvpr_pa);
		return;
	}

	/*
	 * When destroying VM, kvm_unload_vcpu_mmu() calls vcpu_load() for every
	 * vcpu after they already disassociated from the per cpu list by
	 * tdx_mmu_release_hkid().  So we need to disassociate them again,
	 * otherwise the freed vcpu data will be accessed when do
	 * list_{del,add}() on associated_tdvcpus list later.
	 */
	tdx_disassociate_vp_on_cpu(vcpu);
	WARN_ON_ONCE(vcpu->cpu != -1);

	if (tdx->tdvpx_pa) {
		for (i = 0; i < tdx_info.nr_tdvpx_pages; i++) {
			if (!tdx->tdvpx_pa[i])
				continue;
			tdx_reclaim_td_page(tdx->tdvpx_pa[i]);
			tdx_unaccount_ctl_page(vcpu->kvm);
		}
		kfree(tdx->tdvpx_pa);
		tdx->tdvpx_pa = NULL;
	}
	if (tdx->tdvpr_pa) {
		tdx_reclaim_td_page(tdx->tdvpr_pa);
		tdx->tdvpr_pa = 0;
		tdx_unaccount_ctl_page(vcpu->kvm);
	}
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{

	/* vcpu_deliver_init method silently discards INIT event. */
	if (KVM_BUG_ON(init_event, vcpu->kvm))
		return;
	if (KVM_BUG_ON(is_td_vcpu_created(to_tdx(vcpu)), vcpu->kvm))
		return;

	/*
	 * Don't update mp_state to runnable because more initialization
	 * is needed by TDX_VCPU_INIT.
	 */
}

static void tdx_complete_interrupts(struct kvm_vcpu *vcpu)
{
	/* Avoid costly SEAMCALL if no nmi was injected */
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
static unsigned int tdx_uret_tsx_ctrl_slot;

static void tdx_user_return_update_cache(struct kvm_vcpu *vcpu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++)
		kvm_user_return_update_cache(tdx_uret_msrs[i].slot,
					     tdx_uret_msrs[i].defval);
	/*
	 * TSX_CTRL is reset to 0 if guest TSX is supported. Otherwise
	 * preserved.
	 */
	if (to_kvm_tdx(vcpu->kvm)->tsx_supported && tdx_uret_tsx_ctrl_slot != -1)
		kvm_user_return_update_cache(tdx_uret_tsx_ctrl_slot, 0);
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
			 (kvm_caps.supported_xss | XFEATURE_MASK_PT | TDX_TD_XFAM_CET)))
		wrmsrl(MSR_IA32_XSS, host_xss);
	if (static_cpu_has(X86_FEATURE_PKU) &&
	    (kvm_tdx->xfam & XFEATURE_MASK_PKRU))
		write_pkru(vcpu->arch.host_pkru);
}

static noinstr void tdx_vcpu_enter_exit(struct vcpu_tdx *tdx)
{
	/*
	 * Avoid section mismatch with to_tdx() with KVM_VM_BUG().  The caller
	 * should call to_tdx().
	 */
	struct kvm_vcpu *vcpu = &tdx->vcpu;

	guest_state_enter_irqoff();

	/*
	 * struct tdx_module_args and struct kvm_vcpu_arch::args must be same
	 * layout to use __seamcall_saved_ret().
	 */
#define WORD_SIZE	(BITS_PER_LONG / 8)
#define BUG_ON_ARG_OFFSET(arg_reg, vcpu_reg)				\
	BUILD_BUG_ON(offsetof(struct tdx_module_args, arg_reg) !=	\
		     VCPU_REGS_ ## vcpu_reg * WORD_SIZE);

	BUG_ON_ARG_OFFSET(rax_unused, RAX);
	BUG_ON_ARG_OFFSET(rcx, RCX);
	BUG_ON_ARG_OFFSET(rdx, RDX);
	BUG_ON_ARG_OFFSET(rbx, RBX);
	BUG_ON_ARG_OFFSET(rsp_unused, RSP);
	BUG_ON_ARG_OFFSET(rbp_unused, RBP);
	BUG_ON_ARG_OFFSET(rsi, RSI);
	BUG_ON_ARG_OFFSET(rdi, RDI);
	BUG_ON_ARG_OFFSET(r8, R8);
	BUG_ON_ARG_OFFSET(r9, R9);
	BUG_ON_ARG_OFFSET(r10, R10);
	BUG_ON_ARG_OFFSET(r11, R11);
	BUG_ON_ARG_OFFSET(r12, R12);
	BUG_ON_ARG_OFFSET(r13, R13);
	BUG_ON_ARG_OFFSET(r14, R14);
	BUG_ON_ARG_OFFSET(r15, R15);

#undef BUG_ON_ARG_OFFSET
#undef WORD_SIZE

	/*
	 * TODO: micro optimization:
	 * copyin/copyout registers only if (tdx->tdvmvall.regs_mask != 0)
	 * which means TDG.VP.VMCALL.
	 */
	vcpu->arch.regs[VCPU_REGS_RCX] = tdx->tdvpr_pa;
	tdx->exit_reason.full = __seamcall_saved_ret(TDH_VP_ENTER,
						     (struct tdx_module_args*)vcpu->arch.regs);
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

fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (unlikely(!tdx->initialized))
		return -EINVAL;
	if (unlikely(vcpu->kvm->vm_bugged)) {
		tdx->exit_reason.full = TDX_NON_RECOVERABLE_VCPU;
		return EXIT_FASTPATH_NONE;
	}

	trace_kvm_entry(vcpu);

	if (pi_test_on(&tdx->pi_desc)) {
		apic->send_IPI_self(POSTED_INTR_VECTOR);

		kvm_wait_lapic_expire(vcpu);
	}

	tdx_vcpu_enter_exit(tdx);

	tdx_user_return_update_cache(vcpu);
	perf_restore_debug_store();
	tdx_restore_host_xsave_state(vcpu);
	tdx->host_state_need_restore = true;

	tdx->exit_qualification = kvm_rcx_read(vcpu);
	tdx->ext_exit_qualification = kvm_rdx_read(vcpu);
	tdx->exit_gpa = kvm_r8_read(vcpu);
	tdx->exit_intr_info = kvm_r9_read(vcpu);
	if (tdx->exit_reason.basic == EXIT_REASON_TDCALL)
		tdx->tdvmcall.rcx = kvm_rcx_read(vcpu);
	else
		tdx->tdvmcall.rcx = 0;

	trace_kvm_exit(vcpu, KVM_ISA_VMX);

	tdx_complete_interrupts(vcpu);

	vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;

	return EXIT_FASTPATH_NONE;
}

void tdx_inject_nmi(struct kvm_vcpu *vcpu)
{
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
	else if (unlikely(tdx->exit_reason.non_recoverable ||
		 tdx->exit_reason.error)) {
		/*
		 * The only reason it gets EXIT_REASON_OTHER_SMI is there is an
		 * #MSMI(Machine Check System Management Interrupt) with
		 * exit_qualification bit 0 set in TD guest.
		 * The #MSMI is delivered right after SEAMCALL returns,
		 * and an #MC is delivered to host kernel after SMI handler
		 * returns.
		 *
		 * The #MC right after SEAMCALL is fixed up and skipped in #MC
		 * handler because it's an #MC happens in TD guest we cannot
		 * handle it with host's context.
		 *
		 * Call KVM's machine check handler explicitly here.
		 */
		if (tdx->exit_reason.basic == EXIT_REASON_OTHER_SMI) {
			unsigned long exit_qual;

			exit_qual = tdexit_exit_qual(vcpu);
			if (exit_qual & TD_EXIT_OTHER_SMI_IS_MSMI)
				kvm_machine_check();
		}
	}
}

static int tdx_handle_exception(struct kvm_vcpu *vcpu)
{
	u32 intr_info = tdexit_intr_info(vcpu);

	if (is_nmi(intr_info) || is_machine_check(intr_info))
		return 1;

	if (to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG) {
		vcpu->run->exit_reason = KVM_EXIT_DEBUG;
		vcpu->mmio_needed = 0;
		vcpu->run->debug.arch.dr6 = 0;
		vcpu->run->debug.arch.dr7 = 0;
		vcpu->run->debug.arch.pc = kvm_get_linear_rip(vcpu);
		vcpu->run->debug.arch.exception = intr_info & 0xff;
		return 0;
	}

	kvm_pr_unimpl("unexpected exception 0x%x(exit_reason 0x%llx qual 0x%lx)\n",
		intr_info,
		to_tdx(vcpu)->exit_reason.full, tdexit_exit_qual(vcpu));
	return -EFAULT;
}

static int tdx_handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int tdx_handle_triple_fault(struct kvm_vcpu *vcpu)
{
	if (to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG)
		pr_err("triple fault at 0x%lx\n", kvm_rip_read(vcpu));
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

	ret = __kvm_emulate_hypercall(vcpu, nr, a0, a1, a2, a3, true);

	tdvmcall_set_return_code(vcpu, ret);

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

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);

	return 1;
}

static int tdx_emulate_hlt(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/* See tdx_protected_apic_has_interrupt() to avoid heavy seamcall */
	tdx->interrupt_disabled_hlt = tdvmcall_a0_read(vcpu);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return kvm_emulate_halt_noskip(vcpu);
}

static int tdx_complete_pio_in(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	int ret;

	WARN_ON_ONCE(vcpu->arch.pio.count != 1);

	ret = ctxt->ops->pio_in_emulated(ctxt, vcpu->arch.pio.size,
					 vcpu->arch.pio.port, &val, 1);
	WARN_ON_ONCE(!ret);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
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
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	if (write) {
		val = tdvmcall_a3_read(vcpu);
		ret = ctxt->ops->pio_out_emulated(ctxt, size, port, &val, 1);

		/* No need for a complete_userspace_io callback. */
		vcpu->arch.pio.count = 0;
	} else {
		ret = ctxt->ops->pio_in_emulated(ctxt, size, port, &val, 1);
		if (!ret)
			vcpu->arch.complete_userspace_io = tdx_complete_pio_in;
		else
			tdvmcall_set_return_val(vcpu, val);
	}
	if (ret)
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return ret;
}

static int tdx_complete_mmio(struct kvm_vcpu *vcpu)
{
	unsigned long val = 0;
	gpa_t gpa;
	int size;

	KVM_BUG_ON(vcpu->mmio_needed != 1, vcpu->kvm);
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

	KVM_BUG_ON(vcpu->mmio_needed, vcpu->kvm);

	size = tdvmcall_a0_read(vcpu);
	write = tdvmcall_a1_read(vcpu);
	gpa = tdvmcall_a2_read(vcpu);
	val = write ? tdvmcall_a3_read(vcpu) : 0;

	if (size != 1 && size != 2 && size != 4 && size != 8)
		goto error;
	if (write != 0 && write != 1)
		goto error;

	/* Strip the shared bit, allow MMIO with and without it set. */
	gpa = gpa & ~gfn_to_gpa(kvm_gfn_shared_mask(vcpu->kvm));

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
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
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
	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	return 1;
}

static int tdx_emulate_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_a0_read(vcpu);
	u64 data;

	if (!kvm_msr_allowed(vcpu, index, KVM_MSR_FILTER_READ) ||
	    kvm_get_msr(vcpu, index, &data)) {
		trace_kvm_msr_read_ex(index);
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}
	trace_kvm_msr_read(index, data);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
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
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	trace_kvm_msr_write(index, data);
	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return 1;
}

static int tdx_get_td_vm_call_info(struct kvm_vcpu *vcpu)
{
	if (tdvmcall_a0_read(vcpu))
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	else {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
		kvm_r11_write(vcpu, 0);
		tdvmcall_a0_write(vcpu, 0);
		tdvmcall_a1_write(vcpu, 0);
		tdvmcall_a2_write(vcpu, 0);
	}
	return 1;
}

static int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	int r;

	if (tdvmcall_exit_type(vcpu))
		return tdx_emulate_vmcall(vcpu);

	trace_kvm_tdx_hypercall(tdvmcall_leaf(vcpu), kvm_rcx_read(vcpu),
				kvm_r12_read(vcpu), kvm_r13_read(vcpu), kvm_r14_read(vcpu),
				kvm_rbx_read(vcpu), kvm_rdi_read(vcpu), kvm_rsi_read(vcpu),
				kvm_r8_read(vcpu), kvm_r9_read(vcpu), kvm_rdx_read(vcpu));

	switch (tdvmcall_leaf(vcpu)) {
	case EXIT_REASON_CPUID:
		r = tdx_emulate_cpuid(vcpu);
		break;
	case EXIT_REASON_HLT:
		r = tdx_emulate_hlt(vcpu);
		break;
	case EXIT_REASON_IO_INSTRUCTION:
		r = tdx_emulate_io(vcpu);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		r = tdx_emulate_mmio(vcpu);
		break;
	case EXIT_REASON_MSR_READ:
		r = tdx_emulate_rdmsr(vcpu);
		break;
	case EXIT_REASON_MSR_WRITE:
		r = tdx_emulate_wrmsr(vcpu);
		break;
	case TDG_VP_VMCALL_GET_TD_VM_CALL_INFO:
		r = tdx_get_td_vm_call_info(vcpu);
		break;
	default:
		/*
		 * Unknown VMCALL.  Toss the request to the user space VMM,
		 * e.g. qemu, as it may know how to handle.
		 *
		 * Those VMCALLs require user space VMM:
		 * TDG_VP_VMCALL_REPORT_FATAL_ERROR, TDG_VP_VMCALL_MAP_GPA,
		 * TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT, and
		 * TDG_VP_VMCALL_GET_QUOTE.
		 */
		r = tdx_vp_vmcall_to_user(vcpu);
		break;
	}

	trace_kvm_tdx_hypercall_done(r, kvm_r11_read(vcpu), kvm_r10_read(vcpu),
				     kvm_r12_read(vcpu), kvm_r13_read(vcpu), kvm_r14_read(vcpu),
				     kvm_rbx_read(vcpu), kvm_rdi_read(vcpu), kvm_rsi_read(vcpu),
				     kvm_r8_read(vcpu), kvm_r9_read(vcpu), kvm_rdx_read(vcpu));
	return r;
}

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	td_vmcs_write64(to_tdx(vcpu), SHARED_EPT_POINTER, root_hpa & PAGE_MASK);
}

static void tdx_measure_page(struct kvm_tdx *kvm_tdx, hpa_t gpa, int size)
{
	struct tdx_module_args out;
	u64 err;
	int i;

	WARN_ON_ONCE(size % TDX_EXTENDMR_CHUNKSIZE);

	for (i = 0; i < size; i += TDX_EXTENDMR_CHUNKSIZE) {
		err = tdh_mr_extend(kvm_tdx->tdr_pa, gpa + i, &out);
		if (KVM_BUG_ON(err, &kvm_tdx->kvm)) {
			pr_tdx_error(TDH_MR_EXTEND, err, &out);
			break;
		}
	}
}

static void tdx_unpin(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
		      enum pg_level level)
{
	int i;

	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++)
		put_page(pfn_to_page(pfn + i));
}

static int tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	hpa_t hpa = pfn_to_hpa(pfn);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_args out;
	hpa_t source_pa;
	bool measure;
	u64 err;
	int i;

	if (WARN_ON_ONCE(is_error_noslot_pfn(pfn) ||
			 !kvm_pfn_to_refcounted_page(pfn)))
		return 0;

	/*
	 * Because restricted mem doesn't support page migration with
	 * a_ops->migrate_page (yet), no callback isn't triggered for KVM on
	 * page migration.  Until restricted mem supports page migration,
	 * prevent page migration.
	 * TODO: Once restricted mem introduces callback on page migration,
	 * implement it and remove get_page/put_page().
	 */
	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++)
		get_page(pfn_to_page(pfn + i));

	/* Build-time faults are induced and handled via TDH_MEM_PAGE_ADD. */
	if (likely(is_td_finalized(kvm_tdx))) {
		err = tdh_mem_page_aug(kvm_tdx->tdr_pa, gpa, tdx_level, hpa, &out);
		if (unlikely(err == TDX_ERROR_SEPT_BUSY)) {
			tdx_unpin(kvm, gfn, pfn, level);
			return -EAGAIN;
		}
		if (unlikely(err == (TDX_EPT_ENTRY_NOT_FREE | TDX_OPERAND_ID_RCX))) {
			/*
			 * TDX 1.0 may return TDX_EPT_ENTRY_NOT_FREE without
			 * SEPT entry.  TDX 1.5 (or later) returns
			 * TDX_EPT_ENTRY_STATE_INCORRECT.  Emulate it.
			 */
			err = tdh_mem_sept_rd(kvm_tdx->tdr_pa, gpa, tdx_level, &out);
			if (KVM_BUG_ON(err, kvm)) {
				pr_tdx_error(TDH_MEM_SEPT_RD, err, &out);
				tdx_unpin(kvm, gfn, pfn, level);
				return -EIO;
			}
			err = TDX_EPT_ENTRY_STATE_INCORRECT | TDX_OPERAND_ID_RCX;
		}
		if (unlikely(err == (TDX_EPT_ENTRY_STATE_INCORRECT | TDX_OPERAND_ID_RCX))) {
			union tdx_sept_entry entry = {
				.raw = out.rcx,
			};
			union tdx_sept_level_state level_state = {
				.raw = out.rdx,
			};

			/*
			 * TD.attribute.sept_ve_disable=1 and EPT violation on
			 * pending page. Probably it's a race condition or a bug
			 * for guest TD to access unaccepted region.  Let vcpu
			 * retry with the expectation of a race condition so that
			 * other vcpu would accept the page.
			 */
			if (level_state.level == tdx_level &&
			    level_state.state == TDX_SEPT_PENDING &&
			    entry.leaf && entry.hpa == hpa && entry.sve) {
				tdx_unpin(kvm, gfn, pfn, level);
				WARN_ON_ONCE(!(to_kvm_tdx(kvm)->attributes &
					       BIT(28) /* =ATTR_SEPT_VE_DISABLE) */));
				WARN_ON_ONCE(1);
				return -EAGAIN;
			}

			/* Someone updated the entry to the same value. */
			if (level_state.level == tdx_level &&
			    level_state.state == TDX_SEPT_PRESENT &&
			    entry.leaf && entry.hpa == hpa) {
				tdx_unpin(kvm, gfn, pfn, level);
				return -EAGAIN;
			}
		}
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_AUG, err, &out);
			tdx_unpin(kvm, gfn, pfn, level);
			return -EIO;
		}
		tdx_account_td_pages(kvm, level);
		trace_kvm_tdx_page_add(kvm_tdx->tdr_pa, gfn, pfn, level);
		return 0;
	}

	/*
	 * KVM_INIT_MEM_REGION, tdx_init_mem_region(), supports only 4K page
	 * because tdh_mem_page_add() supports only 4K page.
	 */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return -EINVAL;

	/*
	 * In case of TDP MMU, fault handler can run concurrently.  Note
	 * 'source_pa' is a TD scope variable, meaning if there are multiple
	 * threads reaching here with all needing to access 'source_pa', it
	 * will break.  However fortunately this won't happen, because below
	 * TDH_MEM_PAGE_ADD code path is only used when VM is being created
	 * before it is running, using KVM_TDX_INIT_MEM_REGION ioctl (which
	 * always uses vcpu 0's page table and protected by vcpu->mutex).
	 */
	if (KVM_BUG_ON(kvm_tdx->source_pa == INVALID_PAGE, kvm)) {
		tdx_unpin(kvm, gfn, pfn, level);
		return -EINVAL;
	}

	source_pa = kvm_tdx->source_pa & ~KVM_TDX_MEASURE_MEMORY_REGION;
	measure = kvm_tdx->source_pa & KVM_TDX_MEASURE_MEMORY_REGION;
	kvm_tdx->source_pa = INVALID_PAGE;

	do {
		err = tdh_mem_page_add(kvm_tdx->tdr_pa, gpa, tdx_level, hpa,
				       source_pa, &out);
		/*
		 * This path is executed during populating initial guest memory
		 * image. i.e. before running any vcpu.  Race is rare.
		 */
	} while (unlikely(err == TDX_ERROR_SEPT_BUSY));
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_ADD, err, &out);
		tdx_unpin(kvm, gfn, pfn, level);
		return -EIO;
	} else if (measure)
		tdx_measure_page(kvm_tdx, gpa, KVM_HPAGE_SIZE(level));

	tdx_account_td_pages(kvm, level);
	trace_kvm_tdx_page_add(kvm_tdx->tdr_pa, gfn, pfn, level);
	return 0;
}

static int tdx_sept_drop_private_spte(struct kvm *kvm, gfn_t gfn,
				       enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_module_args out;
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = pfn_to_hpa(pfn);
	hpa_t hpa_with_hkid;
	int r = 0;
	u64 err;
	int i;

	if (unlikely(!is_hkid_assigned(kvm_tdx))) {
		/*
		 * The HKID assigned to this TD was already freed and cache
		 * was already flushed. We don't have to flush again.
		 */
		err = tdx_reclaim_page(hpa, level, false, 0);
		if (KVM_BUG_ON(err, kvm)) {
			pr_err("%s:%d:%s gfn 0x%llx level 0x%x pfn 0x%llx\n",
			       __FILE__, __LINE__, __func__, gfn, level, pfn);
			return -EIO;
		}
		tdx_unpin(kvm, gfn, pfn, level);
		tdx_unaccount_td_pages(kvm, level);
		trace_kvm_tdx_page_remove(kvm_tdx->tdr_pa, gfn, pfn, level);
		return 0;
	}

	do {
		/*
		 * When zapping private page, write lock is held. So no race
		 * condition with other vcpu sept operation.  Race only with
		 * TDH.VP.ENTER.
		 */
		err = tdh_mem_page_remove(kvm_tdx->tdr_pa, gpa, tdx_level, &out);
	} while (unlikely(err == TDX_ERROR_SEPT_BUSY));
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_REMOVE, err, &out);
		return -EIO;
	}

	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++) {
		hpa_with_hkid = set_hkid_to_hpa(hpa, (u16)kvm_tdx->hkid);
		do {
			/*
			 * TDX_OPERAND_BUSY can happen on locking PAMT entry.
			 * Because this page was removed above, other thread
			 * shouldn't be repeatedly operating on this page.
			 * Simple retry should work.
			 */
			err = tdh_phymem_page_wbinvd(hpa_with_hkid);
		} while (unlikely(err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX)));
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			r = -EIO;
		} else {
			tdx_set_page_present(hpa);
			tdx_clear_page(hpa, PAGE_SIZE);
			tdx_unpin(kvm, gfn + i, pfn + i, PG_LEVEL_4K);
		}
		hpa += PAGE_SIZE;
	}
	tdx_unaccount_td_pages(kvm, level);
	trace_kvm_tdx_page_remove(kvm_tdx->tdr_pa, gfn, pfn, level);
	return r;
}

static int tdx_sept_link_private_spt(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, void *private_spt)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = __pa(private_spt);
	struct tdx_module_args out;
	u64 err;

	err = tdh_mem_sept_add(kvm_tdx->tdr_pa, gpa, tdx_level, hpa, &out);
	if (unlikely(err == TDX_ERROR_SEPT_BUSY))
		return -EAGAIN;
	if (unlikely(err == (TDX_EPT_ENTRY_NOT_FREE | TDX_OPERAND_ID_RCX))) {
		err = tdh_mem_sept_rd(kvm_tdx->tdr_pa, gpa, tdx_level, &out);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_SEPT_RD, err, &out);
			return -EIO;
		}
		err = TDX_EPT_ENTRY_STATE_INCORRECT | TDX_OPERAND_ID_RCX;
	}
	if (unlikely(err == (TDX_EPT_ENTRY_STATE_INCORRECT | TDX_OPERAND_ID_RCX))) {
		union tdx_sept_entry entry = {
			.raw = out.rcx,
		};
		union tdx_sept_level_state level_state = {
			.raw = out.rdx,
		};

		/* someone updated the entry with same value. */
		if (level_state.level == tdx_level &&
		    level_state.state == TDX_SEPT_PRESENT &&
		    !entry.leaf && entry.hpa == hpa)
			return -EAGAIN;
	}
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_ADD, err, &out);
		return -EIO;
	}

	/* level is for parent's. */
	tdx_account_sept_page(kvm, level - 1);
	trace_kvm_tdx_sept_add(kvm_tdx->tdr_pa, gfn, hpa >> PAGE_SHIFT, level - 1);
	return 0;
}

static int tdx_sept_split_private_spt(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, void *private_spt)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn) & KVM_HPAGE_MASK(level);
	hpa_t hpa = __pa(private_spt);
	struct tdx_module_args out;
	u64 err;

	/* See comment in tdx_sept_set_private_spte() */
	do {
		err = tdh_mem_page_demote(kvm_tdx->tdr_pa, gpa, tdx_level, hpa, &out);
	} while (err == TDX_INTERRUPTED_RESTARTABLE);
	if (unlikely(err == TDX_ERROR_SEPT_BUSY)) {
		trace_kvm_tdx_page_demote(kvm_tdx->tdr_pa, gfn, hpa >> PAGE_SHIFT,
					  level, -EAGAIN);
		return -EAGAIN;
	}
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_DEMOTE, err, &out);
		trace_kvm_tdx_page_demote(kvm_tdx->tdr_pa, gfn, hpa >> PAGE_SHIFT, level, -EIO);
		return -EIO;
	}

	tdx_account_sept_page(kvm, level - 1);
	trace_kvm_tdx_page_demote(kvm_tdx->tdr_pa, gfn, hpa >> PAGE_SHIFT, level, 0);
	return 0;
}

static int tdx_sept_merge_private_spt(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, void *private_spt)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_module_args out;
	gpa_t gpa = gfn_to_gpa(gfn) & KVM_HPAGE_MASK(level);
	u64 err;

	/* See comment in tdx_sept_set_private_spte() */
	do {
		err = tdh_mem_page_promote(kvm_tdx->tdr_pa, gpa, tdx_level, &out);
	} while (err == TDX_INTERRUPTED_RESTARTABLE);
	if (unlikely(err == TDX_ERROR_SEPT_BUSY)) {
		trace_kvm_tdx_page_promote(kvm_tdx->tdr_pa, gfn,
					   __pa(private_spt) >> PAGE_SHIFT, level, -EAGAIN);
		return -EAGAIN;
	}
	if (unlikely(err == (TDX_EPT_INVALID_PROMOTE_CONDITIONS |
			     TDX_OPERAND_ID_RCX))) {
		/*
		 * Some pages are accepted, some pending.  Need to wait for TD
		 * to accept all pages.  Tell it the caller.
		 */
		trace_kvm_tdx_page_promote(kvm_tdx->tdr_pa, gfn,
					   __pa(private_spt) >> PAGE_SHIFT, level, -EAGAIN);
		return -EAGAIN;
	}
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_PROMOTE, err, &out);
		trace_kvm_tdx_page_promote(kvm_tdx->tdr_pa, gfn,
					   __pa(private_spt) >> PAGE_SHIFT, level, -EIO);
		return -EIO;
	}
	WARN_ON_ONCE(out.rcx != __pa(private_spt));

	/*
	 * TDH.MEM.PAGE.PROMOTE frees the Secure-EPT page for the lower level.
	 * Flush cache for reuse.
	 */
	do {
		err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(__pa(private_spt),
							     to_kvm_tdx(kvm)->hkid));
	} while (unlikely(err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX)));
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
		trace_kvm_tdx_page_promote(kvm_tdx->tdr_pa, gfn,
					   __pa(private_spt) >> PAGE_SHIFT, level, -EIO);
		return -EIO;
	}

	tdx_set_page_present(__pa(private_spt));
	tdx_clear_page(__pa(private_spt), PAGE_SIZE);
	tdx_unaccount_sept_page(kvm, level - 1);
	trace_kvm_tdx_page_promote(kvm_tdx->tdr_pa, gfn,
				   __pa(private_spt) >> PAGE_SHIFT, level, 0);
	return 0;
}

static int tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn) & KVM_HPAGE_MASK(level);
	struct tdx_module_args out;
	u64 err;

	/* This can be called when destructing guest TD after freeing HKID. */
	if (unlikely(!is_hkid_assigned(kvm_tdx)))
		return 0;

	err = tdh_mem_range_block(kvm_tdx->tdr_pa, gpa, tdx_level, &out);
	if (unlikely(err == TDX_ERROR_SEPT_BUSY))
		return -EAGAIN;
	if (unlikely(err == (TDX_GPA_RANGE_ALREADY_BLOCKED | TDX_OPERAND_ID_RCX)))
		return -EAGAIN;

	WRITE_ONCE(kvm_tdx->has_range_blocked, true);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &out);
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
static void tdx_track(struct kvm_tdx *kvm_tdx)
{
	u64 err;

	KVM_BUG_ON(!is_hkid_assigned(kvm_tdx), &kvm_tdx->kvm);
	/* If TD isn't finalized, it's before any vcpu running. */
	if (unlikely(!is_td_finalized(kvm_tdx)))
		return;

	/*
	 * tdx_flush_tlb() waits for this function to issue TDH.MEM.TRACK() by
	 * the counter.  The counter is used instead of bool because multiple
	 * TDH_MEM_TRACK() can be issued concurrently by multiple vcpus.
	 */
	atomic_inc(&kvm_tdx->tdh_mem_track);
	/*
	 * KVM_REQ_TLB_FLUSH waits for the empty IPI handler, ack_flush(), with
	 * KVM_REQUEST_WAIT.
	 */
	kvm_make_all_cpus_request(&kvm_tdx->kvm, KVM_REQ_TLB_FLUSH);

	do {
		/*
		 * kvm_flush_remote_tlbs() doesn't allow to return error and
		 * retry.
		 */
		err = tdh_mem_track(kvm_tdx->tdr_pa);
	} while (unlikely((err & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_BUSY));

	/* Release remote vcpu waiting for TDH.MEM.TRACK in tdx_flush_tlb(). */
	atomic_dec(&kvm_tdx->tdh_mem_track);

	if (KVM_BUG_ON(err, &kvm_tdx->kvm))
		pr_tdx_error(TDH_MEM_TRACK, err, NULL);

}

static int tdx_sept_unzap_private_spte(struct kvm *kvm, gfn_t gfn,
				       enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn) & KVM_HPAGE_MASK(level);
	struct tdx_module_args out;
	u64 err;

	do {
		err = tdh_mem_range_unblock(kvm_tdx->tdr_pa, gpa, tdx_level, &out);

		/*
		 * tdh_mem_range_block() is accompanied with tdx_track() via kvm
		 * remote tlb flush.  Wait for the caller of
		 * tdh_mem_range_block() to complete TDX track.
		 */
	} while (err == (TDX_TLB_TRACKING_NOT_DONE | TDX_OPERAND_ID_SEPT));
	if (unlikely(err == TDX_ERROR_SEPT_BUSY))
		return -EAGAIN;
	if (unlikely(err == (TDX_GPA_RANGE_NOT_BLOCKED | TDX_OPERAND_ID_RCX)))
		return -EAGAIN;
	if (unlikely(err == (TDX_EPT_ENTRY_STATE_INCORRECT | TDX_OPERAND_ID_RCX))) {
		union tdx_sept_level_state level_state = {
			.raw = out.rdx,
		};

		if (level_state.level == tdx_level &&
		    (level_state.state == TDX_SEPT_PRESENT ||
		     level_state.state == TDX_SEPT_PENDING)) {
			return -EAGAIN;
		}
	}
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_RANGE_UNBLOCK, err, &out);
		return -EIO;
	}
	return 0;
}

static int tdx_sept_free_private_spt(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, void *private_spt)
{
	/* +1 to remove this SEPT page from the parent's entry. */
	gpa_t parent_gpa = gfn_to_gpa(gfn) & KVM_HPAGE_MASK(level + 1);
	int parent_tdx_level = pg_level_to_tdx_sept_level(level + 1);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_module_args out;
	u64 err;

	/*
	 * The HKID assigned to this TD was already freed and cache was
	 * already flushed. We don't have to flush again.
	 */
	if (!is_hkid_assigned(kvm_tdx)) {
		int r;

		r = tdx_reclaim_page(__pa(private_spt), PG_LEVEL_4K, false, 0);
		if (!r) {
			tdx_unaccount_sept_page(kvm, level);
			trace_kvm_tdx_sept_remove(kvm_tdx->tdr_pa, gfn,
						  __pa(private_spt) >> PAGE_SHIFT, level);
		}
		return r;
	}

	/*
	 * Inefficient. But this is only called for deleting memslot
	 * which isn't performance critical path.
	 *
	 * free_private_spt() is (obviously) called when a shadow page is being
	 * zapped.  KVM doesn't (yet) zap private SPs while the TD is active.
	 * Note: This function is for private shadow page.  Not for private
	 * guest page.   private guest page can be zapped during TD is active.
	 * shared <-> private conversion and slot move/deletion.
	 */
	do {
		err = tdh_mem_range_block(kvm_tdx->tdr_pa, parent_gpa,
					  parent_tdx_level, &out);
	} while (unlikely(err == TDX_ERROR_SEPT_BUSY));
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &out);
		return -EIO;
	}

	tdx_track(kvm_tdx);

	err = tdh_mem_sept_remove(kvm_tdx->tdr_pa, parent_gpa,
				  parent_tdx_level, &out);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_REMOVE, err, &out);
		return -EIO;
	}
	tdx_unaccount_sept_page(kvm, level);

	err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(__pa(private_spt),
						     kvm_tdx->hkid));
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
		return -EIO;
	}
	tdx_set_page_present(__pa(private_spt));
	tdx_clear_page(__pa(private_spt), PAGE_SIZE);
	trace_kvm_tdx_sept_remove(kvm_tdx->tdr_pa, gfn,
				  __pa(private_spt) >> PAGE_SHIFT, level);
	return 0;
}

int tdx_sept_flush_remote_tlbs_range(struct kvm *kvm, gfn_t gfn, gfn_t nr_pages)
{
	struct kvm_tdx *kvm_tdx;

	if (unlikely(!is_td(kvm)))
		return -EOPNOTSUPP;

	kvm_tdx = to_kvm_tdx(kvm);
	if (is_hkid_assigned(kvm_tdx))
		tdx_track(kvm_tdx);

	return 0;
}

int tdx_sept_flush_remote_tlbs(struct kvm *kvm)
{
	return tdx_sept_flush_remote_tlbs_range(kvm, 0, -1ULL);
}

static int tdx_sept_remove_private_spte(struct kvm *kvm, gfn_t gfn,
					 enum pg_level level, kvm_pfn_t pfn)
{
	/*
	 * TDX requires TLB tracking before dropping private page.  Do
	 * it here, although it is also done later.
	 * If hkid isn't assigned, the guest is destroying and no vcpu
	 * runs further.  TLB shootdown isn't needed.
	 *
	 * TODO: implement with_range version for optimization.
	 * kvm_flush_remote_tlbs_with_address(kvm, gfn, 1);
	 *   => tdx_sept_flush_remote_tlbs_range(kvm, gfn,
	 *                                       KVM_PAGES_PER_HPAGE(level));
	 */
	if (is_hkid_assigned(to_kvm_tdx(kvm)))
		kvm_flush_remote_tlbs(kvm);

	return tdx_sept_drop_private_spte(kvm, gfn, level, pfn);
}

void tdx_deliver_interrupt(struct kvm_lapic *apic, int delivery_mode,
			   int trig_mode, int vector)
{
	struct kvm_vcpu *vcpu = apic->vcpu;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	/* See comment in tdx_protected_apic_has_interrupt(). */
	tdx->buggy_hlt_workaround = 1;
	/* TDX supports only posted interrupt.  No lapic emulation. */
	__vmx_deliver_posted_interrupt(vcpu, &tdx->pi_desc, vector);
}

static int tdx_handle_ept_violation(struct kvm_vcpu *vcpu)
{
	union tdx_ext_exit_qualification ext_exit_qual;
	unsigned long exit_qual;
	int err_page_level = 0;

	ext_exit_qual.full = tdexit_ext_exit_qual(vcpu);

	if (ext_exit_qual.type >= NUM_EXT_EXIT_QUAL) {
		pr_err("EPT violation at gpa 0x%lx, with invalid ext exit qualification type 0x%x\n",
			tdexit_gpa(vcpu), ext_exit_qual.type);
		kvm_vm_bugged(vcpu->kvm);
		return 0;
	} else if (ext_exit_qual.type == EXT_EXIT_QUAL_ACCEPT) {
		err_page_level = tdx_sept_level_to_pg_level(ext_exit_qual.req_sept_level);
	}

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
	return __vmx_handle_ept_violation(vcpu, tdexit_gpa(vcpu), exit_qual, err_page_level);
}

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON_ONCE(1);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

static int tdx_handle_bus_lock_vmexit(struct kvm_vcpu *vcpu)
{
	/*
	 * When EXIT_REASON_BUS_LOCK, bus_lock_detected bit is not necessarily
	 * set.  Enforce the bit set so that tdx_handle_exit() will handle it
	 * uniformly.
	 */
	to_tdx(vcpu)->exit_reason.bus_lock_detected = true;
	return 1;
}

static int __tdx_handle_exit(struct kvm_vcpu *vcpu, fastpath_t fastpath)
{
	union tdx_exit_reason exit_reason = to_tdx(vcpu)->exit_reason;

	/* See the comment of tdh_sept_seamcall(). */
	if (unlikely(exit_reason.full == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_SEPT)))
		return 1;

	/*
	 * TDH.VP.ENTRY checks TD EPOCH which contend with TDH.MEM.TRACK and
	 * vcpu TDH.VP.ENTER.
	 */
	if (unlikely(exit_reason.full == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_TD_EPOCH)))
		return 1;

	if (unlikely(exit_reason.full == (TDX_INCONSISTENT_MSR | MSR_IA32_TSX_CTRL))) {
		pr_err_once("TDX module is outdated. Use v1.0.3 or newer.\n");
		return 1;
	}

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

		/*
		 * tdx_handle_exit_irqoff() handled EXIT_REASON_OTHER_SMI.  It
		 * must be handled before enabling preemption because it's #MC.
		 */
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

	WARN_ON_ONCE(fastpath != EXIT_FASTPATH_NONE);

	switch (exit_reason.basic) {
	case EXIT_REASON_EXCEPTION_NMI:
		return tdx_handle_exception(vcpu);
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
		 * Unlike VMX, all the SMI in SEAM non-root mode (i.e. when
		 * TD guest vcpu is running) will cause TD exit to TDX module,
		 * then SEAMRET to KVM. Once it exits to KVM, SMI is delivered
		 * and handled right away.
		 *
		 * - If it's an Machine Check System Management Interrupt
		 *   (MSMI), it's handled above due to non_recoverable bit set.
		 * - If it's not an MSMI, don't need to do anything here.
		 */
		return 1;
	case EXIT_REASON_BUS_LOCK:
		tdx_handle_bus_lock_vmexit(vcpu);
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

int tdx_handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
	int ret = __tdx_handle_exit(vcpu, exit_fastpath);

	/* Exit to user space when bus-lock was detected in the guest TD. */
	if (unlikely(to_tdx(vcpu)->exit_reason.bus_lock_detected)) {
		if (ret > 0)
			vcpu->run->exit_reason = KVM_EXIT_X86_BUS_LOCK;

		vcpu->run->flags |= KVM_RUN_X86_BUS_LOCK;
		return 0;
	}
	return ret;
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

static bool tdx_is_emulated_kvm_msr(u32 index, bool write)
{
	switch (index) {
	case MSR_KVM_POLL_CONTROL:
		return true;
	default:
		return false;
	}
}

bool tdx_has_emulated_msr(u32 index, bool write)
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
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_EXT_CTL:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MCx_CTL(KVM_MAX_MCE_BANKS) - 1:
	case MSR_IA32_MC0_CTL2 ... MSR_IA32_MCx_CTL2(KVM_MAX_MCE_BANKS) - 1:
		/* MSR_IA32_MCx_{CTL, STATUS, ADDR, MISC, CTL2} */
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
	case MSR_IA32_FEAT_CTL:
	case MSR_IA32_APICBASE:
	case MSR_EFER:
		return !write;
	case 0x4b564d00 ... 0x4b564dff:
		/* KVM custom MSRs */
		return tdx_is_emulated_kvm_msr(index, write);
	default:
		return false;
	}
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
	case MSR_MTRRdefType:
		/*
		 * FIXME: Xen convention to disable guest MTRR:
		 * The guest kernel pretends as if MTRR isn't available when
		 * CPUID.MTRR = 1 (MTRR available) and MTRRdefType.enable = 0
		 * (MTRRs disabled) as BIOS hand-off state. Which is deviation
		 * from SDM.  MTRRdefType.enable = 0 means all memory access is
		 * UC according to the SDM.
		 *
		 * The TD guest kernel has to disable MTRR otherwise it tries
		 * program MTRRs to disable caching. CR4.CD=1 results in the
		 * unexpected #VE and the guest kernel panic.  As workaround,
		 * utilize the Xen convention in the guest kernel.
		 * E(MTRR enable)=0, FE(fixed range MTRR enable)=0,
		 * default memory type=WB
		 */
		msr->data = MTRR_TYPE_WRBACK;
		return 0;
	default:
		if (tdx_has_emulated_msr(msr->index, false))
			return kvm_get_msr_common(vcpu, msr);
		return 1;
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
		if (tdx_has_emulated_msr(msr->index, true))
			return kvm_set_msr_common(vcpu, msr);
		return 1;
	}
}

#ifdef CONFIG_KVM_SMM
int tdx_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	/* SMI isn't supported for TDX. */
	WARN_ON_ONCE(1);
	return false;
}

int tdx_enter_smm(struct kvm_vcpu *vcpu, union kvm_smram *smram)
{
	/* smi_allowed() is always false for TDX as above. */
	WARN_ON_ONCE(1);
	return 0;
}

int tdx_leave_smm(struct kvm_vcpu *vcpu, const union kvm_smram *smram)
{
	WARN_ON_ONCE(1);
	return 0;
}

void tdx_enable_smi_window(struct kvm_vcpu *vcpu)
{
	/* SMI isn't supported for TDX.  Silently discard SMI request. */
	WARN_ON_ONCE(1);
	vcpu->arch.smi_pending = false;
}
#endif

void tdx_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	/* Only x2APIC mode is supported for TD. */
	WARN_ON_ONCE(kvm_get_apic_mode(vcpu) != LAPIC_MODE_X2APIC);
}

int tdx_get_cpl(struct kvm_vcpu *vcpu)
{
	return 0;
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

unsigned long tdx_get_rflags(struct kvm_vcpu *vcpu)
{
	return 0;
}

u64 tdx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	return 0;
}

void tdx_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	memset(var, 0, sizeof(*var));
}

static int tdx_get_capabilities(struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx_capabilities __user *user_caps;
	const struct tdsysinfo_struct *tdsysinfo;
	struct kvm_tdx_capabilities *caps = NULL;
	int ret;

	BUILD_BUG_ON(sizeof(struct kvm_tdx_cpuid_config) !=
		     sizeof(struct tdx_cpuid_config));

	if (cmd->flags)
		return -EINVAL;

	tdsysinfo = tdx_get_sysinfo();
	if (!tdsysinfo)
		return -EOPNOTSUPP;

	caps = kmalloc(sizeof(*caps), GFP_KERNEL);
	if (!caps)
		return -ENOMEM;

	user_caps = (void __user *)cmd->data;
	if (copy_from_user(caps, user_caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}

	if (caps->nr_cpuid_configs < tdsysinfo->num_cpuid_config) {
		ret = -E2BIG;
		goto out;
	}

	*caps = (struct kvm_tdx_capabilities) {
		.attrs_fixed0 = tdsysinfo->attributes_fixed0,
		.attrs_fixed1 = tdsysinfo->attributes_fixed1,
		.xfam_fixed0 = tdsysinfo->xfam_fixed0,
		.xfam_fixed1 = tdsysinfo->xfam_fixed1,
		.supported_gpaw = TDX_CAP_GPAW_48 |
		(kvm_get_shadow_phys_bits() >= 52 &&
		 cpu_has_vmx_ept_5levels()) ? TDX_CAP_GPAW_52 : 0,
		.nr_cpuid_configs = tdsysinfo->num_cpuid_config,
		.padding = 0,
	};

	if (copy_to_user(user_caps, caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}
	if (copy_to_user(user_caps->cpuid_configs, &tdsysinfo->cpuid_configs,
			 tdsysinfo->num_cpuid_config *
			 sizeof(struct tdx_cpuid_config))) {
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

static void setup_tdparams_cpuids(struct kvm *kvm,
				  const struct tdsysinfo_struct *tdsysinfo,
				  struct kvm_cpuid2 *cpuid,
				  struct td_params *td_params)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int i;

	/*
	 * td_params.cpuid_values: The number and the order of cpuid_value must
	 * be same to the one of struct tdsysinfo.{num_cpuid_config, cpuid_configs}
	 * It's assumed that td_params was zeroed.
	 */
	kvm_tdx->cpuid_nent = 0;
	for (i = 0; i < tdsysinfo->num_cpuid_config; i++) {
		const struct tdx_cpuid_config *config = &tdsysinfo->cpuid_configs[i];
		/* TDX_CPUID_NO_SUBLEAF in TDX CPUID_CONFIG means index = 0. */
		u32 index = config->sub_leaf == TDX_CPUID_NO_SUBLEAF ? 0 : config->sub_leaf;
		const struct kvm_cpuid_entry2 *entry =
			kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent,
					      config->leaf, index);
		struct tdx_cpuid_value *value = &td_params->cpuid_values[i];

		if (!entry)
			continue;

		/*
		 * tdsysinfo.cpuid_configs[].{eax, ebx, ecx, edx}
		 * bit 1 means it can be configured to zero or one.
		 * bit 0 means it must be zero.
		 * Mask out non-configurable bits.
		 */
		value->eax = entry->eax & config->eax;
		value->ebx = entry->ebx & config->ebx;
		value->ecx = entry->ecx & config->ecx;
		value->edx = entry->edx & config->edx;

		/* Remember the setting to check for KVM_SET_CPUID2. */
		kvm_tdx->cpuid[kvm_tdx->cpuid_nent] = *entry;
		kvm_tdx->cpuid_nent++;
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

	/* PT can be exposed to TD guest regardless of KVM's XSS support */
	guest_supported_xss &=
		(kvm_caps.supported_xss | XFEATURE_MASK_PT | TDX_TD_XFAM_CET);

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
	const struct tdsysinfo_struct *tdsysinfo;
	int ret;

	tdsysinfo = tdx_get_sysinfo();
	if (!tdsysinfo)
		return -EOPNOTSUPP;
	if (kvm->created_vcpus)
		return -EBUSY;

	if (td_params->attributes & TDX_TD_ATTRIBUTE_PERFMON) {
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
	td_params->tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(kvm->arch.default_tsc_khz);

	ret = setup_tdparams_eptp_controls(cpuid, td_params);
	if (ret)
		return ret;
	setup_tdparams_cpuids(kvm, tdsysinfo, cpuid, td_params);
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
	struct tdx_module_args out;
	cpumask_var_t packages;
	unsigned long *tdcs_pa = NULL;
	unsigned long tdr_pa = 0;
	unsigned long va;
	int ret, i;
	u64 err;

	*seamcall_err = 0;
	ret = tdx_guest_keyid_alloc();
	if (ret < 0)
		return ret;
	kvm_tdx->hkid = ret;
	kvm_tdx->misc_cg = get_current_misc_cg();
	ret = misc_cg_try_charge(MISC_CG_RES_TDX, kvm_tdx->misc_cg, 1);
	if (ret)
		goto free_hkid;

	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		goto free_hkid;
	tdr_pa = __pa(va);

	tdcs_pa = kcalloc(tdx_info.nr_tdcs_pages, sizeof(*kvm_tdx->tdcs_pa),
			  GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!tdcs_pa)
		goto free_tdr;
	for (i = 0; i < tdx_info.nr_tdcs_pages; i++) {
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
	err = tdh_mng_create(tdr_pa, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (err == TDX_RND_NO_ENTROPY) {
		ret = -EAGAIN;
		goto free_packages;
	}
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_CREATE, err, NULL);
		ret = -EIO;
		goto free_packages;
	}
	kvm_tdx->tdr_pa = tdr_pa;
	tdx_account_ctl_page(kvm);

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
				      &kvm_tdx->tdr_pa, true);
		mutex_unlock(&tdx_mng_key_config_lock[pkg]);
		if (ret)
			break;
	}
	if (!ret)
		atomic_inc(&nr_configured_hkid);
	cpus_read_unlock();
	free_cpumask_var(packages);
	if (ret) {
		i = 0;
		goto teardown;
	}

	kvm_tdx->tdcs_pa = tdcs_pa;
	for (i = 0; i < tdx_info.nr_tdcs_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx->tdr_pa, tdcs_pa[i]);
		if (err == TDX_RND_NO_ENTROPY) {
			/* Here it's hard to allow userspace to retry. */
			ret = -EBUSY;
			goto teardown;
		}
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err, NULL);
			ret = -EIO;
			goto teardown;
		}
		tdx_account_ctl_page(kvm);
	}

	err = tdh_mng_init(kvm_tdx->tdr_pa, __pa(td_params), &out);
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
		pr_tdx_error(TDH_MNG_INIT, err, &out);
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
	for (; i < tdx_info.nr_tdcs_pages; i++) {
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
	for (i = 0; i < tdx_info.nr_tdcs_pages; i++) {
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

	WARN_ON_ONCE(kvm_tdx->cpuid);
	kvm_tdx->cpuid = kzalloc(flex_array_size(init_vm, cpuid.entries, KVM_MAX_CPUID_ENTRIES),
				 GFP_KERNEL);
	if (!kvm_tdx->cpuid)
		return -ENOMEM;

	init_vm = kzalloc(struct_size(init_vm, cpuid.entries, KVM_MAX_CPUID_ENTRIES),
			  GFP_KERNEL);
	if (!init_vm) {
		ret = -ENOMEM;
		goto out;
	}
	if (copy_from_user(init_vm, (void __user *)cmd->data, sizeof(*init_vm))) {
		ret = -EFAULT;
		goto out;
	}
	if (init_vm->cpuid.nent > KVM_MAX_CPUID_ENTRIES) {
		ret = -E2BIG;
		goto out;
	}
	if (copy_from_user(init_vm->cpuid.entries,
			   (void __user *)cmd->data + sizeof(*init_vm),
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
		kvm->arch.gfn_shared_mask = gpa_to_gfn(BIT_ULL(51));
	else
		kvm->arch.gfn_shared_mask = gpa_to_gfn(BIT_ULL(47));

out:
	/* kfree() accepts NULL. */
	if (ret) {
		kfree(kvm_tdx->cpuid);
		kvm_tdx->cpuid = NULL;
		kvm_tdx->cpuid_nent = 0;
	}
	kfree(init_vm);
	kfree(td_params);
	return ret;
}

void tdx_flush_tlb(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

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
	while (atomic_read(&kvm_tdx->tdh_mem_track))
		cpu_relax();
}

void tdx_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	/*
	 * flush_tlb_current() is used only the first time for the vcpu to run.
	 * As it isn't performance critical, keep this function simple.
	 */
	tdx_track(to_kvm_tdx(vcpu->kvm));
}

#define TDX_SEPT_PFERR	(PFERR_WRITE_MASK | PFERR_GUEST_ENC_MASK)

static int tdx_init_mem_region(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_mem_region region;
	struct kvm_vcpu *vcpu;
	struct page *page;
	u64 error_code;
	int idx, ret = 0;
	bool added = false;

	/* Once TD is finalized, the initial guest memory is fixed. */
	if (is_td_finalized(kvm_tdx))
		return -EINVAL;

	/* The BSP vCPU must be created before initializing memory regions. */
	if (!atomic_read(&kvm->online_vcpus))
		return -EINVAL;

	if (cmd->flags & ~KVM_TDX_MEASURE_MEMORY_REGION)
		return -EINVAL;

	if (copy_from_user(&region, (void __user *)cmd->data, sizeof(region)))
		return -EFAULT;

	/* Sanity check */
	if (!IS_ALIGNED(region.source_addr, PAGE_SIZE) ||
	    !IS_ALIGNED(region.gpa, PAGE_SIZE) ||
	    !region.nr_pages ||
	    region.gpa + (region.nr_pages << PAGE_SHIFT) <= region.gpa ||
	    !kvm_is_private_gpa(kvm, region.gpa) ||
	    !kvm_is_private_gpa(kvm, region.gpa + (region.nr_pages << PAGE_SHIFT)))
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, 0);
	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;

	vcpu_load(vcpu);
	idx = srcu_read_lock(&kvm->srcu);

	kvm_mmu_reload(vcpu);

	while (region.nr_pages) {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		if (need_resched())
			cond_resched();

		/* Pin the source page. */
		ret = get_user_pages_fast(region.source_addr, 1, 0, &page);
		if (ret < 0)
			break;
		if (ret != 1) {
			ret = -ENOMEM;
			break;
		}

		kvm_tdx->source_pa = pfn_to_hpa(page_to_pfn(page)) |
				     (cmd->flags & KVM_TDX_MEASURE_MEMORY_REGION);

		/* TODO: large page support. */
		error_code = TDX_SEPT_PFERR;
		error_code |= (PG_LEVEL_4K << PFERR_LEVEL_START_BIT) &
			PFERR_LEVEL_MASK;
		ret = kvm_mmu_map_tdp_page(vcpu, region.gpa, error_code,
					   PG_LEVEL_4K);
		put_page(page);
		if (ret)
			break;

		region.source_addr += PAGE_SIZE;
		region.gpa += PAGE_SIZE;
		region.nr_pages--;
		added = true;
	}

	srcu_read_unlock(&kvm->srcu, idx);
	vcpu_put(vcpu);

	mutex_unlock(&vcpu->mutex);

	if (added && region.nr_pages > 0)
		ret = -EAGAIN;
	if (copy_to_user((void __user *)cmd->data, &region, sizeof(region)))
		ret = -EFAULT;

	return ret;
}

static int tdx_td_finalizemr(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;

	if (!is_hkid_assigned(kvm_tdx) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	err = tdh_mr_finalize(kvm_tdx->tdr_pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MR_FINALIZE, err, NULL);
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
	case KVM_TDX_INIT_MEM_REGION:
		r = tdx_init_mem_region(kvm, &tdx_cmd);
		break;
	case KVM_TDX_FINALIZE_VM:
		r = tdx_td_finalizemr(kvm);
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
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long *tdvpx_pa = NULL;
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

	tdvpx_pa = kcalloc(tdx_info.nr_tdvpx_pages, sizeof(*tdx->tdvpx_pa),
			   GFP_KERNEL_ACCOUNT);
	if (!tdvpx_pa) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}
	for (i = 0; i < tdx_info.nr_tdvpx_pages; i++) {
		va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!va) {
			ret = -ENOMEM;
			goto free_tdvpx;
		}
		tdvpx_pa[i] = __pa(va);
	}

	err = tdh_vp_create(kvm_tdx->tdr_pa, tdvpr_pa);
	if (KVM_BUG_ON(err, vcpu->kvm)) {
		ret = -EIO;
		pr_tdx_error(TDH_VP_CREATE, err, NULL);
		goto free_tdvpx;
	}
	tdx->tdvpr_pa = tdvpr_pa;
	tdx_account_ctl_page(vcpu->kvm);

	tdx->tdvpx_pa = tdvpx_pa;
	for (i = 0; i < tdx_info.nr_tdvpx_pages; i++) {
		err = tdh_vp_addcx(tdx->tdvpr_pa, tdvpx_pa[i]);
		if (KVM_BUG_ON(err, vcpu->kvm)) {
			pr_tdx_error(TDH_VP_ADDCX, err, NULL);
			for (; i < tdx_info.nr_tdvpx_pages; i++) {
				free_page((unsigned long)__va(tdvpx_pa[i]));
				tdvpx_pa[i] = 0;
			}
			/* vcpu_free method frees TDVPX and TDR donated to TDX */
			return -EIO;
		}
		tdx_account_ctl_page(vcpu->kvm);
	}

	err = tdh_vp_init(tdx->tdvpr_pa, vcpu_rcx);
	if (KVM_BUG_ON(err, vcpu->kvm)) {
		pr_tdx_error(TDH_VP_INIT, err, NULL);
		return -EIO;
	}

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	return 0;

free_tdvpx:
	for (i = 0; i < tdx_info.nr_tdvpx_pages; i++) {
		if (tdvpx_pa[i])
			free_page((unsigned long)__va(tdvpx_pa[i]));
		tdvpx_pa[i] = 0;
	}
	kfree(tdvpx_pa);
	tdx->tdvpx_pa = NULL;
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

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct msr_data apic_base_msr;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_tdx_cmd cmd;
	int ret;

	if (tdx->initialized)
		return -EINVAL;

	if (!is_hkid_assigned(kvm_tdx) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.error)
		return -EINVAL;

	/* Currently only KVM_TDX_INTI_VCPU is defined for vcpu operation. */
	if (cmd.flags || cmd.id != KVM_TDX_INIT_VCPU)
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

	ret = tdx_td_vcpu_init(vcpu, (u64)cmd.data);
	if (ret)
		return ret;

	td_vmcs_write16(tdx, POSTED_INTR_NV, POSTED_INTR_VECTOR);
	td_vmcs_write64(tdx, POSTED_INTR_DESC_ADDR, __pa(&tdx->pi_desc));
	td_vmcs_setbit32(tdx, PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR);

	if (vcpu->kvm->arch.bus_lock_detection_enabled)
		td_vmcs_setbit32(tdx,
				 SECONDARY_VM_EXEC_CONTROL,
				 SECONDARY_EXEC_BUS_LOCK_DETECTION);

	tdx->initialized = true;
	return 0;
}

static int __init tdx_module_setup(void)
{
	const struct tdsysinfo_struct *tdsysinfo;
	int ret = 0;

	BUILD_BUG_ON(sizeof(*tdsysinfo) > TDSYSINFO_STRUCT_SIZE);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

	ret = tdx_enable();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		return ret;
	}

	tdsysinfo = tdx_get_sysinfo();
	WARN_ON(tdsysinfo->num_cpuid_config > TDX_MAX_NR_CPUID_CONFIGS);
	tdx_info = (struct tdx_info) {
		.nr_tdcs_pages = tdsysinfo->tdcs_base_size / PAGE_SIZE,
		/*
		 * TDVPS = TDVPR(4K page) + TDVPX(multiple 4K pages).
		 * -1 for TDVPR.
		 */
		.nr_tdvpx_pages = tdsysinfo->tdvps_base_size / PAGE_SIZE - 1,
	};

	pr_info("nr_tdcs %d nr_tdvpx %d\n",
		tdx_info.nr_tdcs_pages, tdx_info.nr_tdvpx_pages);
	return 0;
}

bool tdx_is_vm_type_supported(unsigned long type)
{
	/* enable_tdx check is done by the caller. */
	return type == KVM_X86_TDX_VM;
}

struct vmx_tdx_enabled {
	cpumask_var_t vmx_enabled;
	atomic_t err;
};

static void __init vmx_tdx_on(void *_vmx_tdx)
{
	struct vmx_tdx_enabled *vmx_tdx = _vmx_tdx;
	int r;

	r = vmx_hardware_enable();
	if (!r) {
		cpumask_set_cpu(smp_processor_id(), vmx_tdx->vmx_enabled);
		r = tdx_cpu_enable();
	}
	if (r)
		atomic_set(&vmx_tdx->err, r);
}

static void __init vmx_off(void *_vmx_enabled)
{
	cpumask_var_t *vmx_enabled = (cpumask_var_t *)_vmx_enabled;

	if (cpumask_test_cpu(smp_processor_id(), *vmx_enabled))
		vmx_hardware_disable();
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	struct vmx_tdx_enabled vmx_tdx = {
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
		 * Here it checks if MSRs (tdx_uret_msrs) can be saved/restored
		 * before returning to user space.
		 *
		 * this_cpu_ptr(user_return_msrs)->registered isn't checked
		 * because the registration is done at vcpu runtime by
		 * kvm_set_user_return_msr().
		 * Here is setting up cpu feature before running vcpu,
		 * registered is already false.
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
	 * TDX supports tdx_num_keyids keys total, the first private key is used
	 * as global encryption key to encrypt TDX module managed global scope.
	 * The left private keys is the available keys for launching guest TDs.
	 * The total number of available keys for TDs is (tdx_num_keyid - 1).
	 */
	if (misc_cg_set_capacity(MISC_CG_RES_TDX, tdx_get_nr_guest_keyids() - 1))
		return -EINVAL;

	max_pkgs = topology_max_packages();
	tdx_mng_key_config_lock = kcalloc(max_pkgs, sizeof(*tdx_mng_key_config_lock),
				   GFP_KERNEL);
	if (!tdx_mng_key_config_lock) {
		r = -ENOMEM;
		goto out;
	}
	for (i = 0; i < max_pkgs; i++)
		mutex_init(&tdx_mng_key_config_lock[i]);

	if (!zalloc_cpumask_var(&vmx_tdx.vmx_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	/*
	 * REVERTME: The current TDX module requires TDH_SYS_LP_INIT for all
	 * LPs to initialize.  It requires all present LPs to be online.
	 * Once the TDX module is updated to allow offline LPs, remove this
	 * warning.
	 */
	if (!cpumask_equal(cpu_online_mask, cpu_present_mask))
		pr_warn("The old TDX module requires all present CPUs to be online to initialize.\n");
	on_each_cpu(vmx_tdx_on, &vmx_tdx, true);	/* TDX requires vmxon. */
	r = atomic_read(&vmx_tdx.err);
	if (!r)
		r = tdx_module_setup();
	else
		r = -EIO;
	on_each_cpu(vmx_off, &vmx_tdx.vmx_enabled, true);
	cpus_read_unlock();
	free_cpumask_var(vmx_tdx.vmx_enabled);
	if (r)
		goto out;

	x86_ops->link_private_spt = tdx_sept_link_private_spt;
	x86_ops->free_private_spt = tdx_sept_free_private_spt;
	x86_ops->split_private_spt = tdx_sept_split_private_spt;
	x86_ops->merge_private_spt = tdx_sept_merge_private_spt;
	x86_ops->set_private_spte = tdx_sept_set_private_spte;
	x86_ops->remove_private_spte = tdx_sept_remove_private_spte;
	x86_ops->zap_private_spte = tdx_sept_zap_private_spte;
	x86_ops->unzap_private_spte = tdx_sept_unzap_private_spte;

	return 0;

out:
	/* kfree() accepts NULL. */
	kfree(tdx_mng_key_config_lock);
	tdx_mng_key_config_lock = NULL;
	misc_cg_set_capacity(MISC_CG_RES_TDX, 0);
	return r;
}

void tdx_hardware_unsetup(void)
{
	/* kfree accepts NULL. */
	kfree(tdx_mng_key_config_lock);
	misc_cg_set_capacity(MISC_CG_RES_TDX, 0);
}

int tdx_offline_cpu(void)
{
	int curr_cpu = smp_processor_id();
	cpumask_var_t packages;
	int ret = 0;
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
	if (!zalloc_cpumask_var(&packages, GFP_KERNEL))
		return -ENOMEM;
	for_each_online_cpu(i) {
		if (i != curr_cpu)
			cpumask_set_cpu(topology_physical_package_id(i), packages);
	}
	/* Check if this cpu is the last online cpu of this package. */
	if (!cpumask_test_cpu(topology_physical_package_id(curr_cpu), packages))
		ret = -EBUSY;
	free_cpumask_var(packages);
	if (ret)
		/*
		 * Because it's hard for human operator to understand the
		 * reason, warn it.
		 */
#define MSG_ALLPKG_ONLINE \
	"TDX requires all packages to have an online CPU. Delete all TDs in order to offline all CPUs of a package.\n"
		pr_warn_ratelimited(MSG_ALLPKG_ONLINE);
	return ret;
}

static __always_inline bool tdx_guest(struct kvm *kvm)
{
	struct kvm_tdx *tdx_kvm = to_kvm_tdx(kvm);

	return tdx_kvm->finalized;
}

#define for_each_memslot_pair(memslots_1, memslots_2, memslot_iter_1, \
			      memslot_iter_2)                         \
	for (memslot_iter_1 = rb_first(&memslots_1->gfn_tree),        \
	    memslot_iter_2 = rb_first(&memslots_2->gfn_tree);         \
	     memslot_iter_1 && memslot_iter_2;                        \
	     memslot_iter_1 = rb_next(memslot_iter_1),                \
	    memslot_iter_2 = rb_next(memslot_iter_2))

static int tdx_migrate_from(struct kvm *dst, struct kvm *src)
{
	struct rb_node *src_memslot_iter, *dst_memslot_iter;
	struct vcpu_tdx *dst_tdx_vcpu, *src_tdx_vcpu;
	struct kvm_memslots *src_slots, *dst_slots;
	struct kvm_vcpu *dst_vcpu, *src_vcpu;
	struct kvm_tdx *src_tdx, *dst_tdx;
	unsigned long i, j;
	int ret;

	src_tdx = to_kvm_tdx(src);
	dst_tdx = to_kvm_tdx(dst);

	src_slots = __kvm_memslots(src, 0);
	dst_slots = __kvm_memslots(dst, 0);

	ret = -EINVAL;

	if (!src_tdx->finalized) {
		pr_warn("Cannot migrate from a non finalized VM\n");
		goto abort;
	}

	// Traverse both memslots in gfn order and compare them
	for_each_memslot_pair(src_slots, dst_slots, src_memslot_iter, dst_memslot_iter) {
		struct kvm_memory_slot *src_slot, *dst_slot;

		src_slot =
			container_of(src_memslot_iter, struct kvm_memory_slot,
				     gfn_node[src_slots->node_idx]);
		dst_slot =
			container_of(src_memslot_iter, struct kvm_memory_slot,
				     gfn_node[dst_slots->node_idx]);

		if (src_slot->base_gfn != dst_slot->base_gfn ||
		    src_slot->npages != dst_slot->npages) {
			pr_warn("Cannot migrate between VMs with different memory slots configurations\n");
			goto abort;
		}

		if (src_slot->flags != dst_slot->flags) {
			pr_warn("Cannot migrate between VMs with different memory slots configurations\n");
			goto abort;
		}

		if (src_slot->flags & KVM_MEM_PRIVATE) {
			rcu_read_lock();
			if (src_slot->gmem.file->f_inode->i_ino !=
			    dst_slot->gmem.file->f_inode->i_ino) {
				pr_warn("Private memslots points to different restricted files\n");
				rcu_read_unlock();
				goto abort;
			}

			if (src_slot->gmem.pgoff != dst_slot->gmem.pgoff) {
				pr_warn("Private memslots points to the restricted file at different offsets\n");
				rcu_read_unlock();
				goto abort;
			}
			rcu_read_unlock();
		}
	}

	if (src_memslot_iter || dst_memslot_iter) {
		pr_warn("Cannot migrate between VMs with different memory slots configurations\n");
		goto abort;
	}

	dst_tdx->hkid = src_tdx->hkid;
	dst_tdx->tdr_pa = src_tdx->tdr_pa;

	dst_tdx->tdcs_pa = kcalloc(tdx_info.nr_tdcs_pages, sizeof(*dst_tdx->tdcs_pa),
			  GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!dst_tdx->tdcs_pa) {
		ret = -ENOMEM;
		goto late_abort;
	}
	memcpy(dst_tdx->tdcs_pa, src_tdx->tdcs_pa,
	       tdx_info.nr_tdcs_pages * sizeof(*dst_tdx->tdcs_pa));

	dst_tdx->tsc_offset = src_tdx->tsc_offset;
	dst_tdx->attributes = src_tdx->attributes;
	dst_tdx->xfam = src_tdx->xfam;
	dst_tdx->kvm.arch.gfn_shared_mask = src_tdx->kvm.arch.gfn_shared_mask;

	kvm_for_each_vcpu(i, src_vcpu, src)
		tdx_flush_vp_on_cpu(src_vcpu);

	/* Copy per-vCPU state */
	kvm_for_each_vcpu(i, src_vcpu, src) {
		src_tdx_vcpu = to_tdx(src_vcpu);
		dst_vcpu = kvm_get_vcpu(dst, i);
		dst_tdx_vcpu = to_tdx(dst_vcpu);

		vcpu_load(dst_vcpu);

		memcpy(dst_vcpu->arch.regs, src_vcpu->arch.regs,
		       NR_VCPU_REGS * sizeof(src_vcpu->arch.regs[0]));
		dst_vcpu->arch.regs_avail = src_vcpu->arch.regs_avail;
		dst_vcpu->arch.regs_dirty = src_vcpu->arch.regs_dirty;

		dst_vcpu->arch.tsc_offset = dst_tdx->tsc_offset;

		dst_tdx_vcpu->interrupt_disabled_hlt = src_tdx_vcpu->interrupt_disabled_hlt;
		dst_tdx_vcpu->buggy_hlt_workaround = src_tdx_vcpu->buggy_hlt_workaround;

		dst_tdx_vcpu->tdvpr_pa = src_tdx_vcpu->tdvpr_pa;
		dst_tdx_vcpu->tdvpx_pa = kcalloc(tdx_info.nr_tdvpx_pages,
						 sizeof(*dst_tdx_vcpu->tdvpx_pa),
						 GFP_KERNEL_ACCOUNT);
		if (!dst_tdx_vcpu->tdvpx_pa) {
			ret = -ENOMEM;
			vcpu_put(dst_vcpu);
			goto late_abort;
		}
		memcpy(dst_tdx_vcpu->tdvpx_pa, src_tdx_vcpu->tdvpx_pa,
		       tdx_info.nr_tdvpx_pages * sizeof(*dst_tdx_vcpu->tdvpx_pa));

		td_vmcs_write64(dst_tdx_vcpu, POSTED_INTR_DESC_ADDR, __pa(&dst_tdx_vcpu->pi_desc));

		/* Copy private EPT tables */
		if (kvm_mmu_move_private_pages_from(dst_vcpu, src_vcpu)) {
			ret = -EINVAL;
			vcpu_put(dst_vcpu);
			goto late_abort;
		}

		for (j = 0; j < tdx_info.nr_tdvpx_pages; j++)
			src_tdx_vcpu->tdvpx_pa[j] = 0;

		src_tdx_vcpu->tdvpr_pa = 0;

		vcpu_put(dst_vcpu);
	}

	for_each_memslot_pair(src_slots, dst_slots, src_memslot_iter,
			      dst_memslot_iter) {
		struct kvm_memory_slot *src_slot, *dst_slot;

		src_slot = container_of(src_memslot_iter,
					struct kvm_memory_slot,
					gfn_node[src_slots->node_idx]);
		dst_slot = container_of(src_memslot_iter,
					struct kvm_memory_slot,
					gfn_node[dst_slots->node_idx]);

		for (i = 1; i < KVM_NR_PAGE_SIZES; ++i) {
			unsigned long ugfn;
			int level = i + 1;

			/*
			 * If the gfn and userspace address are not aligned wrt each other, then
			 * large page support should already be disabled at this level.
			 */
			ugfn = dst_slot->userspace_addr >> PAGE_SHIFT;
			if ((dst_slot->base_gfn ^ ugfn) & (KVM_PAGES_PER_HPAGE(level) - 1))
				continue;

			dst_slot->arch.lpage_info[i - 1] =
				src_slot->arch.lpage_info[i - 1];
			src_slot->arch.lpage_info[i - 1] = NULL;
		}
	}

	dst->mem_attr_array.xa_head = src->mem_attr_array.xa_head;
	src->mem_attr_array.xa_head = NULL;

	dst_tdx->finalized = true;

	/* Clear source VM to avoid freeing the hkid and pages on VM put */
	src_tdx->hkid = -1;
	src_tdx->tdr_pa = 0;
	for (i = 0; i < tdx_info.nr_tdcs_pages; i++)
		src_tdx->tdcs_pa[i] = 0;

	return 0;

late_abort:
	/* If we aborted after the state transfer already started, the src VM
	 * is no longer valid.
	 */
	kvm_vm_dead(src);

abort:
	dst_tdx->hkid = -1;
	dst_tdx->tdr_pa = 0;

	return ret;
}

int tdx_vm_move_enc_context_from(struct kvm *kvm, unsigned int source_fd)
{
	struct kvm_tdx *dst_tdx = to_kvm_tdx(kvm);
	struct file *src_kvm_file;
	struct kvm_tdx *src_tdx;
	struct kvm *src_kvm;
	int ret;

	src_kvm_file = fget(source_fd);
	if (!file_is_kvm(src_kvm_file)) {
		ret = -EBADF;
		goto out_fput;
	}
	src_kvm = src_kvm_file->private_data;
	src_tdx = to_kvm_tdx(src_kvm);

	ret = pre_move_enc_context_from(kvm, src_kvm,
					&dst_tdx->migration_in_progress,
					&src_tdx->migration_in_progress);
	if (ret)
		goto out_fput;

	if (tdx_guest(kvm) || !tdx_guest(src_kvm)) {
		ret = -EINVAL;
		goto out_post;
	}

	ret = tdx_migrate_from(kvm, src_kvm);
	if (ret)
		goto out_post;

	kvm_vm_dead(src_kvm);
	ret = 0;

out_post:
	post_move_enc_context_from(kvm, src_kvm,
				 &dst_tdx->migration_in_progress,
				 &src_tdx->migration_in_progress);
out_fput:
	if (src_kvm_file)
		fput(src_kvm_file);
	return ret;
}
