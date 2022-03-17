// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/kvm_host.h>
#include <linux/jump_label.h>
#include <linux/trace_events.h>
#include <linux/mmu_context.h>
#include <linux/pagemap.h>
#include <linux/perf_event.h>
#include <linux/debugfs.h>

#include <asm/fpu/xcr.h>
#include <asm/virtext.h>

#include "tdx_errno.h"
#include "tdx_ops.h"
#include "x86_ops.h"
#include "common.h"
#include "cpuid.h"
#include "lapic.h"
#include "tdx.h"

#include <trace/events/kvm.h>
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

/*
 * workaround to compile.
 * TODO: once the TDX module initiation code in x86 host is merged, remove this.
 * The function returns struct tdsysinfo_struct from TDX module provides.  It
 * provides the system wide information about the TDX module.
 */
#if __has_include(<asm/tdx_host.h>)
#include <asm/tdx_host.h>
#else
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	return NULL;
}
#endif

static int trace_seamcalls __read_mostly = DEBUGCONFIG_TRACE_CUSTOM;
module_param(trace_seamcalls, int, 0444);
static int trace_seamcalls_initialized;

/* Debug configuration SEAMCALLs */
bool tdx_is_debug_seamcall_available __read_mostly;
/* Non-architectural configuration SEAMCALLs */
bool tdx_is_nonarch_seamcall_available __read_mostly;

/* KeyID range reserved to TDX by BIOS */
static u32 tdx_keyids_start __read_mostly;
static u32 tdx_nr_keyids __read_mostly;
static u32 tdx_seam_keyid __read_mostly;

static void __init tdx_keyids_init(void)
{
	u32 nr_mktme_ids;

	rdmsr(MSR_IA32_MKTME_KEYID_PART, nr_mktme_ids, tdx_nr_keyids);

	/* KeyID 0 is reserved, i.e. KeyIDs are 1-based. */
	tdx_keyids_start = nr_mktme_ids + 1;
	tdx_seam_keyid = tdx_keyids_start;
}

/* TDX KeyID pool */
static DEFINE_IDA(tdx_keyid_pool);

static int tdx_keyid_alloc(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_TDX))
		return -EINVAL;

	if (WARN_ON_ONCE(!tdx_keyids_start || !tdx_nr_keyids))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_keyid_pool, tdx_keyids_start + 1,
			       tdx_keyids_start + tdx_nr_keyids - 1,
			       GFP_KERNEL);
}

static void tdx_keyid_free(int keyid)
{
	if (!keyid || keyid < 0)
		return;

	ida_free(&tdx_keyid_pool, keyid);
}

/* Capabilities of KVM + TDX-SEAM. */
struct tdx_capabilities tdx_caps;

static DEFINE_MUTEX(tdx_lock);
static struct mutex *tdx_mng_key_config_lock;

/*
 * A per-CPU list of TD vCPUs associated with a given CPU.  Used when a CPU
 * is brought down to invoke TDH_VP_FLUSH on the approapriate TD vCPUS.
 * Protected by interrupt mask.  This list is manipulated in process context
 * of vcpu and IPI callback.  See tdx_flush_vp_on_cpu().
 */
static DEFINE_PER_CPU(struct list_head, associated_tdvcpus);

static u64 hkid_mask __ro_after_init;
static u8 hkid_start_pos __ro_after_init;

struct tdx_uret_msr {
	u32 msr;
	unsigned int slot;
	u64 defval;
};

static struct tdx_uret_msr tdx_uret_msrs[] = {
	{.msr = MSR_SYSCALL_MASK,},
	{.msr = MSR_STAR,},
	{.msr = MSR_LSTAR,},
	{.msr = MSR_TSC_AUX,},
};

static enum {
	TD_PROFILE_NONE = 0,
	TD_PROFILE_ENABLE,
	TD_PROFILE_DISABLE,
} td_profile_state;

/*
 * Currently, host is allowed to get TD's profile only if this TD is debuggable
 * and cannot use PMU.
 */
static inline bool td_profile_allowed(struct kvm_tdx *kvm_tdx)
{
	u64 attributes = kvm_tdx->attributes;

	if ((td_profile_state == TD_PROFILE_ENABLE) &&
	    (attributes & TDX_TD_ATTRIBUTE_DEBUG) &&
	    !(attributes & TDX_TD_ATTRIBUTE_PERFMON))
		return true;

	return false;
}

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	pa &= ~hkid_mask;
	pa |= (u64)hkid << hkid_start_pos;

	return pa;
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

#define BUILD_TDVMCALL_ACCESSORS(param, gpr)				    \
static __always_inline							    \
unsigned long tdvmcall_##param##_read(struct kvm_vcpu *vcpu)		    \
{									    \
	return kvm_##gpr##_read(vcpu);					    \
}									    \
static __always_inline void tdvmcall_##param##_write(struct kvm_vcpu *vcpu, \
						     unsigned long val)	    \
{									    \
	kvm_##gpr##_write(vcpu, val);					    \
}
BUILD_TDVMCALL_ACCESSORS(p1, r12);
BUILD_TDVMCALL_ACCESSORS(p2, r13);
BUILD_TDVMCALL_ACCESSORS(p3, r14);
BUILD_TDVMCALL_ACCESSORS(p4, r15);

#define TDX_VMCALL_REG_MASK_RBX	BIT_ULL(2)
#define TDX_VMCALL_REG_MASK_RDX	BIT_ULL(3)
#define TDX_VMCALL_REG_MASK_RBP	BIT_ULL(5)
#define TDX_VMCALL_REG_MASK_RSI	BIT_ULL(6)
#define TDX_VMCALL_REG_MASK_RDI	BIT_ULL(7)
#define TDX_VMCALL_REG_MASK_R8	BIT_ULL(8)
#define TDX_VMCALL_REG_MASK_R9	BIT_ULL(9)
#define TDX_VMCALL_REG_MASK_R12	BIT_ULL(12)
#define TDX_VMCALL_REG_MASK_R13	BIT_ULL(13)
#define TDX_VMCALL_REG_MASK_R14	BIT_ULL(14)
#define TDX_VMCALL_REG_MASK_R15	BIT_ULL(15)

static __always_inline unsigned long tdvmcall_exit_type(struct kvm_vcpu *vcpu)
{
	return kvm_r10_read(vcpu);
}
static __always_inline unsigned long tdvmcall_exit_reason(struct kvm_vcpu *vcpu)
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
	return tdx->tdvpr.added;
}

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr.added;
}

static inline bool is_hkid_assigned(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->hkid >= 0;
}

static inline bool is_td_initialized(struct kvm *kvm)
{
	return !!kvm->max_vcpus;
}

static inline bool is_td_finalized(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->finalized;
}

static void tdx_clear_page(unsigned long page, int size)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	unsigned long i;

	WARN_ON_ONCE(size % 64);

	/* Zeroing the page is only necessary for systems with MKTME-i. */
	if (!static_cpu_has(X86_FEATURE_MOVDIR64B))
		return;

	for (i = 0; i < size; i += 64)
		/* MOVDIR64B [rdx], es:rdi */
		asm (".byte 0x66, 0x0f, 0x38, 0xf8, 0x3a"
		     : : "d" (zero_page), "D" (page + i) : "memory");
}

static int __tdx_reclaim_page(unsigned long va, hpa_t pa, enum pg_level level,
			      bool do_wb, u16 hkid)
{
	struct tdx_ex_ret ex_ret;
	u64 err;

	err = tdh_phymem_page_reclaim(pa, &ex_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_RECLAIM, err, &ex_ret);
		return -EIO;
	}

	WARN_ON_ONCE(ex_ret.phymem_page_md.page_size !=
		     pg_level_to_tdx_sept_level(level));

	/* only TDR page gets into this path */
	if (do_wb &&
	    level == PG_LEVEL_4K) {
		err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(pa, hkid));
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			return -EIO;
		}
	}

	tdx_clear_page(va, KVM_HPAGE_SIZE(level));
	return 0;
}

/*
 * It's for the page already writeback'd. Thus cannot be used for TDR.
 * @level is one of enum pg_level
 */
static int tdx_reclaim_page(unsigned long va, hpa_t pa, enum pg_level level)
{
	return __tdx_reclaim_page(va, pa, level, false, 0);
}

static int tdx_alloc_td_page(struct tdx_td_page *page)
{
	page->va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!page->va)
		return -ENOMEM;

	page->pa = __pa(page->va);
	return 0;
}

static void tdx_add_td_page(struct tdx_td_page *page)
{
	WARN_ON_ONCE(page->added);
	page->added = true;
}

static void tdx_reclaim_td_page(struct tdx_td_page *page)
{
	if (page->added) {
		if (tdx_reclaim_page(page->va, page->pa, PG_LEVEL_4K))
			return;

		page->added = false;
	}
	free_page(page->va);
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

static void tdx_flush_vp(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	u64 err;

	/* Task migration can race with CPU offlining. */
	if (vcpu->cpu != raw_smp_processor_id())
		return;

	/*
	 * No need to do TDH_VP_FLUSH if the vCPU hasn't been initialized.  The
	 * list tracking still needs to be updated so that it's correct if/when
	 * the vCPU does get initialized.
	 */
	if (is_td_vcpu_created(to_tdx(vcpu))) {
		err = tdh_vp_flush(to_tdx(vcpu)->tdvpr.pa);
		if (unlikely(err && err != TDX_VCPU_NOT_ASSOCIATED)) {
			if (WARN_ON_ONCE(err))
				pr_tdx_error(TDH_VP_FLUSH, err, NULL);
		}
	}

	tdx_disassociate_vp(vcpu);
}

static void tdx_flush_vp_on_cpu(struct kvm_vcpu *vcpu)
{
	if (unlikely(vcpu->cpu == -1))
		return;

	smp_call_function_single(vcpu->cpu, tdx_flush_vp, vcpu, 1);
}

static int tdx_do_tdh_phymem_cache_wb(void *param)
{
	u64 err = 0;

	mutex_lock(&tdx_lock);
	do {
		err = tdh_phymem_cache_wb(!!err);
	} while (err == TDX_INTERRUPTED_RESUMABLE);
	mutex_unlock(&tdx_lock);

	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_CACHE_WB, err, NULL);
		return -EIO;
	}

	return 0;
}

void tdx_vm_teardown(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_vcpu *vcpu;
	u64 err;
	int ret;
	int i;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	if (!is_td_created(kvm_tdx))
		goto free_hkid;

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_reclaimid(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_RECLAIMID, err, NULL);
		return;
	}

	kvm_for_each_vcpu(i, vcpu, (&kvm_tdx->kvm))
		tdx_flush_vp_on_cpu(vcpu);

	mutex_lock(&tdx_lock);
	err = tdh_mng_vpflushdone(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_VPFLUSHDONE, err, NULL);
		return;
	}

	/*
	 * TODO: optimize to invoke the callback only once per CPU package
	 * instead of all CPUS because TDH.PHYMEM.CACHE.WB is per CPU package
	 * operation.
	 *
	 * Invoke the callback one-by-one to avoid contention.
	 * TDH.PHYMEM.CACHE.WB competes for key ownership table lock.
	 */
	ret = 0;
	for_each_online_cpu(i) {
		ret = smp_call_on_cpu(i, tdx_do_tdh_phymem_cache_wb, NULL, 1);
		if (ret)
			break;
	}
	if (unlikely(ret))
		return;

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_freeid(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err, NULL);
		return;
	}

free_hkid:
	tdx_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
}

void tdx_vm_destroy(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int i;

	/* Can't reclaim or free TD pages if teardown failed. */
	if (is_hkid_assigned(kvm_tdx))
		return;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++)
		tdx_reclaim_td_page(&kvm_tdx->tdcs[i]);

	if (kvm_tdx->tdr.added &&
	    __tdx_reclaim_page(kvm_tdx->tdr.va, kvm_tdx->tdr.pa, PG_LEVEL_4K,
			       true, tdx_seam_keyid))
		return;

	free_page(kvm_tdx->tdr.va);
}

static int tdx_do_tdh_mng_key_config(void *param)
{
	hpa_t *tdr_p = param;
	int cpu, cur_pkg;
	u64 err;

	cpu = raw_smp_processor_id();
	cur_pkg = topology_physical_package_id(cpu);

	mutex_lock(&tdx_mng_key_config_lock[cur_pkg]);
	do {
		err = tdh_mng_key_config(*tdr_p);
	} while (err == TDX_KEY_GENERATION_FAILED);
	mutex_unlock(&tdx_mng_key_config_lock[cur_pkg]);

	/*
	 * WORKAROUND for the TDX module.  When the key is configured on all CPU
	 * packages, it returns TDX_LIFECYCLE_STATE_INCORRECT (or
	 * TDX_KEY_STATE_INCORRECT depending on the version of the TDX module)
	 * instead of TDX_KEY_CONFIGURED.  Remove this once it's fixed.
	 */
	if (err == TDX_LIFECYCLE_STATE_INCORRECT ||
		err == TDX_KEY_STATE_INCORRECT)
		err = TDX_KEY_CONFIGURED;

	/*
	 * TDH.MNG.KEY.CONFIG is per CPU package operation.  Other CPU on the
	 * same package did it for us.
	 */
	if (err == TDX_KEY_CONFIGURED)
		err = 0;

	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_CONFIG, err, NULL);
		return -EIO;
	}

	return 0;
}

int tdx_vm_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int ret, i;
	u64 err;

	kvm->dirty_log_unsupported = true;
	kvm->readonly_mem_unsupported = true;

	kvm->arch.tsc_immutable = true;
	kvm->arch.eoi_intercept_unsupported = true;
	kvm->arch.smm_unsupported = true;
	kvm->arch.init_sipi_unsupported = true;
	kvm->arch.irq_injection_disallowed = true;
	kvm->arch.mce_injection_disallowed = true;
	/*
	 * To generate EPT violation to inject #VE instead of EPT MISCONFIG,
	 * set RWX=0.
	 */
	kvm_mmu_set_mmio_spte_mask(kvm, 0, VMX_EPT_RWX_MASK, 0);

	/*
	 * So far legacy MMU supports 4K and 2M pages, but TDP MMU doesn't
	 * support large page at all.
	 * TODO: 2MB support for TDP MMU.
	 */
	if (!kvm->arch.tdp_mmu_enabled)
		kvm->arch.tdp_max_page_level = PG_LEVEL_2M;
	else
		kvm->arch.tdp_max_page_level = PG_LEVEL_4K;

	/* vCPUs can't be created until after KVM_TDX_INIT_VM. */
	kvm->max_vcpus = 0;

	kvm_tdx->hkid = tdx_keyid_alloc();
	if (kvm_tdx->hkid < 0)
		return -EBUSY;
	if (WARN_ON_ONCE(kvm_tdx->hkid >> 16)) {
		ret = -EIO;
		goto free_hkid;
	}

	ret = tdx_alloc_td_page(&kvm_tdx->tdr);
	if (ret)
		goto free_hkid;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		ret = tdx_alloc_td_page(&kvm_tdx->tdcs[i]);
		if (ret)
			goto free_tdcs;
	}

	ret = -EIO;
	mutex_lock(&tdx_lock);
	err = tdh_mng_create(kvm_tdx->tdr.pa, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_CREATE, err, NULL);
		goto free_tdcs;
	}
	tdx_add_td_page(&kvm_tdx->tdr);

	/*
	 * TODO: optimize to invoke the callback only once per CPU package
	 * instead of all CPUS because TDH.MNG.KEY.CONFIG is per CPU package
	 * operation.
	 *
	 * Invoke callback one-by-one to avoid contention because
	 * TDH.MNG.KEY.CONFIG competes for TDR lock.
	 */
	for_each_online_cpu(i) {
		ret = smp_call_on_cpu(i, tdx_do_tdh_mng_key_config,
				&kvm_tdx->tdr.pa, 1);
		if (ret)
			break;
	}
	if (ret)
		goto teardown;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx->tdr.pa, kvm_tdx->tdcs[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err, NULL);
			goto teardown;
		}
		tdx_add_td_page(&kvm_tdx->tdcs[i]);
	}

	spin_lock_init(&kvm_tdx->seamcall_lock);

	/*
	 * Note, TDH_MNG_INIT cannot be invoked here.  TDH_MNG_INIT requires a dedicated
	 * ioctl() to define the configure CPUID values for the TD.
	 */
	return 0;

	/*
	 * The sequence for freeing resources from a partially initialized TD
	 * varies based on where in the initialization flow failure occurred.
	 * Simply use the full teardown and destroy, which naturally play nice
	 * with partial initialization.
	 */
teardown:
	tdx_vm_teardown(kvm);
	tdx_vm_destroy(kvm);
	return ret;

free_tdcs:
	/* @i points at the TDCS page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(kvm_tdx->tdcs[i].va);

	free_page(kvm_tdx->tdr.va);
free_hkid:
	tdx_keyid_free(kvm_tdx->hkid);
	return ret;
}

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int ret, i;

	ret = tdx_alloc_td_page(&tdx->tdvpr);
	if (ret)
		return ret;

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		ret = tdx_alloc_td_page(&tdx->tdvpx[i]);
		if (ret)
			goto free_tdvpx;
	}

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.switch_db_regs = KVM_DEBUGREG_AUTO_SWITCH;
	/*
	 * kvm_arch_vcpu_reset(init_event=false) reads cr0 to reset MMU.
	 * Prevent to read CR0 via SEAMCALL.
	 */
	vcpu->arch.cr0_guest_owned_bits = 0ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;

	vcpu->arch.tsc_offset = to_kvm_tdx(vcpu->kvm)->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG);
	vcpu->arch.root_mmu.no_prefetch = true;

	tdx->pi_desc.nv = POSTED_INTR_VECTOR;
	tdx->pi_desc.sn = 1;
	tdx->host_state_need_save = true;
	tdx->host_state_need_restore = false;

	return 0;

free_tdvpx:
	/* @i points at the TDVPX page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(tdx->tdvpx[i].va);

	free_page(tdx->tdvpr.va);

	return ret;
}

void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (vcpu->cpu != cpu) {
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

	vmx_vcpu_pi_load(vcpu, cpu);
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

	/* Can't reclaim or free pages if teardown failed. */
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm)))
		return;

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++)
		tdx_reclaim_td_page(&tdx->tdvpx[i]);

	tdx_reclaim_td_page(&tdx->tdvpr);

	/*
	 * kvm_free_vcpus()
	 *   -> kvm_unload_vcpu_mmu()
	 *
	 * does vcpu_load() for every vcpu after they already disassociated
	 * from the per cpu list when tdx_vm_teardown(). So we need to
	 * disassociate them again, otherwise the freed vcpu data will be
	 * accessed when do list_{del,add}() on associated_tdvcpus list
	 * later.
	 */
	tdx_flush_vp_on_cpu(vcpu);
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct msr_data apic_base_msr;
	u64 err;
	int i;

	if (WARN_ON(init_event) || !vcpu->arch.apic)
		goto td_bugged;

	if (WARN_ON(is_td_vcpu_created(tdx)))
		goto td_bugged;

	err = tdh_vp_create(kvm_tdx->tdr.pa, tdx->tdvpr.pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_CREATE, err, NULL);
		goto td_bugged;
	}
	tdx_add_td_page(&tdx->tdvpr);

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		err = tdh_vp_addcx(tdx->tdvpr.pa, tdx->tdvpx[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_VP_ADDCX, err, NULL);
			goto td_bugged;
		}
		tdx_add_td_page(&tdx->tdvpx[i]);
	}

	apic_base_msr.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC;
	if (kvm_vcpu_is_reset_bsp(vcpu))
		apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
	apic_base_msr.host_initiated = true;
	if (WARN_ON(kvm_set_apic_base(vcpu, &apic_base_msr)))
		goto td_bugged;

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	vcpu->arch.cr0_guest_owned_bits = -1ul;
	vcpu->arch.regs_dirty = 0;

	return;

td_bugged:
	vcpu->kvm->vm_bugged = true;
}

void tdx_inject_nmi(struct kvm_vcpu *vcpu)
{
	td_management_write8(to_tdx(vcpu), TD_VCPU_PEND_NMI, 1);
}

static void tdx_complete_interrupts(struct kvm_vcpu *vcpu)
{
	/* Avoid costly SEAMCALL if no nmi was injected */
	if (vcpu->arch.nmi_injected)
		vcpu->arch.nmi_injected = td_management_read8(to_tdx(vcpu),
							      TD_VCPU_PEND_NMI);

	if (is_debug_td(vcpu))
		kvm_clear_exception_queue(vcpu);
}

static void tdx_user_return_update_cache(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++)
		kvm_user_return_update_cache(tdx_uret_msrs[i].slot,
					     tdx_uret_msrs[i].defval);
}

static void tdx_restore_host_xsave_state(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	if (static_cpu_has(X86_FEATURE_XSAVE) &&
	    host_xcr0 != (kvm_tdx->xfam & supported_xcr0))
		xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
	if (static_cpu_has(X86_FEATURE_XSAVES) &&
	    /* PT can be exposed to TD guest regardless of KVM's XSS support */
	    host_xss != (kvm_tdx->xfam & (supported_xss | XFEATURE_MASK_PT |
					  TDX_TD_XFAM_CET)))
		wrmsrl(MSR_IA32_XSS, host_xss);
	if (static_cpu_has(X86_FEATURE_PKU) &&
	    (kvm_tdx->xfam & XFEATURE_MASK_PKRU))
		write_pkru(vcpu->arch.host_pkru);
}

static inline void tdx_register_cache_reset(struct kvm_vcpu *vcpu)
{
	vcpu->arch.regs_avail = 0;
	vcpu->arch.regs_dirty = 0;
}

/*
 * Update TD VMCS to enable PMU counters when this TD vCPU is running.
 */
static void tdx_switch_perf_msrs(struct kvm_vcpu *vcpu)
{
	int i, nr_msrs;
	struct perf_guest_switch_msr *msrs;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	msrs = perf_guest_get_msrs(&nr_msrs);
	if (!msrs)
		return;

	for (i = 0; i < nr_msrs; i++) {
		switch (msrs[i].msr) {
		case MSR_CORE_PERF_GLOBAL_CTRL:
			if (tdx->guest_perf_global_ctrl != msrs[i].guest) {
				td_vmcs_write64(tdx,
						GUEST_IA32_PERF_GLOBAL_CTRL,
						msrs[i].guest);
				tdx->guest_perf_global_ctrl = msrs[i].guest;
			}
			break;

		default:
			WARN_ONCE(1, "Cannot switch msrs other than IA32_PERF_GLOBAL_CTRL");
		}
	}
}

u64 __tdx_vcpu_run(hpa_t tdvpr, void *regs, u32 regs_mask);
static void tdx_flush_gprs_dirty(struct kvm_vcpu *vcpu, bool force);

static noinstr void tdx_vcpu_enter_exit(struct kvm_vcpu *vcpu,
					struct vcpu_tdx *tdx)
{
	u64 tsx_ctrl;

	/*
	 * TDH.VP.ENTER has special environment requirements that
	 * RTM_DISABLE(bit 0) and TSX_CPUID_CLEAR(bit 1) of IA32_TSX_CTRL must
	 * be 0 if it's supported.
	 */
	tsx_ctrl = tsx_ctrl_clear();
	kvm_guest_enter_irqoff();

	tdx->exit_reason.full = __tdx_vcpu_run(tdx->tdvpr.pa, vcpu->arch.regs,
					       tdx->tdvmcall.regs_mask);

	kvm_guest_exit_irqoff();
	tsx_ctrl_restore(tsx_ctrl);
}

fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	if (unlikely(vcpu->kvm->vm_bugged)) {
		tdx->exit_reason.full = TDX_NON_RECOVERABLE_VCPU;
		return EXIT_FASTPATH_NONE;
	}

	trace_kvm_entry(vcpu);

	if (pi_test_on(&tdx->pi_desc)) {
		apic->send_IPI_self(POSTED_INTR_VECTOR);

		kvm_wait_lapic_expire(vcpu, true);
	}

	/*
	 * Always do PMU context switch here because SEAM module
	 * unconditionally clear MSR_IA32_DS_AREA, otherwise CPU
	 * may start to write data into DS area immediately after
	 * SEAMRET to KVM, which cause PANIC with NULL access.
	 */
	intel_pmu_save();
	if (!(kvm_tdx->attributes & TDX_TD_ATTRIBUTE_PERFMON) &&
		td_profile_allowed(kvm_tdx))
		tdx_switch_perf_msrs(vcpu);

	/*
	 * limited to debug td only due to now only debug
	 * td guest need this feature for instructioin
	 * emulation/skipping and TD-off debugging.
	 */
	if (is_debug_td(vcpu)) {
		tdx_flush_gprs_dirty(vcpu, false);
		/*
		 * Clear corresponding interruptibility bits for STI
		 * and MOV SS as legacy guest, refer vmx_vcpu_run()
		 * for more informaiton
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
			tdx_set_interrupt_shadow(vcpu, 0);
	}

	tdx_vcpu_enter_exit(vcpu, tdx);

	tdx_user_return_update_cache();
	perf_restore_debug_store();
	tdx_restore_host_xsave_state(vcpu);
	tdx->host_state_need_restore = true;

	/*
	 * See the comments above for intel_pmu_save() for why
	 * always do PMU context switch here
	 *
	 * Restoring PMU must be after DS area because PMU may start to log
	 * records in DS area.
	 */
	intel_pmu_restore();
	if (kvm_tdx->attributes & TDX_TD_ATTRIBUTE_PERFMON) {
		/*
		 * Guest perf counters overflow leads to a PMI configured by
		 * host VMM into APIC_LVTPC being delivered.  This PMI causes a
		 * VM exit.  And as host counters are disabled before TDENTER, a
		 * PMI pending (if mask is set) always means a guest counter
		 * overflew.
		 *
		 * Simply set a flag to guide following NMI handling and unmask
		 * APIC_LVTPC here as host counters are to be enabled.
		 * Otherwise, a subsequent host PMI may be masked.
		 */
		if (tdx->exit_reason.basic == EXIT_REASON_EXCEPTION_NMI) {
			if (apic_read(APIC_LVTPC) & APIC_LVT_MASKED) {
				tdx->guest_pmi_exit = true;
				apic_write(APIC_LVTPC, APIC_DM_NMI);
			}
		}
	}

	tdx_register_cache_reset(vcpu);

	trace_kvm_exit(vcpu, KVM_ISA_VMX);

	tdx_complete_interrupts(vcpu);

	if (tdx->exit_reason.error || tdx->exit_reason.non_recoverable)
		return EXIT_FASTPATH_NONE;

	if (tdx->exit_reason.basic == EXIT_REASON_TDCALL)
		tdx->tdvmcall.rcx = vcpu->arch.regs[VCPU_REGS_RCX];
	else
		tdx->tdvmcall.rcx = 0;

	return EXIT_FASTPATH_NONE;
}

void tdx_hardware_enable(void)
{
	INIT_LIST_HEAD(&per_cpu(associated_tdvcpus, raw_smp_processor_id()));

	if (!cmpxchg(&trace_seamcalls_initialized, 0, 1)) {
		tdh_trace_seamcalls(trace_seamcalls);

		/* Unconditionally intercept triple faults to aid debug. */
		tdxmode(true, BIT_ULL(EXIT_REASON_TRIPLE_FAULT));
	}
}

void tdx_hardware_disable(void)
{
	int cpu = raw_smp_processor_id();
	struct list_head *tdvcpus = &per_cpu(associated_tdvcpus, cpu);
	struct vcpu_tdx *tdx, *tmp;

	/* Safe variant needed as tdx_disassociate_vp() deletes the entry. */
	list_for_each_entry_safe(tdx, tmp, tdvcpus, cpu_list)
		tdx_disassociate_vp(&tdx->vcpu);
}

void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	u16 exit_reason = tdx->exit_reason.basic;

	if (exit_reason == EXIT_REASON_EXCEPTION_NMI) {
		if (tdx->guest_pmi_exit) {
			kvm_make_request(KVM_REQ_PMI, vcpu);
			tdx->guest_pmi_exit = false;
		} else {
			kvm_before_interrupt(vcpu);
			vmx_handle_exception_nmi_irqoff(vcpu,
							tdexit_intr_info(vcpu));
			kvm_after_interrupt(vcpu);
		}
	} else if (exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(vcpu,
						     tdexit_intr_info(vcpu));
	else if (unlikely(tdx->exit_reason.non_recoverable ||
		 tdx->exit_reason.error)) {
		/*
		 * The only reason it gets EXIT_REASON_OTHER_SMI is there is
		 * an #MSMI in TD guest. The #MSMI is delivered right after
		 * SEAMCALL returns, and an #MC is delivered to host kernel
		 * after SMI handler returns.
		 *
		 * The #MC right after SEAMCALL is fixed up and skipped in #MC
		 * handler because it's an #MC happens in TD guest we cannot
		 * handle it with host's context.
		 *
		 * Call KVM's machine check handler explicitly here.
		 */
		if (tdx->exit_reason.basic == EXIT_REASON_OTHER_SMI)
			kvm_machine_check();
	}
}

static int tdx_emulate_inject_bp_end(struct kvm_vcpu *vcpu, unsigned long dr6)
{
	if ((dr6 & DR6_BS) && vcpu->arch.exception.emulate_inject_bp) {
		vcpu->arch.exception.emulate_inject_bp = false;

		// Check if we need enable #BP interception again
		tdx_update_exception_bitmap(vcpu);

		// No guest debug single step request, so clear it
		if (!(vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)) {
			unsigned long rflags;

			rflags = tdx_get_rflags(vcpu);
			rflags &= ~X86_EFLAGS_TF;
			tdx_set_rflags(vcpu, rflags);
			kvm_make_request(KVM_REQ_EVENT, vcpu);

			pr_info("Emulate the #BP injection end with single-step disabled\n");
			return 1;
		}
		pr_info("Emulate the #BP injection end with single-step enabled\n");
	}

	return 0;
}

static int tdx_handle_exception(struct kvm_vcpu *vcpu)
{
	u32 ex_no;
	unsigned long dr6;
	struct vcpu_tdx *tdx;
	struct kvm_run *kvm_run = vcpu->run;
	u32 intr_info = tdexit_intr_info(vcpu);
	const u32 guest_debug_enable = KVM_GUESTDBG_USE_HW_BP
		| KVM_GUESTDBG_SINGLESTEP;

	if (is_nmi(intr_info) || is_machine_check(intr_info))
		return 1;

	tdx = to_tdx(vcpu);
	ex_no = intr_info & INTR_INFO_VECTOR_MASK;
	switch (ex_no) {
	case DB_VECTOR:
		dr6 = tdexit_exit_qual(vcpu);

		if (tdx_emulate_inject_bp_end(vcpu, dr6))
			return 1;

		if (!(vcpu->guest_debug & guest_debug_enable)) {
			if (is_icebp(intr_info))
				WARN_ON(!tdx_skip_emulated_instruction(vcpu));

			kvm_queue_exception_p(vcpu, DB_VECTOR, dr6);
			return 1;
		}

		kvm_run->debug.arch.dr6 = dr6 | DR6_ACTIVE_LOW;
		kvm_run->debug.arch.dr7 = td_vmcs_read64(tdx, GUEST_DR7);
		fallthrough;
	case BP_VECTOR:
		vcpu->arch.event_exit_inst_len =
			td_vmcs_read32(tdx, VM_EXIT_INSTRUCTION_LEN);
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.pc = kvm_get_linear_rip(vcpu);
		kvm_run->debug.arch.exception = ex_no;
		return 0;
	default:
		kvm_pr_unimpl("unexpected exception 0x%x\n", intr_info);
		break;
	}

	return -EFAULT;
}

static void tdx_emulate_inject_bp_begin(struct kvm_vcpu *vcpu)
{
	unsigned long rflags;
	unsigned long guest_debug_old;

	/*
	 * Disable #BP intercept and enable single stepping
	 * so the int3 will execute normally in guest and
	 * return to KVM due to single stepping enabled
	 * this emulated the #BP injection.
	 */
	guest_debug_old = vcpu->guest_debug;
	vcpu->guest_debug &= ~KVM_GUESTDBG_USE_SW_BP;
	tdx_update_exception_bitmap(vcpu);
	vcpu->guest_debug = guest_debug_old;

	rflags = tdx_get_rflags(vcpu);
	rflags |= X86_EFLAGS_TF;
	tdx_set_rflags(vcpu, rflags);

	vcpu->arch.exception.emulate_inject_bp = true;

	pr_info("Emulate the #BP injection begin\n");
}

void tdx_queue_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx;
	unsigned int nr;
	bool has_error_code;
	u32 error_code;
	u32 intr_info;

	if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return;

	tdx = to_tdx(vcpu);
	nr = vcpu->arch.exception.nr;
	has_error_code = vcpu->arch.exception.has_error_code;
	error_code = vcpu->arch.exception.error_code;
	intr_info = nr | INTR_INFO_VALID_MASK;

	/*
	 * Emulate BP injection due to
	 * TDX doesn't support exception injection
	 */
	if (nr == BP_VECTOR)
		return tdx_emulate_inject_bp_begin(vcpu);

	kvm_deliver_exception_payload(vcpu);

	if (has_error_code) {
		td_vmcs_write32(tdx, VM_ENTRY_EXCEPTION_ERROR_CODE,
				error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (kvm_exception_is_soft(nr)) {
		td_vmcs_write32(tdx, VM_ENTRY_INSTRUCTION_LEN,
				vcpu->arch.event_exit_inst_len);
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	} else {
		intr_info |= INTR_TYPE_HARD_EXCEPTION;
	}

	pr_info("%s: injected: 0x%x\n", __func__, intr_info);
	td_vmcs_write32(tdx, VM_ENTRY_INTR_INFO_FIELD, intr_info);
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

static int tdx_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	eax = tdvmcall_p1_read(vcpu);
	ecx = tdvmcall_p2_read(vcpu);

	kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, true);

	tdvmcall_p1_write(vcpu, eax);
	tdvmcall_p2_write(vcpu, ebx);
	tdvmcall_p3_write(vcpu, ecx);
	tdvmcall_p4_write(vcpu, edx);

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);

	return 1;
}

static int tdx_emulate_hlt(struct kvm_vcpu *vcpu)
{
	bool interrupt_disabled = tdvmcall_p1_read(vcpu);
	union tdx_vcpu_state_details details;

	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);

	if (!interrupt_disabled) {
		details.full = td_state_non_arch_read64(
			to_tdx(vcpu), TD_VCPU_STATE_DETAILS_NON_ARCH);
		if (details.vmxip)
			return 1;
	}

	return kvm_vcpu_halt(vcpu);
}

static int tdx_complete_pio_in(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	int ret;

	WARN_ON(vcpu->arch.pio.count != 1);

	ret = ctxt->ops->pio_in_emulated(ctxt, vcpu->arch.pio.size,
					 vcpu->arch.pio.port, &val, 1);
	WARN_ON(!ret);

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

	++vcpu->stat.io_exits;

	size = tdvmcall_p1_read(vcpu);
	port = tdvmcall_p3_read(vcpu);

	if (size != 1 && size != 2 && size != 4) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	if (!tdvmcall_p2_read(vcpu)) {
		ret = ctxt->ops->pio_in_emulated(ctxt, size, port, &val, 1);
		if (!ret)
			vcpu->arch.complete_userspace_io = tdx_complete_pio_in;
		else
			tdvmcall_set_return_val(vcpu, val);
	} else {
		val = tdvmcall_p4_read(vcpu);
		ret = ctxt->ops->pio_out_emulated(ctxt, size, port, &val, 1);

		// No need for a complete_userspace_io callback.
		vcpu->arch.pio.count = 0;
	}
	if (ret)
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return ret;
}

static int tdx_emulate_vmcall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;

#define TDX_HYPERCALL_VENDOR_KVM		0x4d564b2e584454 /* TDX.KVM */
	nr = kvm_r10_read(vcpu);
	if (nr == TDX_HYPERCALL_VENDOR_KVM) {
		/*
		 * TODO: once the guest ABI change is done, remove this ABI
		 * support.
		 *
		 * ABI for KVM tdvmcall argument:
		 * magic number: R10 (0x4d564b2e584454)
		 * hypercall leaf: R11
		 * arguments: R12, R13, R14, R15.
		 */
		nr = tdvmcall_exit_reason(vcpu);
		a0 = tdvmcall_p1_read(vcpu);
		a1 = tdvmcall_p2_read(vcpu);
		a2 = tdvmcall_p3_read(vcpu);
		a3 = tdvmcall_p4_read(vcpu);
	} else {
		/*
		 * ABI for KVM tdvmcall argument:
		 * hypercall leaf: R10 (!= 0). KVM hypercall leaf starts from 1.
		 * arguments: R11, R12, R13, R14.
		 */
		a0 = kvm_r11_read(vcpu);
		a1 = kvm_r12_read(vcpu);
		a2 = kvm_r13_read(vcpu);
		a3 = kvm_r14_read(vcpu);
	}

	ret = __kvm_emulate_hypercall(vcpu, nr, a0, a1, a2, a3, true);

	tdvmcall_set_return_code(vcpu, ret);

	return 1;
}

static int tdx_complete_mmio(struct kvm_vcpu *vcpu)
{
	unsigned long val = 0;
	gpa_t gpa;
	int size;

	WARN_ON(vcpu->mmio_needed != 1);
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

	WARN_ON(vcpu->mmio_needed);

	size = tdvmcall_p1_read(vcpu);
	write = tdvmcall_p2_read(vcpu);
	gpa = tdvmcall_p3_read(vcpu);
	val = write ? tdvmcall_p4_read(vcpu) : 0;

	/* Strip the shared bit, allow MMIO with and without it set. */
	gpa &= ~(vcpu->kvm->arch.gfn_shared_mask << PAGE_SHIFT);

	if (size > 8u || ((gpa + size - 1) ^ gpa) & PAGE_MASK) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gpa >> PAGE_SHIFT);
	if (slot && !(slot->flags & KVM_MEMSLOT_INVALID)) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	if (!kvm_io_bus_write(vcpu, KVM_FAST_MMIO_BUS, gpa, 0, NULL)) {
		trace_kvm_fast_mmio(gpa);
		return 1;
	}

	if (write)
		r = tdx_mmio_write(vcpu, gpa, size, val);
	else
		r = tdx_mmio_read(vcpu, gpa, size);
	if (!r) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
		return 1;
	}

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
}

static int tdx_emulate_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_p1_read(vcpu);
	u64 data;

	if (kvm_get_msr(vcpu, index, &data)) {
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
	u32 index = tdvmcall_p1_read(vcpu);
	u64 data = tdvmcall_p2_read(vcpu);

	if (kvm_set_msr(vcpu, index, data)) {
		trace_kvm_msr_write_ex(index, data);
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	trace_kvm_msr_write(index, data);
	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);
	return 1;
}

static int tdx_map_gpa(struct kvm_vcpu *vcpu)
{
	gpa_t gpa = tdvmcall_p1_read(vcpu);
	gpa_t size = tdvmcall_p2_read(vcpu);

	if (!IS_ALIGNED(gpa, 4096) || !IS_ALIGNED(size, 4096) ||
	    (gpa + size) < gpa ||
	    (gpa + size) > vcpu->kvm->arch.gfn_shared_mask << (PAGE_SHIFT + 1))
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	else
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_SUCCESS);

	return 1;
}

static int tdx_complete_vp_vmcall(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx_vmcall *tdx_vmcall = &vcpu->run->tdx.u.vmcall;
	__u64 reg_mask;

	tdvmcall_set_return_code(vcpu, tdx_vmcall->status_code);
	tdvmcall_set_return_val(vcpu, tdx_vmcall->out_r11);

	reg_mask = kvm_rcx_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R12)
		kvm_r12_write(vcpu, tdx_vmcall->out_r12);
	if (reg_mask & TDX_VMCALL_REG_MASK_R13)
		kvm_r13_write(vcpu, tdx_vmcall->out_r13);
	if (reg_mask & TDX_VMCALL_REG_MASK_R14)
		kvm_r14_write(vcpu, tdx_vmcall->out_r14);
	if (reg_mask & TDX_VMCALL_REG_MASK_R15)
		kvm_r15_write(vcpu, tdx_vmcall->out_r15);
	if (reg_mask & TDX_VMCALL_REG_MASK_RBX)
		kvm_rbx_write(vcpu, tdx_vmcall->out_rbx);
	if (reg_mask & TDX_VMCALL_REG_MASK_RDI)
		kvm_rdi_write(vcpu, tdx_vmcall->out_rdi);
	if (reg_mask & TDX_VMCALL_REG_MASK_RSI)
		kvm_rsi_write(vcpu, tdx_vmcall->out_rsi);
	if (reg_mask & TDX_VMCALL_REG_MASK_R8)
		kvm_r8_write(vcpu, tdx_vmcall->out_r8);
	if (reg_mask & TDX_VMCALL_REG_MASK_R9)
		kvm_r9_write(vcpu, tdx_vmcall->out_r9);
	if (reg_mask & TDX_VMCALL_REG_MASK_RDX)
		kvm_rdx_write(vcpu, tdx_vmcall->out_rdx);

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
	tdx_vmcall->type = tdvmcall_exit_type(vcpu);
	tdx_vmcall->subfunction = tdvmcall_exit_reason(vcpu);

	reg_mask = kvm_rcx_read(vcpu);
	tdx_vmcall->reg_mask = reg_mask;
	if (reg_mask & TDX_VMCALL_REG_MASK_R12)
		tdx_vmcall->in_r12 = kvm_r12_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R13)
		tdx_vmcall->in_r13 = kvm_r13_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R14)
		tdx_vmcall->in_r14 = kvm_r14_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R15)
		tdx_vmcall->in_r15 = kvm_r15_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_RBX)
		tdx_vmcall->in_rbx = kvm_rbx_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_RDI)
		tdx_vmcall->in_rdi = kvm_rdi_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_RSI)
		tdx_vmcall->in_rsi = kvm_rsi_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R8)
		tdx_vmcall->in_r8 = kvm_r8_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_R9)
		tdx_vmcall->in_r9 = kvm_r9_read(vcpu);
	if (reg_mask & TDX_VMCALL_REG_MASK_RDX)
		tdx_vmcall->in_rdx = kvm_rdx_read(vcpu);

	/* notify userspace to handle the request */
	return 0;
}

static int tdx_get_quote(struct kvm_vcpu *vcpu)
{
	gpa_t gpa = tdvmcall_p1_read(vcpu);

	if (!IS_ALIGNED(gpa, PAGE_SIZE)) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	return tdx_vp_vmcall_to_user(vcpu);
}

static int tdx_report_fatal_error(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
	vcpu->run->system_event.type = KVM_SYSTEM_EVENT_CRASH;
	vcpu->run->system_event.flags = tdvmcall_p1_read(vcpu);
	return 0;
}

static int tdx_setup_event_notify_interrupt(struct kvm_vcpu *vcpu)
{
	u64 vector = tdvmcall_p1_read(vcpu);

	if (!(vector >= 32 && vector <= 255)) {
		tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
		return 1;
	}

	return tdx_vp_vmcall_to_user(vcpu);
}

static int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long exit_reason;

	if (unlikely(tdx->tdvmcall.xmm_mask))
		goto unsupported;

	if (tdvmcall_exit_type(vcpu))
		return tdx_emulate_vmcall(vcpu);

	exit_reason = tdvmcall_exit_reason(vcpu);

	trace_kvm_tdvmcall(vcpu, exit_reason,
			   tdvmcall_p1_read(vcpu), tdvmcall_p2_read(vcpu),
			   tdvmcall_p3_read(vcpu), tdvmcall_p4_read(vcpu));

	switch (exit_reason) {
	case EXIT_REASON_CPUID:
		return tdx_emulate_cpuid(vcpu);
	case EXIT_REASON_HLT:
		return tdx_emulate_hlt(vcpu);
	case EXIT_REASON_IO_INSTRUCTION:
		return tdx_emulate_io(vcpu);
	case EXIT_REASON_MSR_READ:
		return tdx_emulate_rdmsr(vcpu);
	case EXIT_REASON_MSR_WRITE:
		return tdx_emulate_wrmsr(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_emulate_mmio(vcpu);
	case TDG_VP_VMCALL_MAP_GPA:
		return tdx_map_gpa(vcpu);
	case TDG_VP_VMCALL_GET_QUOTE:
		return tdx_get_quote(vcpu);
	case TDG_VP_VMCALL_REPORT_FATAL_ERROR:
		return tdx_report_fatal_error(vcpu);
	case TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT:
		return tdx_setup_event_notify_interrupt(vcpu);
	default:
		break;
	}

unsupported:
	tdvmcall_set_return_code(vcpu, TDG_VP_VMCALL_INVALID_OPERAND);
	return 1;
}

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	td_vmcs_write64(to_tdx(vcpu), SHARED_EPT_POINTER, root_hpa & PAGE_MASK);
}

static void tdx_measure_page(struct kvm_tdx *kvm_tdx, hpa_t gpa, int size)
{
	struct tdx_ex_ret ex_ret;
	u64 err;
	int i;

	WARN_ON_ONCE(size % TDX_EXTENDMR_CHUNKSIZE);

	for (i = 0; i < size; i += TDX_EXTENDMR_CHUNKSIZE) {
		err = tdh_mr_extend(kvm_tdx->tdr.pa, gpa + i, &ex_ret);
		if (KVM_BUG_ON(err, &kvm_tdx->kvm)) {
			pr_tdx_error(TDH_MR_EXTEND, err, &ex_ret);
			break;
		}
	}
}

static void __tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
					enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	hpa_t hpa = pfn << PAGE_SHIFT;
	gpa_t gpa = gfn << PAGE_SHIFT;
	struct tdx_ex_ret ex_ret;
	hpa_t source_pa;
	u64 err;
	int i;

	if (WARN_ON_ONCE(is_error_noslot_pfn(pfn) || kvm_is_reserved_pfn(pfn)))
		return;

	/* Only support 4KB and 2MB pages */
	if (KVM_BUG_ON(level > PG_LEVEL_2M, kvm))
		return;

	/* Pin the page, KVM doesn't yet support page migration. */
	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++)
		get_page(pfn_to_page(pfn + i));

	/* Build-time faults are induced and handled via TDH_MEM_PAGE_ADD. */
	if (is_td_finalized(kvm_tdx)) {
		trace_kvm_sept_seamcall(TDH_MEM_PAGE_AUG, gpa, hpa, tdx_level);

		err = tdh_mem_page_aug(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &ex_ret);
		if (KVM_BUG_ON(err, kvm))
			pr_tdx_error(TDH_MEM_PAGE_AUG, err, &ex_ret);
		return;
	}

	trace_kvm_sept_seamcall(TDH_MEM_PAGE_ADD, gpa, hpa, tdx_level);

	/*
	 * In case of TDP MMU, fault handler can run concurrently.  Note
	 * 'source_pa' is a TD scope variable, meaning if there are multiple
	 * threads reaching here with all needing to access 'source_pa', it
	 * will break.  However fortunately this won't happen, because below
	 * TDH_MEM_PAGE_ADD code path is only used when VM is being created
	 * before it is running, using KVM_TDX_INIT_MEM_REGION ioctl (which
	 * always uses vcpu 0's page table and protected by vcpu->mutex).
	 */
	WARN_ON(kvm_tdx->source_pa == INVALID_PAGE);
	source_pa = kvm_tdx->source_pa & ~KVM_TDX_MEASURE_MEMORY_REGION;

	err = tdh_mem_page_add(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, source_pa, &ex_ret);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_PAGE_ADD, err, &ex_ret);
	else if ((kvm_tdx->source_pa & KVM_TDX_MEASURE_MEMORY_REGION))
		tdx_measure_page(kvm_tdx, gpa, KVM_HPAGE_SIZE(level));

	kvm_tdx->source_pa = INVALID_PAGE;
}

static void tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/*
	 * Only TDP MMU needs to use spinlock, however for simplicity,
	 * just always use spinlock for seamcall, regardless whether
	 * legacy MMU or TDP MMU is being used.  For legacy MMU it
	 * should not have noticeable performance impact since taking
	 * spinlock w/o needing to wait should be fast.
	 */
	spin_lock(&kvm_tdx->seamcall_lock);
	__tdx_sept_set_private_spte(kvm, gfn, level, pfn);
	spin_unlock(&kvm_tdx->seamcall_lock);
}

static void __tdx_sept_drop_private_spte(struct kvm *kvm, gfn_t gfn, enum pg_level level,
					kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	hpa_t hpa = pfn << PAGE_SHIFT;
	hpa_t hpa_with_hkid;
	struct tdx_ex_ret ex_ret;
	u64 err;
	int i;

	/* Only support 4KB and 2MB pages */
	if (KVM_BUG_ON(level > PG_LEVEL_2M, kvm))
		return;

	if (is_hkid_assigned(kvm_tdx)) {
		trace_kvm_sept_seamcall(TDH_MEM_PAGE_REMOVE, gpa, hpa, tdx_level);

		err = tdh_mem_page_remove(kvm_tdx->tdr.pa, gpa, tdx_level, &ex_ret);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_REMOVE, err, &ex_ret);
			return;
		}

		for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++) {
			hpa_with_hkid = set_hkid_to_hpa(hpa, (u16)kvm_tdx->hkid);
			err = tdh_phymem_page_wbinvd(hpa_with_hkid);
			if (WARN_ON_ONCE(err)) {
				pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
				return;
			}
			hpa += PAGE_SIZE;
		}
	} else if (tdx_reclaim_page((unsigned long)__va(hpa), hpa, level)) {
		return;
	}

	for (i = 0; i < KVM_PAGES_PER_HPAGE(level); i++)
		put_page(pfn_to_page(pfn + i));
}

static void tdx_sept_drop_private_spte(struct kvm *kvm, gfn_t gfn, enum pg_level level,
				       kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	__tdx_sept_drop_private_spte(kvm, gfn, level, pfn);
	spin_unlock(&kvm_tdx->seamcall_lock);
}

static int __tdx_sept_link_private_sp(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, void *sept_page)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	hpa_t hpa = __pa(sept_page);
	struct tdx_ex_ret ex_ret;
	u64 err;

	trace_kvm_sept_seamcall(TDH_MEM_SEPT_ADD, gpa, hpa, tdx_level);

	err = tdh_mem_sept_add(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &ex_ret);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_ADD, err, &ex_ret);
		return -EIO;
	}

	return 0;
}

static int tdx_sept_link_private_sp(struct kvm *kvm, gfn_t gfn,
				    enum pg_level level, void *sept_page)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int ret;

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	ret = __tdx_sept_link_private_sp(kvm, gfn, level, sept_page);
	spin_unlock(&kvm_tdx->seamcall_lock);

	return ret;
}

static int __tdx_sept_split_private_spte(struct kvm *kvm, gfn_t gfn,
					enum pg_level level, void *sept_page)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	hpa_t hpa = __pa(sept_page);
	struct tdx_ex_ret ex_ret;
	u64 err;

	trace_kvm_sept_seamcall(TDH_MEM_PAGE_DEMOTE, gpa, hpa, tdx_level);

	err = tdh_mem_page_demote(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &ex_ret);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_DEMOTE, err, &ex_ret);
		return -EIO;
	}

	return 0;
}

static int tdx_sept_split_private_spte(struct kvm *kvm, gfn_t gfn,
				enum pg_level level, void *sept_page)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int ret;

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	ret = __tdx_sept_split_private_spte(kvm, gfn, level, sept_page);
	spin_unlock(&kvm_tdx->seamcall_lock);

	return ret;
}

static void __tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn,
					enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	struct tdx_ex_ret ex_ret;
	u64 err;

	trace_kvm_sept_seamcall(TDH_MEM_RANGE_BLOCK, gpa, -1ull, tdx_level);

	err = tdh_mem_range_block(kvm_tdx->tdr.pa, gpa, tdx_level, &ex_ret);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &ex_ret);
}

static void tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	__tdx_sept_zap_private_spte(kvm, gfn, level);
	spin_unlock(&kvm_tdx->seamcall_lock);
}

static void __tdx_sept_unzap_private_spte(struct kvm *kvm, gfn_t gfn,
					  enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn << PAGE_SHIFT;
	struct tdx_ex_ret ex_ret;
	u64 err;

	trace_kvm_sept_seamcall(TDH_MEM_RANGE_UNBLOCK, gpa, -1ull, tdx_level);

	err = tdh_mem_range_unblock(kvm_tdx->tdr.pa, gpa, tdx_level, &ex_ret);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_RANGE_UNBLOCK, err, &ex_ret);
}

static void tdx_sept_unzap_private_spte(struct kvm *kvm, gfn_t gfn,
					enum pg_level level)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	__tdx_sept_unzap_private_spte(kvm, gfn, level);
	spin_unlock(&kvm_tdx->seamcall_lock);
}

static int __tdx_sept_free_private_sp(struct kvm *kvm, gfn_t gfn, enum pg_level level,
				      void *sept_page)
{
	/*
	 * free_private_sp() is (obviously) called when a shadow page is being
	 * zapped.  KVM doesn't (yet) zap private SPs while the TD is active.
	 */
	if (KVM_BUG_ON(is_hkid_assigned(to_kvm_tdx(kvm)), kvm))
		return -EINVAL;

	return tdx_reclaim_page((unsigned long)sept_page, __pa(sept_page), PG_LEVEL_4K);
}

static int tdx_sept_free_private_sp(struct kvm *kvm, gfn_t gfn, enum pg_level level,
				    void *sept_page)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int ret;

	/* See comment in tdx_sept_set_private_spte() */
	spin_lock(&kvm_tdx->seamcall_lock);
	ret = __tdx_sept_free_private_sp(kvm, gfn, level, sept_page);
	spin_unlock(&kvm_tdx->seamcall_lock);

	return ret;
}

/*
 * TODO: optimization:
 * Implement tlb_remote_flush_with_range and flush only private EPT by
 * TDH.MEM.TRACK or shared EPT by ept_sync_context().
 */
static int tdx_sept_tlb_remote_flush(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx;
	u64 err;

	if (!is_td(kvm))
		return -EOPNOTSUPP;

	kvm_tdx = to_kvm_tdx(kvm);
	kvm_tdx->tdh_mem_track = true;

	kvm_make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH);

	if (is_hkid_assigned(kvm_tdx) && is_td_finalized(kvm_tdx)) {
		err = tdh_mem_track(to_kvm_tdx(kvm)->tdr.pa);
		if (KVM_BUG_ON(err, kvm))
			pr_tdx_error(TDH_MEM_TRACK, err, NULL);
	}

	WRITE_ONCE(kvm_tdx->tdh_mem_track, false);

	return 0;
}

void tdx_flush_tlb(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	u64 root_hpa = mmu->root_hpa;

	/* Flush the shared EPTP, if it's valid. */
	if (VALID_PAGE(root_hpa))
		ept_sync_context(construct_eptp(vcpu, root_hpa,
						mmu->shadow_root_level));

	while (READ_ONCE(kvm_tdx->tdh_mem_track))
		cpu_relax();
}

static inline bool tdx_is_private_gpa(struct kvm *kvm, gpa_t gpa)
{
	return !((gpa >> PAGE_SHIFT) & kvm->arch.gfn_shared_mask);
}

#define TDX_SEPT_PFERR (PFERR_WRITE_MASK | PFERR_USER_MASK)

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
		err_page_level = ext_exit_qual.req_sept_level + 1;
	}

	if (tdx_is_private_gpa(vcpu->kvm, tdexit_gpa(vcpu))) {
		exit_qual = TDX_SEPT_PFERR;
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

	trace_kvm_page_fault(tdexit_gpa(vcpu), exit_qual);
	return __vmx_handle_ept_violation(vcpu, tdexit_gpa(vcpu), exit_qual, err_page_level);
}

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON(1);

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

static int tdx_handle_dr(struct kvm_vcpu *vcpu)
{
	return vmx_handle_dr(vcpu);
}

static int __tdx_handle_exit(struct kvm_vcpu *vcpu,
			     enum exit_fastpath_completion fastpath)
{
	union tdx_exit_reason exit_reason = to_tdx(vcpu)->exit_reason;

	if (unlikely(exit_reason.non_recoverable || exit_reason.error)) {
		kvm_pr_unimpl("TD exit %s(0x%llx), %d qual 0x%lx ext 0x%lx gpa 0x%lx intr 0x%lx\n",
			      tdx_error_name(exit_reason.full),
			      exit_reason.full, exit_reason.basic,
			      tdexit_exit_qual(vcpu),
			      tdexit_ext_exit_qual(vcpu),
			      tdexit_gpa(vcpu),
			      tdexit_intr_info(vcpu));
		if (exit_reason.basic == EXIT_REASON_TRIPLE_FAULT)
			return tdx_handle_triple_fault(vcpu);

		/*
		 * tdx_handle_exit_irqoff() handled EXIT_REASON_OTHER_SMI.  It
		 * must be handled before enabling preemption because it's #MC.
		 */

		goto unhandled_exit;
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
	case EXIT_REASON_DR_ACCESS:
		return tdx_handle_dr(vcpu);
	case EXIT_REASON_TRIPLE_FAULT:
		return tdx_handle_triple_fault(vcpu);
	case EXIT_REASON_OTHER_SMI:
		/*
		 * Unlike VMX, all the SMI in SEAM non-root mode (i.e. when
		 * TD guest vcpu is running) will cause TD exit to TDX module,
		 * then SEAMRET to KVM. Once it exits to KVM, SMI is delivered
		 * and handled right away.
		 *
		 * - If it's an MSMI, it's handled above due to non_recoverable
		 *   bit set.
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
	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = exit_reason.full;
	return 0;
}

int tdx_handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
	int ret = __tdx_handle_exit(vcpu, exit_fastpath);

	/*
	 * Exit to user space when bus lock detected to inform that there is
	 * a bus lock in guest.
	 */
	if (to_tdx(vcpu)->exit_reason.bus_lock_detected) {
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

int __init tdx_check_processor_compatibility(void)
{
	/* TDX-SEAM itself verifies compatibility on all CPUs. */
	return 0;
}

void tdx_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	/* Only x2APIC mode is supported for TD. */
	WARN_ON_ONCE(kvm_get_apic_mode(vcpu) != LAPIC_MODE_X2APIC);
}

void tdx_apicv_post_state_restore(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	pi_clear_on(&tdx->pi_desc);
	memset(tdx->pi_desc.pir, 0, sizeof(tdx->pi_desc.pir));
}

/*
 * Send interrupt to vcpu via posted interrupt way.
 * 1. If target vcpu is running(non-root mode), send posted interrupt
 * notification to vcpu and hardware will sync PIR to vIRR atomically.
 * 2. If target vcpu isn't running(root mode), kick it to pick up the
 * interrupt from PIR in next vmentry.
 */
int tdx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (pi_test_and_set_pir(vector, &tdx->pi_desc))
		return 0;

	/* If a previous notification has sent the IPI, nothing to do. */
	if (pi_test_and_set_on(&tdx->pi_desc))
		return 0;

	if (vcpu != kvm_get_running_vcpu() &&
	    !kvm_vcpu_trigger_posted_interrupt(vcpu, false))
		kvm_vcpu_kick(vcpu);

	return 0;
}

int tdx_dev_ioctl(void __user *argp)
{
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities caps;
	struct kvm_tdx_cmd cmd;

	BUILD_BUG_ON(sizeof(struct kvm_tdx_cpuid_config) !=
		     sizeof(struct tdx_cpuid_config));

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.metadata || cmd.id != KVM_TDX_CAPABILITIES)
		return -EINVAL;

	user_caps = (void __user *)cmd.data;
	if (copy_from_user(&caps, user_caps, sizeof(caps)))
		return -EFAULT;

	if (caps.nr_cpuid_configs < tdx_caps.nr_cpuid_configs)
		return -E2BIG;
	caps.nr_cpuid_configs = tdx_caps.nr_cpuid_configs;

	if (copy_to_user(user_caps->cpuid_configs, &tdx_caps.cpuid_configs,
			 tdx_caps.nr_cpuid_configs * sizeof(struct tdx_cpuid_config)))
		return -EFAULT;

	caps.attrs_fixed0 = tdx_caps.attrs_fixed0;
	caps.attrs_fixed1 = tdx_caps.attrs_fixed1;
	caps.xfam_fixed0 = tdx_caps.xfam_fixed0;
	caps.xfam_fixed1 = tdx_caps.xfam_fixed1;

	if (copy_to_user((void __user *)cmd.data, &caps, sizeof(caps)))
		return -EFAULT;

	return 0;
}

/*
 * TDX-SEAM definitions for fixed{0,1} are inverted relative to VMX.  The TDX
 * definitions are sane, the VMX definitions are backwards.
 *
 * if fixed0[i] == 0: val[i] must be 0
 * if fixed1[i] == 1: val[i] must be 1
 */
static inline bool tdx_fixed_bits_valid(u64 val, u64 fixed0, u64 fixed1)
{
	return ((val & fixed0) | fixed1) == val;
}

static struct kvm_cpuid_entry2 *tdx_find_cpuid_entry(struct kvm_tdx *kvm_tdx,
						     u32 function, u32 index)
{
	struct kvm_cpuid_entry2 *e;
	int i;

	for (i = 0; i < kvm_tdx->cpuid_nent; i++) {
		e = &kvm_tdx->cpuid_entries[i];

		if (e->function == function && (e->index == index ||
		    !(e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)))
			return e;
	}
	return NULL;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params,
			  struct kvm_tdx_init_vm *init_vm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_cpuid_config *config;
	struct kvm_cpuid_entry2 *entry;
	struct tdx_cpuid_value *value;
	u64 guest_supported_xcr0;
	u64 guest_supported_xss;
	u32 guest_tsc_khz;
	int max_pa;
	int i;

	/* init_vm->reserved must be zero */
	if (find_first_bit((unsigned long *)init_vm->reserved,
			   sizeof(init_vm->reserved) * 8) !=
	    sizeof(init_vm->reserved) * 8)
		return -EINVAL;

	td_params->attributes = init_vm->attributes;
	td_params->max_vcpus = init_vm->max_vcpus;

	/* TODO: Enforce consistent CPUID features for all vCPUs. */
	for (i = 0; i < tdx_caps.nr_cpuid_configs; i++) {
		config = &tdx_caps.cpuid_configs[i];

		entry = tdx_find_cpuid_entry(kvm_tdx, config->leaf,
					     config->sub_leaf);
		if (!entry)
			continue;

		/*
		 * Non-configurable bits must be '0', even if they are fixed to
		 * '1' by TDX-SEAM, i.e. mask off non-configurable bits.
		 */
		value = &td_params->cpuid_values[i];
		value->eax = entry->eax & config->eax;
		value->ebx = entry->ebx & config->ebx;
		value->ecx = entry->ecx & config->ecx;
		value->edx = entry->edx & config->edx;
	}

	entry = tdx_find_cpuid_entry(kvm_tdx, 0xd, 0);
	if (entry)
		guest_supported_xcr0 = (entry->eax | ((u64)entry->edx << 32));
	else
		guest_supported_xcr0 = 0;
	guest_supported_xcr0 &= supported_xcr0;

	entry = tdx_find_cpuid_entry(kvm_tdx, 0xd, 1);
	if (entry)
		guest_supported_xss = (entry->ecx | ((u64)entry->edx << 32));
	else
		guest_supported_xss = 0;

	/* PT can be exposed to TD guest regardless of KVM's XSS support */
	guest_supported_xss &= (supported_xss | XFEATURE_MASK_PT | TDX_TD_XFAM_CET);

	max_pa = 36;
	entry = tdx_find_cpuid_entry(kvm_tdx, 0x80000008, 0);
	if (entry)
		max_pa = entry->eax & 0xff;

	td_params->eptp_controls = VMX_EPTP_MT_WB;

	if (cpu_has_vmx_ept_5levels() && max_pa > 48) {
		td_params->eptp_controls |= VMX_EPTP_PWL_5;
		td_params->exec_controls |= TDX_EXEC_CONTROL_MAX_GPAW;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
	}

	if (!tdx_fixed_bits_valid(td_params->attributes,
				  tdx_caps.attrs_fixed0,
				  tdx_caps.attrs_fixed1))
		return -EINVAL;

	/* Setup td_params.xfam */
	td_params->xfam = guest_supported_xcr0 | guest_supported_xss;
	if (!tdx_fixed_bits_valid(td_params->xfam,
				  tdx_caps.xfam_fixed0,
				  tdx_caps.xfam_fixed1))
		return -EINVAL;

	if (td_params->xfam & TDX_TD_XFAM_LBR) {
		pr_warn("TD doesn't support LBR. KVM needs to save/restore "
			"IA32_LBR_DEPTH properly.\n");
		return -EOPNOTSUPP;
	}

	if (td_params->xfam & TDX_TD_XFAM_AMX) {
		pr_warn("TD doesn't support AMX. KVM needs to save/restore "
			"IA32_XFD, IA32_XFD_ERR properly.\n");
		return -EOPNOTSUPP;
	}

	if (init_vm->tsc_khz)
		guest_tsc_khz = init_vm->tsc_khz;
	else
		guest_tsc_khz = kvm->arch.initial_tsc_khz;

	if (guest_tsc_khz < TDX_MIN_TSC_FREQUENCY_KHZ ||
	    guest_tsc_khz > TDX_MAX_TSC_FREQUENCY_KHZ) {
		pr_warn_ratelimited("Illegal TD TSC %d Khz, it must be between [%d, %d] Khz\n",
		guest_tsc_khz, TDX_MIN_TSC_FREQUENCY_KHZ, TDX_MAX_TSC_FREQUENCY_KHZ);
		return -EINVAL;
	}

	td_params->tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(guest_tsc_khz);
	if (TDX_TSC_25MHZ_TO_KHZ(td_params->tsc_frequency) != guest_tsc_khz) {
		pr_warn_ratelimited("TD TSC %d Khz not a multiple of 25Mhz\n", guest_tsc_khz);
		if (init_vm->tsc_khz)
			return -EINVAL;
	}

	BUILD_BUG_ON(sizeof(td_params->mrconfigid) !=
		     sizeof(init_vm->mrconfigid));
	memcpy(td_params->mrconfigid, init_vm->mrconfigid,
	       sizeof(td_params->mrconfigid));
	BUILD_BUG_ON(sizeof(td_params->mrowner) !=
		     sizeof(init_vm->mrowner));
	memcpy(td_params->mrowner, init_vm->mrowner, sizeof(td_params->mrowner));
	BUILD_BUG_ON(sizeof(td_params->mrownerconfig) !=
		     sizeof(init_vm->mrownerconfig));
	memcpy(td_params->mrownerconfig, init_vm->mrownerconfig,
	       sizeof(td_params->mrownerconfig));

	return 0;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_cpuid2 __user *user_cpuid;
	struct kvm_tdx_init_vm init_vm;
	struct td_params *td_params;
	struct tdx_ex_ret ex_ret;
	struct kvm_cpuid2 cpuid;
	int ret;
	u64 err;

	if (is_td_initialized(kvm))
		return -EINVAL;

	if (cmd->metadata)
		return -EINVAL;

	if (copy_from_user(&init_vm, (void __user *)cmd->data, sizeof(init_vm)))
		return -EFAULT;

	if (init_vm.max_vcpus > KVM_MAX_VCPUS)
		return -EINVAL;

	user_cpuid = (void *)init_vm.cpuid;
	if (copy_from_user(&cpuid, user_cpuid, sizeof(cpuid)))
		return -EFAULT;

	if (cpuid.nent > KVM_MAX_CPUID_ENTRIES)
		return -E2BIG;

	if (copy_from_user(&kvm_tdx->cpuid_entries, user_cpuid->entries,
			   cpuid.nent * sizeof(struct kvm_cpuid_entry2)))
		return -EFAULT;

	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL_ACCOUNT);
	if (!td_params)
		return -ENOMEM;

	kvm_tdx->cpuid_nent = cpuid.nent;

	ret = setup_tdparams(kvm, td_params, &init_vm);
	if (ret)
		goto free_tdparams;

	err = tdh_mng_init(kvm_tdx->tdr.pa, __pa(td_params), &ex_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_INIT, err, &ex_ret);
		ret = -EIO;
		goto free_tdparams;
	}

	kvm_tdx->tsc_offset = td_tdcs_exec_read64(kvm_tdx, TD_TDCS_EXEC_TSC_OFFSET);
	kvm_tdx->attributes = td_params->attributes;
	kvm_tdx->xfam = td_params->xfam;
	kvm->max_vcpus = td_params->max_vcpus;
	kvm->arch.initial_tsc_khz = TDX_TSC_25MHZ_TO_KHZ(td_params->tsc_frequency);

	if (td_params->exec_controls & TDX_EXEC_CONTROL_MAX_GPAW)
		kvm->arch.gfn_shared_mask = BIT_ULL(51) >> PAGE_SHIFT;
	else
		kvm->arch.gfn_shared_mask = BIT_ULL(47) >> PAGE_SHIFT;

free_tdparams:
	kfree(td_params);
	if (ret)
		kvm_tdx->cpuid_nent = 0;
	return ret;
}

static int tdx_init_mem_region(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_mem_region region;
	struct kvm_vcpu *vcpu;
	struct page *page;
	kvm_pfn_t pfn;
	int idx, ret = 0;

	/* The BSP vCPU must be created before initializing memory regions. */
	if (!atomic_read(&kvm->online_vcpus))
		return -EINVAL;

	if (cmd->metadata & ~KVM_TDX_MEASURE_MEMORY_REGION)
		return -EINVAL;

	if (copy_from_user(&region, (void __user *)cmd->data, sizeof(region)))
		return -EFAULT;

	/* Sanity check */
	if (!IS_ALIGNED(region.source_addr, PAGE_SIZE))
		return -EINVAL;
	if (!IS_ALIGNED(region.gpa, PAGE_SIZE))
		return -EINVAL;
	if (!region.nr_pages)
		return -EINVAL;
	if (region.gpa + (region.nr_pages << PAGE_SHIFT) <= region.gpa)
		return -EINVAL;
	if (!tdx_is_private_gpa(kvm, region.gpa))
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
				     (cmd->metadata & KVM_TDX_MEASURE_MEMORY_REGION);

		pfn = kvm_mmu_map_tdp_page(vcpu, region.gpa, TDX_SEPT_PFERR,
					   PG_LEVEL_4K);
		if (is_error_noslot_pfn(pfn) || kvm->vm_bugged)
			ret = -EFAULT;
		else
			ret = 0;

		put_page(page);
		if (ret)
			break;

		region.source_addr += PAGE_SIZE;
		region.gpa += PAGE_SIZE;
		region.nr_pages--;
	}

	srcu_read_unlock(&kvm->srcu, idx);
	vcpu_put(vcpu);

	mutex_unlock(&vcpu->mutex);

	if (copy_to_user((void __user *)cmd->data, &region, sizeof(region)))
		ret = -EFAULT;

	return ret;
}

static int tdx_td_finalizemr(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;

	if (!is_td_initialized(kvm) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	err = tdh_mr_finalize(kvm_tdx->tdr.pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MR_FINALIZE, err, NULL);
		return -EIO;
	}

	(void)tdh_mem_track(to_kvm_tdx(kvm)->tdr.pa);

	kvm_tdx->finalized = true;
	return 0;
}

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
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

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_tdx_cmd cmd;
	u64 err;

	if (tdx->initialized)
		return -EINVAL;

	if (!is_td_initialized(vcpu->kvm) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.metadata || cmd.id != KVM_TDX_INIT_VCPU)
		return -EINVAL;

	err = tdh_vp_init(tdx->tdvpr.pa, cmd.data);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_INIT, err, NULL);
		return -EIO;
	}

	tdx->initialized = true;

	td_vmcs_write16(tdx, POSTED_INTR_NV, POSTED_INTR_VECTOR);
	td_vmcs_write64(tdx, POSTED_INTR_DESC_ADDR, __pa(&tdx->pi_desc));
	td_vmcs_setbit32(tdx, PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR);

	/*
	 * Check if VM_{ENTRY, EXIT}_LOAD_IA32_PERF_GLOBAL_CTRL are set in case
	 * of a TDX module bug. It is required to monitor TD with PMU events.
	 * Note that these two bits are read-only even for debug TD.
	 */
	if ((td_profile_state == TD_PROFILE_NONE) &&
	    (kvm_tdx->attributes & TDX_TD_ATTRIBUTE_DEBUG) &&
	    !(kvm_tdx->attributes & TDX_TD_ATTRIBUTE_PERFMON))	{
		u32 exit, entry;

		exit = td_vmcs_read32(tdx, VM_EXIT_CONTROLS);
		entry = td_vmcs_read32(tdx, VM_ENTRY_CONTROLS);

		if ((exit & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL) &&
		    (entry & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL))
			td_profile_state = TD_PROFILE_ENABLE;
		else {
			pr_warn_once("Cannot monitor TD with PMU events\n");
			td_profile_state = TD_PROFILE_DISABLE;
		}
	}

	if (is_debug_td(vcpu)) {
		td_vmcs_setbit32(tdx,
				 CPU_BASED_VM_EXEC_CONTROL,
				 CPU_BASED_MOV_DR_EXITING);
		pr_info("Set DR access VMExit for debug enabled TD guest\n");
	}

	if (vcpu->kvm->arch.bus_lock_detection_enabled)
		td_vmcs_setbit32(tdx,
				 SECONDARY_VM_EXEC_CONTROL,
				 SECONDARY_EXEC_BUS_LOCK_DETECTION);

	return 0;
}

void tdx_update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	u32 eb;
	u32 new_eb;
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	const u32 guest_debug_sw_bp = KVM_GUESTDBG_ENABLE
		| KVM_GUESTDBG_USE_SW_BP;

	if (!is_debug_td(vcpu) || !tdx->initialized)
		return;

	eb = td_vmcs_read32(tdx, EXCEPTION_BITMAP);

	new_eb = eb | 1u << DB_VECTOR;
	if ((vcpu->guest_debug & guest_debug_sw_bp) ==
	    guest_debug_sw_bp) {
		new_eb |= 1u << BP_VECTOR;
	} else {
		new_eb &= ~(1u << BP_VECTOR);
	}

	/*
	 * Notice for nested support:
	 * No nested supporting due to SEAM module doesn't
	 * support it o far, we shuole consult
	 * vmx_update_exception_bitmap() when nested support
	 * become ready in future.
	 */

	if (new_eb != eb) {
		u32 verify_eb;

		td_vmcs_write32(tdx, EXCEPTION_BITMAP, new_eb);
		verify_eb = td_vmcs_read32(tdx, EXCEPTION_BITMAP);
		KVM_BUG_ON(verify_eb != new_eb, vcpu->kvm);
	}
}

void tdx_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (!is_debug_td(vcpu) || !tdx->initialized)
		return;

	td_vmcs_write64(tdx, GUEST_DR7, val);
}

void tdx_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx_vcpu = to_tdx(vcpu);

	if (!is_debug_td(vcpu))
		return;

	/*
	 * Even auto switch guest need save the debug register for visting
	 * from userspace when KVM/QEMU doesn't using the DR registers.
	 *
	 * WARN_ON(vcpu->arch.switch_db_regs & KVM_DEBUGREG_AUTO_SWITCH);
	 */

	vcpu->arch.db[0] = td_dr_read64(tdx_vcpu, 0);
	vcpu->arch.db[1] = td_dr_read64(tdx_vcpu, 1);
	vcpu->arch.db[2] = td_dr_read64(tdx_vcpu, 2);
	vcpu->arch.db[3] = td_dr_read64(tdx_vcpu, 3);
	vcpu->arch.dr6 = td_dr_read64(tdx_vcpu, 6);
	vcpu->arch.dr7 = td_vmcs_read64(to_tdx(vcpu), GUEST_DR7);

	vcpu->arch.switch_db_regs &= ~KVM_DEBUGREG_WONT_EXIT;
	td_vmcs_setbit32(tdx_vcpu,
			 CPU_BASED_VM_EXEC_CONTROL,
			 CPU_BASED_MOV_DR_EXITING);
}

void tdx_load_guest_debug_regs(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx_vcpu = to_tdx(vcpu);

	if (!is_debug_td(vcpu))
		return;

	td_dr_write64(tdx_vcpu, 0, vcpu->arch.eff_db[0]);
	td_dr_write64(tdx_vcpu, 1, vcpu->arch.eff_db[1]);
	td_dr_write64(tdx_vcpu, 2, vcpu->arch.eff_db[2]);
	td_dr_write64(tdx_vcpu, 3, vcpu->arch.eff_db[3]);
	td_dr_write64(tdx_vcpu, 6, vcpu->arch.dr6);

	/*
	 * Optimization:
	 * tdx auto switch the guest debug regs, so we clear
	 * KVM_DEBUGREG_BP_ENABLED to avoid  update
	 * guest debug regs every time.
	 */
	vcpu->arch.switch_db_regs &= ~KVM_DEBUGREG_BP_ENABLED;
}

int tdx_get_cpl(struct kvm_vcpu *vcpu)
{
	if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return 0;

	/*
	 * For debug TDs, tdx_get_cpl() may be called before the vCPU is
	 * initialized, i.e. before TDH_VP_RD is legal, if the vCPU is scheduled
	 * out.  If this happens, simply return CPL0 to avoid TDH_VP_RD failure.
	 */
	if (!to_tdx(vcpu)->initialized)
		return 0;

	return VMX_AR_DPL(td_vmcs_read32(to_tdx(vcpu), GUEST_SS_AR_BYTES));
}

unsigned long tdx_get_rflags(struct kvm_vcpu *vcpu)
{
	if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return 0;

	return td_vmcs_read64(to_tdx(vcpu), GUEST_RFLAGS);
}

void tdx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	u64 val;

	if (!tdx->initialized)
		return;

	if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return;

	/*
	 * TODO: This is currently disallowed by TDX-SEAM, which breaks single-
	 * step debug.
	 */
	td_vmcs_write64(to_tdx(vcpu), GUEST_RFLAGS, rflags);
	val = td_vmcs_read64(to_tdx(vcpu), GUEST_RFLAGS);
	pr_info("Guest RFLAGS updated to 0x%llx\n", val);
}

bool tdx_is_emulated_msr(u32 index, bool write)
{
	switch (index) {
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_ARCH_CAPABILITIES:
	case MSR_IA32_POWER_CTL:
	case MSR_MTRRcap:
	case 0x200 ... 0x2ff:
	case MSR_IA32_TSC_DEADLINE:
	case MSR_IA32_MISC_ENABLE:
	case MSR_KVM_STEAL_TIME:
	case MSR_KVM_POLL_CONTROL:
	case MSR_PLATFORM_INFO:
	case MSR_MISC_FEATURES_ENABLES:
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MCx_CTL(32) - 1:
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
	case MSR_IA32_APICBASE:
	case MSR_EFER:
		return !write;
	default:
		return false;
	}
}

int tdx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	if (tdx_is_emulated_msr(msr->index, false))
		return kvm_get_msr_common(vcpu, msr);
	return 1;
}

int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	if (tdx_is_emulated_msr(msr->index, true))
		return kvm_set_msr_common(vcpu, msr);
	return 1;
}

u64 tdx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	if (!is_debug_td(vcpu))
		return 0;

	return td_vmcs_read64(to_tdx(vcpu), GUEST_ES_BASE + seg * 2);
}

void tdx_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (!is_debug_td(vcpu)) {
		memset(var, 0, sizeof(*var));
		return;
	}

	seg *= 2;
	var->base = td_vmcs_read64(tdx, GUEST_ES_BASE + seg);
	var->limit = td_vmcs_read32(tdx, GUEST_ES_LIMIT + seg);
	var->selector = td_vmcs_read16(tdx, GUEST_ES_SELECTOR + seg);
	vmx_decode_ar_bytes(td_vmcs_read32(tdx, GUEST_ES_AR_BYTES + seg), var);
}

void tdx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u32 ar;
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return;

	ar = td_vmcs_read32(tdx, GUEST_CS_AR_BYTES);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

static void tdx_cache_gprs(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	if (!is_td_vcpu(vcpu) || !is_debug_td(vcpu))
		return;

	for (i = 0; i < NR_VCPU_REGS; i++) {

		if (i == VCPU_REGS_RIP) {
			vcpu->arch.regs[i] = td_vmcs_read64(tdx, GUEST_RIP);
			continue;
		}
		if (i == VCPU_REGS_RSP) {
			vcpu->arch.regs[i] = td_vmcs_read64(tdx, GUEST_RSP);
			continue;
		}

		vcpu->arch.regs[i] = td_gpr_read64(tdx, i);
	}
}

static void tdx_flush_gprs_dirty(struct kvm_vcpu *vcpu, bool force)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	for (i = 0; i < NR_VCPU_REGS; i++) {
		if (!kvm_register_is_dirty(vcpu, i) && !force)
			continue;

		if (i == VCPU_REGS_RSP) {
			td_vmcs_write64(tdx, GUEST_RSP, vcpu->arch.regs[i]);
			continue;
		}
		if (i == VCPU_REGS_RIP) {
			td_vmcs_write64(tdx, GUEST_RIP, vcpu->arch.regs[i]);
			continue;
		}

		td_gpr_write64(tdx, i, vcpu->arch.regs[i]);
	}
}

static void tdx_flush_gprs(struct kvm_vcpu *vcpu)
{
	if (!is_td_vcpu(vcpu) || KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return;

	tdx_flush_gprs_dirty(vcpu, true);
}

int tdx_prepare_memory_region(struct kvm *kvm,
			struct kvm_memory_slot *memslot,
			const struct kvm_userspace_memory_region *mem,
			enum kvm_mr_change change)
{
	/* TDX Secure-EPT allows only RWX. */
	if (mem->flags & KVM_MEM_READONLY)
		return -EOPNOTSUPP;

	/* TDX supports only single as-id. */
	if (mem->slot >> 16)
		return -EOPNOTSUPP;

	return 0;
}

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size)
{
	*vcpu_size = sizeof(struct vcpu_tdx);
	*vcpu_align = __alignof__(struct vcpu_tdx);

	if (sizeof(struct kvm_tdx) > *vm_size)
		*vm_size = sizeof(struct kvm_tdx);
}

#define TDX_MEMORY_RW_CHUNK 8
#define TDX_MEMORY_RW_CHUNK_OFFSET_MASK (TDX_MEMORY_RW_CHUNK - 1)
#define TDX_MEMORY_RW_CHUNK_MASK (~TDX_MEMORY_RW_CHUNK_OFFSET_MASK)
static inline void tdx_get_memory_chunk_and_offset(gpa_t addr, u64 *chunk, u32 *offset)
{
	*chunk = addr & TDX_MEMORY_RW_CHUNK_MASK;
	*offset = addr & TDX_MEMORY_RW_CHUNK_OFFSET_MASK;
}

static int do_read_private_memory(struct kvm *kvm, gpa_t addr, u64 *val)
{
	u64 err;
	struct tdx_ex_ret td_ret;

	err = tdh_mem_rd(to_kvm_tdx(kvm)->tdr.pa, addr, &td_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MEM_RD, err, &td_ret);
		return -EIO;
	}

	*val = td_ret.mem_rdwr.mem_val;
	return 0;
}

static int read_private_memory(struct kvm *kvm, gpa_t addr,
			       u32 max_allow_len,
			       u32 *copy_len, void *out_buf)
{
	gpa_t chunk_addr;
	u32 in_chunk_offset;
	u32 len;
	int ret;
	union {
		u64 u64;
		u8 u8[TDX_MEMORY_RW_CHUNK];
	} l_buf;

	tdx_get_memory_chunk_and_offset(addr, &chunk_addr,
					&in_chunk_offset);
	len = min(max_allow_len,
		  TDX_MEMORY_RW_CHUNK - in_chunk_offset);

	if (len < TDX_MEMORY_RW_CHUNK) {
		/* unaligned GPA head/tail */
		ret = do_read_private_memory(kvm,
					     chunk_addr,
					     &l_buf.u64);
		if (!ret)
			memcpy(out_buf,
			       l_buf.u8 + in_chunk_offset,
			       len);
	} else {
		ret = do_read_private_memory(kvm,
					     chunk_addr,
					     out_buf);
	}

	if (copy_len && !ret)
		*copy_len = len;
	return ret;
}

static int do_tdx_td_read_memory(struct kvm *kvm,
				 gpa_t addr, u64 len, void __user *buf)
{
	u32 in_page_offset;
	u32 copy_len;
	u32 round_len;
	u32 saved_round_len;
	gfn_t gfn;
	void *page_buf;
	void *to_buf;
	bool is_private;
	int ret = -EINVAL;
	int idx;
	struct kvm_memory_slot *memslot;

	page_buf = (void *)__get_free_page(GFP_KERNEL);
	if (!page_buf)
		return -ENOMEM;

	while (len > 0) {
		round_len = min(len,
				(u64)(PAGE_SIZE - offset_in_page(addr)));
		saved_round_len = round_len;

		idx = srcu_read_lock(&kvm->srcu);

		gfn = gpa_to_gfn(addr);
		memslot = gfn_to_memslot(kvm, gfn);
		if (!kvm_is_visible_memslot(memslot)) {
			ret = -EINVAL;
			goto fail_unlock_srcu;
		}

		to_buf = page_buf;
		while (round_len > 0) {
			read_lock(&kvm->mmu_lock);

			ret = kvm_mmu_is_page_private(kvm, memslot,
						      gfn, &is_private);
			if (ret)
				goto fail_unlock;

			if (is_private) {
				ret = read_private_memory(kvm, addr,
							  round_len,
							  &copy_len,
							  to_buf);
			} else {
				in_page_offset = offset_in_page(addr);
				copy_len = min(round_len,
					       (u32)
					       (PAGE_SIZE - in_page_offset));
				ret = kvm_read_guest_page(kvm, gfn, to_buf,
							  in_page_offset,
							  copy_len);
			}
			if (ret)
				goto fail_unlock;

			read_unlock(&kvm->mmu_lock);
			addr += copy_len;
			to_buf += copy_len;
			round_len -= copy_len;
		}

		srcu_read_unlock(&kvm->srcu, idx);

		if (copy_to_user(buf,
				 page_buf, saved_round_len)) {
			ret = -EFAULT;
			goto fail_free_mem;
		}

		len -= saved_round_len;
		buf += saved_round_len;
	}

	free_page((u64)page_buf);

	return ret;

fail_unlock:
	read_unlock(&kvm->mmu_lock);
fail_unlock_srcu:
	srcu_read_unlock(&kvm->srcu, idx);
fail_free_mem:
	free_page((u64)page_buf);
	return ret;
}

static int do_write_private_memory(struct kvm *kvm, gpa_t addr, u64 *val)
{
	u64 err;
	struct tdx_ex_ret td_ret;

	err = tdh_mem_wr(to_kvm_tdx(kvm)->tdr.pa, addr, *val, &td_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MEM_WR, err, &td_ret);
		return -EIO;
	}

	return 0;
}

static int write_private_memory(struct kvm *kvm, gpa_t addr,
			       u32 max_allow_len,
			       u32 *copy_len, void *in_buf)
{
	gpa_t chunk_addr;
	u32 in_chunk_offset;
	u32 len;
	void *ptr;
	int ret;
	union {
		u64 u64;
		u8 u8[TDX_MEMORY_RW_CHUNK];
	} l_buf;

	tdx_get_memory_chunk_and_offset(addr, &chunk_addr, &in_chunk_offset);
	len = min(max_allow_len, TDX_MEMORY_RW_CHUNK - in_chunk_offset);

	if (len < TDX_MEMORY_RW_CHUNK) {
		ret = do_read_private_memory(kvm,
					     chunk_addr,
					     &l_buf.u64);
		if (!ret)
			memcpy(l_buf.u8 + in_chunk_offset, in_buf, len);
		ptr = l_buf.u8;
	} else {
		ret = 0;
		ptr = in_buf;
	}

	if (!ret)
		ret = do_write_private_memory(kvm, chunk_addr, ptr);

	if (copy_len && !ret)
		*copy_len = len;

	return ret;
}

static int do_tdx_td_write_memory(struct kvm *kvm,
				  gpa_t addr, u64 len, void __user *buf)
{
	u32 in_page_offset;
	u32 copy_len;
	u32 round_len;
	gfn_t gfn;
	int ret = 0;
	int idx;
	void *page_buf;
	void *from_buf;
	bool is_private;
	struct kvm_memory_slot *memslot;

	page_buf = (void *)__get_free_page(GFP_KERNEL);
	if (!page_buf)
		return -ENOMEM;

	while (len > 0) {
		round_len = min(len,
				(u64)(PAGE_SIZE - offset_in_page(addr)));
		if (copy_from_user(page_buf, buf, round_len)) {
			ret = -EFAULT;
			goto fail_free_mem;
		}

		idx = srcu_read_lock(&kvm->srcu);

		gfn = gpa_to_gfn(addr);
		memslot = gfn_to_memslot(kvm, gfn);
		if (!kvm_is_visible_memslot(memslot)) {
			ret = -EINVAL;
			goto fail_unlock_srcu;
		}

		from_buf = page_buf;
		len -= round_len;
		buf += round_len;
		while (round_len > 0) {
			read_lock(&kvm->mmu_lock);

			ret = kvm_mmu_is_page_private(kvm, memslot, gfn, &is_private);
			if (ret)
				goto fail_unlock;

			if (is_private) {
				ret = write_private_memory(kvm, addr,
							   round_len,
							   &copy_len,
							   from_buf);
			} else {
				in_page_offset = offset_in_page(addr);
				copy_len = min(round_len,
					       (u32)
					       (PAGE_SIZE - in_page_offset));
				ret = kvm_write_guest_page(kvm, gfn,
							   from_buf,
							   in_page_offset,
							   copy_len);
			}
			if (ret)
				goto fail_unlock;

			read_unlock(&kvm->mmu_lock);
			addr += copy_len;
			from_buf += copy_len;
			round_len -= copy_len;
		}
		srcu_read_unlock(&kvm->srcu, idx);
	}

	free_page((u64)page_buf);
	return ret;

fail_unlock:
	read_unlock(&kvm->mmu_lock);
fail_unlock_srcu:
	srcu_read_unlock(&kvm->srcu, idx);
fail_free_mem:
	free_page((u64)page_buf);
	return ret;
}

static int tdx_read_guest_memory(struct kvm *kvm, struct kvm_rw_memory *rw_memory)
{
	if (!is_td(kvm))
		return -EINVAL;

	if (!(to_kvm_tdx(kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG))
		return -EINVAL;

	if (!is_td_initialized(kvm))
		return -EINVAL;

	if (rw_memory->len == 0 || !rw_memory->ubuf)
		return -EINVAL;

	if (rw_memory->addr + rw_memory->len < rw_memory->addr)
		return -EINVAL;

	return do_tdx_td_read_memory(kvm, rw_memory->addr, rw_memory->len,
				     (void __user *)rw_memory->ubuf);
}

int tdx_write_guest_memory(struct kvm *kvm, struct kvm_rw_memory *rw_memory)
{
	if (!is_td(kvm))
		return -EINVAL;

	if (!(to_kvm_tdx(kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG))
		return -EINVAL;

	if (!is_td_initialized(kvm))
		return -EINVAL;

	if (rw_memory->len == 0 || !rw_memory->ubuf)
		return -EINVAL;

	if (rw_memory->addr + rw_memory->len < rw_memory->addr)
		return -EINVAL;

	return do_tdx_td_write_memory(kvm, rw_memory->addr, rw_memory->len,
				      (void __user *)rw_memory->ubuf);
}

void tdx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	if (!is_debug_td(vcpu))
		return;

	vmx_set_interrupt_shadow(vcpu, mask);
}

int tdx_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip, orig_rip;

	if (!is_debug_td(vcpu))
		return 0;

	if (is_guest_mode(vcpu)) {
		/*
		 * Refer vmx_update_emulated_instruction(vcpu)
		 * for more information.
		 */
		kvm_pr_unimpl("No nested support to TD guest\n");
		return 0;
	}

	/*
	 * Refer skip_emulated_instruction() in vmx.c for more information
	 * about this checking
	 */
	if (static_cpu_has(X86_FEATURE_HYPERVISOR) &&
	    to_tdx(vcpu)->exit_reason.basic == EXIT_REASON_EPT_MISCONFIG) {
		kvm_pr_unimpl("kvm_emulate_instruction() doesn't support TD guest\n");
		return 0;
	}

	orig_rip = kvm_rip_read(vcpu);
	rip = orig_rip + td_vmcs_read32(to_tdx(vcpu), VM_EXIT_INSTRUCTION_LEN);
#ifdef CONFIG_X86_64
	rip = vmx_mask_out_guest_rip(vcpu, orig_rip, rip);
#endif
	kvm_rip_write(vcpu, rip);

	tdx_set_interrupt_shadow(vcpu, 0);

	return 1;
}

static int __init tdx_debugfs_init(void);
static void __exit tdx_debugfs_exit(void);

int __init tdx_init(void)
{
	return tdx_debugfs_init();
}

void __exit tdx_exit(void)
{
	tdx_debugfs_exit();
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int i, max_pkgs;
	u32 max_pa;
	const struct tdsysinfo_struct *tdsysinfo = tdx_get_sysinfo();

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (tdsysinfo == NULL) {
		WARN_ON_ONCE(cpu_feature_enabled(X86_FEATURE_TDX));
		return -ENODEV;
	}

	if (WARN_ON_ONCE(x86_ops->tlb_remote_flush))
		return -EIO;

	tdx_caps.tdcs_nr_pages = tdsysinfo->tdcs_base_size / PAGE_SIZE;
	if (tdx_caps.tdcs_nr_pages != TDX_NR_TDCX_PAGES)
		return -EIO;

	tdx_caps.tdvpx_nr_pages = tdsysinfo->tdvps_base_size / PAGE_SIZE - 1;
	if (tdx_caps.tdvpx_nr_pages != TDX_NR_TDVPX_PAGES)
		return -EIO;

	tdx_caps.attrs_fixed0 = tdsysinfo->attributes_fixed0;
	tdx_caps.attrs_fixed1 = tdsysinfo->attributes_fixed1;
	tdx_caps.xfam_fixed0 =	tdsysinfo->xfam_fixed0;
	tdx_caps.xfam_fixed1 = tdsysinfo->xfam_fixed1;

	tdx_caps.nr_cpuid_configs = tdsysinfo->num_cpuid_config;
	if (tdx_caps.nr_cpuid_configs > TDX_MAX_NR_CPUID_CONFIGS)
		return -EIO;

	if (!memcpy(tdx_caps.cpuid_configs, tdsysinfo->cpuid_configs,
		    tdsysinfo->num_cpuid_config * sizeof(struct tdx_cpuid_config)))
		return -EIO;

	tdx_keyids_init();

	x86_ops->cache_gprs = tdx_cache_gprs;
	x86_ops->flush_gprs = tdx_flush_gprs;

	x86_ops->tlb_remote_flush = tdx_sept_tlb_remote_flush;
	x86_ops->set_private_spte = tdx_sept_set_private_spte;
	x86_ops->drop_private_spte = tdx_sept_drop_private_spte;
	x86_ops->zap_private_spte = tdx_sept_zap_private_spte;
	x86_ops->unzap_private_spte = tdx_sept_unzap_private_spte;
	x86_ops->link_private_sp = tdx_sept_link_private_sp;
	x86_ops->free_private_sp = tdx_sept_free_private_sp;
	x86_ops->split_private_spte = tdx_sept_split_private_spte;
	x86_ops->mem_enc_read_memory = tdx_read_guest_memory;
	x86_ops->mem_enc_write_memory = tdx_write_guest_memory;

	max_pkgs = topology_max_packages();

	tdx_mng_key_config_lock = kcalloc(max_pkgs, sizeof(*tdx_mng_key_config_lock),
				   GFP_KERNEL);
	if (!tdx_mng_key_config_lock) {
		kfree(tdx_mng_key_config_lock);
		return -ENOMEM;
	}
	for (i = 0; i < max_pkgs; i++)
		mutex_init(&tdx_mng_key_config_lock[i]);

	max_pa = cpuid_eax(0x80000008) & 0xff;
	hkid_start_pos = boot_cpu_data.x86_phys_bits;
	hkid_mask = GENMASK_ULL(max_pa - 1, hkid_start_pos);

	for (i = 0; i < ARRAY_SIZE(tdx_uret_msrs); i++) {
		tdx_uret_msrs[i].slot = kvm_find_user_return_msr(tdx_uret_msrs[i].msr);
		if (tdx_uret_msrs[i].slot == -1) {
			/* If any MSR isn't supported, it is a KVM bug */
			pr_err("MSR %x isn't included by kvm_find_user_return_msr\n",
				tdx_uret_msrs[i].msr);
			return -EIO;
		}
	}

	return 0;
}

#ifdef CONFIG_DEBUG_FS
static int print_severity_get(void *data, u64 *val)
{
	*val = trace_seamcalls;
	return 0;
}

static int print_severity_set(void *data, u64 val)
{
	int ret = -EINVAL;

	if (!cpu_feature_enabled(X86_FEATURE_TDX))
		return -EOPNOTSUPP;
	if (val == DEBUGCONFIG_TRACE_ALL ||
	    val == DEBUGCONFIG_TRACE_WARN ||
	    val == DEBUGCONFIG_TRACE_ERROR ||
	    val == DEBUGCONFIG_TRACE_CUSTOM ||
	    val == DEBUGCONFIG_TRACE_NONE) {
		kvm_hardware_enable_all();
		tdh_trace_seamcalls(val);
		kvm_hardware_disable_all();
		trace_seamcalls = val;
		ret = 0;
	}
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(print_severity_fops,
			 print_severity_get, print_severity_set, "%llu\n");

static int trace_target = DEBUGCONFIG_TARGET_SERIAL_PORT;

#define TRACE_BUFFER_SIZE	4096
#define MAX_PRINT_LENGTH	256
#define BUFFER_SIZE		(TRACE_BUFFER_SIZE * MAX_PRINT_LENGTH)
static char *buffer_trace;

static int trace_target_get(void *data, u64 *val)
{
	*val = trace_target;
	return 0;
}

static int trace_target_set(void *data, u64 val)
{
	int ret = -EINVAL;
	u64 err;
	u64 paddr = 0;

	if (!cpu_feature_enabled(X86_FEATURE_TDX))
		return -EOPNOTSUPP;

	switch (val) {
	case DEBUGCONFIG_TARGET_EXTERNAL_BUFFER:
		paddr = __pa(buffer_trace);
		fallthrough;
	case DEBUGCONFIG_TARGET_TRACE_BUFFER:
	case DEBUGCONFIG_TARGET_SERIAL_PORT:
		kvm_hardware_enable_all();
		err = tddebugconfig(DEBUGCONFIG_SET_TARGET, val, paddr);
		kvm_hardware_disable_all();
		if (err)
			pr_tdx_error(TDDEBUGCONFIG, err, NULL);
		else
			trace_target = val;
		ret = err;
		break;
	default:
		/* nothing */
		break;
	}
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(trace_target_fops,
			 trace_target_get, trace_target_set, "%llu\n");

static char *buffer_emergency;
static bool emergency_configured;

static int emergency_get(void *data, u64 *val)
{
	*val = emergency_configured;
	return 0;
}

static int emergency_set(void *data, u64 val)
{
	int ret = 0;

	if (!cpu_feature_enabled(X86_FEATURE_TDX))
		return -EOPNOTSUPP;

	/* emergency buffer can't be de-configured */
	if (!val && emergency_configured)
		return -EINVAL;

	memset(buffer_emergency, 0, BUFFER_SIZE);
	if (!emergency_configured) {
		u64 err;

		kvm_hardware_enable_all();
		err = tddebugconfig(DEBUGCONFIG_SET_EMERGENCY_BUFFER,
				    __pa(buffer_emergency),
				    TRACE_BUFFER_SIZE);
		kvm_hardware_disable_all();
		if ((s64)err < 0) {
			pr_tdx_error(TDDEBUGCONFIG, err, NULL);
			ret = (s64)err;
		} else
			ret = 0;

		emergency_configured = true;
	}
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(emergency_fops,
			 emergency_get, emergency_set, "%llu\n");

static char *buffer_dump;
static int dump_set(void *data, u64 val)
{
	int ret = -EINVAL;

	if (trace_target == DEBUGCONFIG_TARGET_TRACE_BUFFER) {
		u64 err;

		memset(buffer_dump, 0, BUFFER_SIZE);
		kvm_hardware_enable_all();
		err = tddebugconfig(DEBUGCONFIG_DUMP_TRACE_BUFFER,
				    __pa(buffer_dump), TRACE_BUFFER_SIZE);
		kvm_hardware_disable_all();
		if ((s64)err < 0) {
			pr_tdx_error(TDDEBUGCONFIG, err, NULL);
			ret = (s64)err;
		} else
			ret = 0;
	}
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(dump_fops, NULL, dump_set, "%llu\n");

static void *buffer_start(struct seq_file *sfile, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;
	if (*pos > TRACE_BUFFER_SIZE)
		return NULL;
	return pos;
}

static void *buffer_next(struct seq_file *sfile, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos > TRACE_BUFFER_SIZE)
		return NULL;
	return pos;
}

static void buffer_stop(struct seq_file *sfile, void *v)
{
}

static int buffer_show(struct seq_file *sfile, void *v)
{
	char *buffer = sfile->private;

	if (v == SEQ_START_TOKEN) {
		if (buffer == buffer_trace)
			seq_puts(sfile, "------- trace buffer ------\n");
		else if (buffer == buffer_dump)
			seq_puts(sfile, "------- dump  buffer ------\n");
		else
			seq_puts(sfile, "------- emerg buffer ------\n");
	} else {
		int index = *((loff_t *)v) - 1;
		const char *buf = &buffer[MAX_PRINT_LENGTH * index];

		seq_printf(sfile, "%."__stringify(MAX_PRINT_LENGTH)"s", buf);
	}
	return 0;
}

static const struct seq_operations buffer_sops = {
	.start = buffer_start,
	.next = buffer_next,
	.stop = buffer_stop,
	.show = buffer_show,
};

DEFINE_SEQ_ATTRIBUTE(buffer);

static struct dentry *tdx_seam;
#endif

static int __init tdx_debugfs_init(void)
{
	int ret = 0;
#ifdef CONFIG_DEBUG_FS
	if (!cpu_feature_enabled(X86_FEATURE_TDX) || !tdx_is_debug_seamcall_available)
		return 0;

	ret = -ENOMEM;
	buffer_trace = kcalloc(TRACE_BUFFER_SIZE, MAX_PRINT_LENGTH, GFP_KERNEL_ACCOUNT);
	if (!buffer_trace)
		goto err;

	buffer_emergency = kcalloc(TRACE_BUFFER_SIZE, MAX_PRINT_LENGTH, GFP_KERNEL_ACCOUNT);
	if (!buffer_emergency)
		goto err;

	buffer_dump = kcalloc(TRACE_BUFFER_SIZE, MAX_PRINT_LENGTH, GFP_KERNEL_ACCOUNT);
	if (!buffer_dump)
		goto err;

	tdx_seam = debugfs_create_dir("tdx_seam", NULL);

	debugfs_create_file("print_severity", 0600,
			    tdx_seam, NULL, &print_severity_fops);
	debugfs_create_file("trace_target", 0600,
			    tdx_seam, NULL, &trace_target_fops);
	debugfs_create_file("emergency", 0600,
			    tdx_seam, NULL, &emergency_fops);

	debugfs_create_file("dump", 0200,
			    tdx_seam, NULL, &dump_fops);
	debugfs_create_file("buffer_trace", 0400,
			    tdx_seam, buffer_trace, &buffer_fops);
	debugfs_create_file("buffer_dump", 0400,
			    tdx_seam, buffer_dump, &buffer_fops);
	debugfs_create_file("buffer_emergency", 0400,
			    tdx_seam, buffer_emergency, &buffer_fops);

	return 0;
err:
	kfree(buffer_trace);
	kfree(buffer_emergency);
	kfree(buffer_dump);
#endif
	return ret;
}

static void __exit tdx_debugfs_exit(void)
{
#ifdef CONFIG_DEBUG_FS
	if (buffer_trace)
		kvfree(buffer_trace);
	if (buffer_emergency)
		kvfree(buffer_emergency);
	if (buffer_dump)
		kvfree(buffer_dump);

	debugfs_remove_recursive(tdx_seam);
	tdx_seam = NULL;
#endif
}

/*
 * debug fs
 * - tdx_seam/print_severity
 *   0: TRACE_ALL
 *   1: TRACE_WARN
 *   2: TRACE_ERROR
 *   1000: TRACE_CUSTOM
 * - tdx_seam/trace_target
 *   0: TRACE_BUFFER: output to buffer internal to TDX module
 *   1: TRACE_SERIAL_PORT: output to serial port
 *   2: TRACE_EXTERNAL_BUFFER: output to VMM buffer which is external
 *                             to TDX module
 * - tdx_seam/emergency
 *   0: noop
 *   1: set emergency buffer
 *
 * - tdx_seam/dump
 *   dump buffer from internal buffer of tdx seam module to VMM buffer
 *   only when trace_target is TRACE_BUFFER
 *
 * - tdx_seam/buffer_trace
 *   read the buffer for trace
 * - tdx_seam/buffer_dump
 *   read the buffer dumped from buffer internal to TDX module
 * - tdx_seam/buffer_emergency
 *   read the buffer for emergency dump
 *
 * Usage example:
 *   # change print_severity
 *   echo 0 > /sys/kernel/debug/tdx_seam/print_severity
 *
 *   # set buffer in KVM and read the trace
 *   echo 2 > /sys/kernel/debug/tdx_seam/trace_target
 *   cat /sys/kernel/debug/tdx_seam/buffer_trace
 *
 *   # make tdx module to record in its internal buffer
 *   # and dump it into KVM buffer
 *   echo 0 > /sys/kernel/debug/tdx_seam/trace_target
 *   echo 1 > /sys/kernel/debug/tdx_seam/dump
 *   cat /sys/kernel/debug/tdx_seam/buffer_dump
 *
 *   # set emergency buffer
 *   echo 1 > /sys/kernel/debug/tdx_seam/emergency
 *   # after tdx seam module panics
 *   cat /sys/kernel/debug/tdx_seam/buffer_emergency
 */

/* backdoor ioctl for testing */
#ifdef CONFIG_KVM_TDX_SEAM_BACKDOOR
static int enable_tdx_seam_backdoor __read_mostly;
module_param_named(tdx_seam_backdoor, enable_tdx_seam_backdoor, bool, 0444);

void tdx_do_seamcall(struct kvm_seamcall *call)
{
	struct kvm_seamcall_regs *out = &call->out;
	struct kvm_seamcall_regs *in = &call->in;
	struct tdx_ex_ret ex;

	if (!enable_tdx_seam_backdoor) {
		WARN("KVM_SEAMCALL backdoor is not enabled. "
		     "ignoring the request");
		return;
	}

	WARN_ONCE(1, "KVM_SEAMCALL is an unsupported backdoor "
		  "only for development purpose."
		  "which can be eliminated anytime.");
	WARN_ON_ONCE(1);

	memset(&ex, 0, sizeof(ex));
	out->rax = seamcall(in->rax, in->rcx, in->rdx, in->r8, in->r9, in->r10,
			&ex);
	out->rcx = ex.regs.rcx;
	out->rdx = ex.regs.rdx;
	out->r8 = ex.regs.r8;
	out->r9 = ex.regs.r9;
	out->r10 = ex.regs.r10;
}

void tdx_do_tdenter(struct kvm_tdenter *tdenter)
{
	union tdx_exit_reason exit_reason;
	u64 *regs = tdenter->regs;

	if (!enable_tdx_seam_backdoor) {
		WARN("KVM_TDH_VP_ENTER backdoor is not enabled. "
		     "ignoring the request");
		return;
	}

	WARN_ONCE(1, "KVM_TDH_VP_ENTER is an unsupported backdoor "
		  "only for development purpose."
		  "which can be eliminated anytime.");
	WARN_ON_ONCE(1);

	preempt_disable();
	local_irq_disable();

	exit_reason.full = __tdx_vcpu_run(regs[VCPU_REGS_RAX], regs,
					  regs[VCPU_REGS_RCX]);

	/* __tdx_vcpu_run() doesn't bother saving RAX. */
	regs[VCPU_REGS_RAX] = exit_reason.full;
	if (exit_reason.error || exit_reason.non_recoverable)
		goto out;

	if (exit_reason.basic == EXIT_REASON_EXCEPTION_NMI &&
	    is_nmi(regs[VCPU_REGS_R9])) {
		asm("int $2");
	} else if (exit_reason.basic == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(NULL,
						     regs[VCPU_REGS_R9]);

out:
	local_irq_enable();
	preempt_enable();
}
#endif
