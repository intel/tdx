// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "tdx.h"
#include "vmx.h"
#include "x86.h"
#include "mmu.h"

#include <trace/events/kvm.h>
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

#define TDX_MAX_NR_CPUID_CONFIGS					\
	((sizeof(struct tdsysinfo_struct) -				\
		offsetof(struct tdsysinfo_struct, cpuid_configs))	\
		/ sizeof(struct tdx_cpuid_config))

struct tdx_capabilities {
	u8 tdcs_nr_pages;
	u8 tdvpx_nr_pages;

	u64 attrs_fixed0;
	u64 attrs_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;

	u32 nr_cpuid_configs;
	struct tdx_cpuid_config cpuid_configs[TDX_MAX_NR_CPUID_CONFIGS];
};

/* Capabilities of KVM + the TDX module. */
static struct tdx_capabilities tdx_caps;

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

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	return pa | ((hpa_t)hkid << boot_cpu_data.x86_phys_bits);
}

static inline bool is_td_vcpu_created(struct vcpu_tdx *tdx)
{
	return tdx->tdvpr.added;
}

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr.added;
}

static inline void tdx_hkid_free(struct kvm_tdx *kvm_tdx)
{
	tdx_keyid_free(kvm_tdx->hkid);
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

static void tdx_clear_page(unsigned long page)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	unsigned long i;

	/*
	 * Zeroing the page is only necessary for systems with MKTME-i:
	 * when re-assign one page from old keyid to a new keyid, MOVDIR64B is
	 * required to clear/write the page with new keyid to prevent integrity
	 * error when read on the page with new keyid.
	 *
	 * The cache line could be poisoned (even without MKTME-i), clear the
	 * poison bit.
	 */
	for (i = 0; i < PAGE_SIZE; i += 64)
		movdir64b((void *)(page + i), zero_page);
	/*
	 * MOVDIR64B store uses WC buffer.  Prevent following memory reads
	 * from seeing potentially poisoned cache.
	 */
	__mb();
}

static int tdx_reclaim_page(unsigned long va, hpa_t pa, bool do_wb, u16 hkid)
{
	struct tdx_module_output out;
	u64 err;

	do {
		err = tdh_phymem_page_reclaim(pa, &out);
		/*
		 * TDH.PHYMEM.PAGE.RECLAIM is allowed only when TD is shutdown.
		 * state.  i.e. destructing TD.
		 * TDH.PHYMEM.PAGE.RECLAIM  requires TDR and target page.
		 * Because we're destructing TD, it's rare to contend with TDR.
		 */
	} while (err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX));
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_RECLAIM, err, &out);
		return -EIO;
	}

	if (do_wb) {
		/*
		 * Only TDR page gets into this path.  No contention is expected
		 * because the last page of TD.
		 */
		err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(pa, hkid));
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			return -EIO;
		}
	}

	tdx_clear_page(va);
	return 0;
}

static int tdx_alloc_td_page(struct tdx_td_page *page)
{
	page->va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!page->va)
		return -ENOMEM;

	page->pa = __pa(page->va);
	return 0;
}

static inline void tdx_mark_td_page_added(struct tdx_td_page *page)
{
	WARN_ON_ONCE(page->added);
	page->added = true;
}

static void tdx_reclaim_td_page(struct tdx_td_page *page)
{
	if (page->added) {
		/*
		 * TDCX are being reclaimed.  TDX module maps TDCX with HKID
		 * assigned to the TD.  Here the cache associated to the TD
		 * was already flushed by TDH.PHYMEM.CACHE.WB before here, So
		 * cache doesn't need to be flushed again.
		 */
		if (tdx_reclaim_page(page->va, page->pa, false, 0))
			return;

		page->added = false;
	}
	if (page->va) {
		free_page(page->va);
		page->va = 0;
	}
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
	u64 err;
	int ret;
	int i;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	if (!is_td_created(kvm_tdx))
		goto free_hkid;

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
	err = tdh_mng_key_freeid(kvm_tdx->tdr.pa);
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

void tdx_vm_free(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int i;

	/* Can't reclaim or free TD pages if teardown failed. */
	if (is_hkid_assigned(kvm_tdx))
		return;

	if (kvm_tdx->tdcs) {
		for (i = 0; i < tdx_caps.tdcs_nr_pages; i++)
			tdx_reclaim_td_page(&kvm_tdx->tdcs[i]);
		kfree(kvm_tdx->tdcs);
	}

	/*
	 * TDX module maps TDR with TDX global HKID.  TDX module may access TDR
	 * while operating on TD (Especially reclaiming TDCS).  Cache flush with
	 * TDX global HKID is needed.
	 */
	if (kvm_tdx->tdr.added &&
		tdx_reclaim_page(kvm_tdx->tdr.va, kvm_tdx->tdr.pa, true,
				tdx_global_keyid))
		return;

	free_page(kvm_tdx->tdr.va);
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

	/* TODO: Enable 2mb and 1gb large page support. */
	kvm->arch.tdp_max_page_level = PG_LEVEL_4K;

	kvm_tdx->hkid = -1;

	/*
	 * This function initializes only KVM software construct.  It doesn't
	 * initialize TDX stuff, e.g. TDCS, TDR, TDCX, HKID etc.
	 * It is handled by KVM_TDX_INIT_VM, __tdx_td_init().
	 */

	return 0;
}

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	/* TDX only supports x2APIC, which requires an in-kernel local APIC. */
	if (!vcpu->arch.apic)
		return -EINVAL;

	fpstate_set_confidential(&vcpu->arch.guest_fpu);

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.cr0_guest_owned_bits = -1ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;

	vcpu->arch.tsc_offset = to_kvm_tdx(vcpu->kvm)->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG);

	return 0;
}

void tdx_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	/* Can't reclaim or free pages if teardown failed. */
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm)))
		return;

	if (tdx->tdvpx) {
		for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++)
			tdx_reclaim_td_page(&tdx->tdvpx[i]);
		kfree(tdx->tdvpx);
		tdx->tdvpx = NULL;
	}
	tdx_reclaim_td_page(&tdx->tdvpr);
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct msr_data apic_base_msr;

	/* TDX doesn't support INIT event. */
	if (WARN_ON_ONCE(init_event))
		goto td_bugged;
	if (WARN_ON_ONCE(is_td_vcpu_created(to_tdx(vcpu))))
		goto td_bugged;

	if (!vcpu->arch.cpuid_entries) {
		/*
		 * On cpu creation, cpuid entry is blank.  Forcibly enable
		 * X2APIC feature to allow X2APIC.
		 */
		struct kvm_cpuid_entry2 *e;

		e = kvmalloc_array(1, sizeof(*e), GFP_KERNEL_ACCOUNT);
		*e  = (struct kvm_cpuid_entry2) {
			.function = 1,	/* Features for X2APIC */
			.index = 0,
			.eax = 0,
			.ebx = 0,
			.ecx = 1ULL << 21,	/* X2APIC */
			.edx = 0,
		};
		vcpu->arch.cpuid_entries = e;
		vcpu->arch.cpuid_nent = 1;
	}

	/* TDX rquires X2APIC. */
	apic_base_msr.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC;
	if (kvm_vcpu_is_reset_bsp(vcpu))
		apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
	apic_base_msr.host_initiated = true;
	if (WARN_ON_ONCE(kvm_set_apic_base(vcpu, &apic_base_msr)))
		goto td_bugged;

	/*
	 * Don't update mp_state to runnable because more initialization
	 * is needed by TDX_VCPU_INIT.
	 */

	return;

td_bugged:
	vcpu->kvm->vm_bugged = true;
}

u64 __tdx_vcpu_run(hpa_t tdvpr, void *regs, u32 regs_mask);

static noinstr void tdx_vcpu_enter_exit(struct kvm_vcpu *vcpu,
					struct vcpu_tdx *tdx)
{
	guest_enter_irqoff();
	tdx->exit_reason.full = __tdx_vcpu_run(tdx->tdvpr.pa, vcpu->arch.regs, 0);
	guest_exit_irqoff();
}

fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (unlikely(vcpu->kvm->vm_bugged)) {
		tdx->exit_reason.full = TDX_NON_RECOVERABLE_VCPU;
		return EXIT_FASTPATH_NONE;
	}

	trace_kvm_entry(vcpu);

	tdx_vcpu_enter_exit(vcpu, tdx);

	vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;
	trace_kvm_exit(vcpu, KVM_ISA_VMX);

	return EXIT_FASTPATH_NONE;
}

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	td_vmcs_write64(to_tdx(vcpu), SHARED_EPT_POINTER, root_hpa & PAGE_MASK);
}

static void tdx_measure_page(struct kvm_tdx *kvm_tdx, hpa_t gpa)
{
	struct tdx_module_output out;
	u64 err;
	int i;

	for (i = 0; i < PAGE_SIZE; i += TDX_EXTENDMR_CHUNKSIZE) {
		err = tdh_mr_extend(kvm_tdx->tdr.pa, gpa + i, &out);
		if (KVM_BUG_ON(err, &kvm_tdx->kvm)) {
			pr_tdx_error(TDH_MR_EXTEND, err, &out);
			break;
		}
	}
}

static void tdx_unpin(struct kvm *kvm, kvm_pfn_t pfn)
{
	struct page *page = pfn_to_page(pfn);

	put_page(page);
}

static int tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
				     enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	hpa_t hpa = pfn_to_hpa(pfn);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	hpa_t source_pa;
	bool measure;
	u64 err;

	if (WARN_ON_ONCE(is_error_noslot_pfn(pfn) ||
			 !kvm_pfn_to_refcounted_page(pfn)))
		return 0;

	/* To prevent page migration, do nothing on mmu notifier. */
	get_page(pfn_to_page(pfn));

	/* Build-time faults are induced and handled via TDH_MEM_PAGE_ADD. */
	if (likely(is_td_finalized(kvm_tdx))) {
		/* TODO: handle large pages. */
		if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
			return -EINVAL;

		err = tdh_mem_page_aug(kvm_tdx->tdr.pa, gpa, hpa, &out);
		if (err == TDX_ERROR_SEPT_BUSY) {
			tdx_unpin(kvm, pfn);
			return -EAGAIN;
		}
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_AUG, err, &out);
			tdx_unpin(kvm, pfn);
			return -EIO;
		}
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
		tdx_unpin(kvm, pfn);
		return -EINVAL;
	}

	source_pa = kvm_tdx->source_pa & ~KVM_TDX_MEASURE_MEMORY_REGION;
	measure = kvm_tdx->source_pa & KVM_TDX_MEASURE_MEMORY_REGION;
	kvm_tdx->source_pa = INVALID_PAGE;

	do {
		err = tdh_mem_page_add(kvm_tdx->tdr.pa, gpa, hpa, source_pa,
				       &out);
		/*
		 * This path is executed during populating initial guest memory
		 * image. i.e. before running any vcpu.  Race is rare.
		 */
	} while (err == TDX_ERROR_SEPT_BUSY);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_ADD, err, &out);
		tdx_unpin(kvm, pfn);
		return -EIO;
	} else if (measure)
		tdx_measure_page(kvm_tdx, gpa);

	return 0;
}

static int tdx_sept_drop_private_spte(struct kvm *kvm, gfn_t gfn,
				       enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_module_output out;
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = pfn_to_hpa(pfn);
	hpa_t hpa_with_hkid;
	u64 err;

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return -EINVAL;

	if (!is_hkid_assigned(kvm_tdx)) {
		/*
		 * The HKID assigned to this TD was already freed and cache
		 * was already flushed. We don't have to flush again.
		 */
		err = tdx_reclaim_page((unsigned long)__va(hpa), hpa, false, 0);
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
		err = tdh_mem_page_remove(kvm_tdx->tdr.pa, gpa, tdx_level, &out);
	} while (err == TDX_ERROR_SEPT_BUSY);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_PAGE_REMOVE, err, &out);
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
	} while (err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX));
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
		return -EIO;
	}
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
	struct tdx_module_output out;
	u64 err;

	err = tdh_mem_sept_add(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &out);
	if (err == TDX_ERROR_SEPT_BUSY)
		return -EAGAIN;
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_ADD, err, &out);
		return -EIO;
	}

	return 0;
}

static int tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	u64 err;

	/* For now large page isn't supported yet. */
	WARN_ON_ONCE(level != PG_LEVEL_4K);
	err = tdh_mem_range_block(kvm_tdx->tdr.pa, gpa, tdx_level, &out);
	if (err == TDX_ERROR_SEPT_BUSY)
		return -EAGAIN;
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
		err = tdh_mem_track(kvm_tdx->tdr.pa);
	} while ((err & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_BUSY);

	/* Release remote vcpu waiting for TDH.MEM.TRACK in tdx_flush_tlb(). */
	atomic_dec(&kvm_tdx->tdh_mem_track);

	if (KVM_BUG_ON(err, &kvm_tdx->kvm))
		pr_tdx_error(TDH_MEM_TRACK, err, NULL);

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
		return tdx_reclaim_page((unsigned long)private_spt,
					__pa(private_spt), false, 0);

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

int tdx_sept_tlb_remote_flush(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx;

	if (!is_td(kvm))
		return -EOPNOTSUPP;

	kvm_tdx = to_kvm_tdx(kvm);
	if (is_hkid_assigned(kvm_tdx))
		tdx_track(kvm_tdx);

	return 0;
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
	 *   => tdx_sept_tlb_remote_flush_with_range(kvm, gfn,
	 *                                 KVM_PAGES_PER_HPAGE(level));
	 */
	if (is_hkid_assigned(to_kvm_tdx(kvm)))
		kvm_flush_remote_tlbs(kvm);

	return tdx_sept_drop_private_spte(kvm, gfn, level, pfn);
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
	if (cmd.flags || cmd.error || cmd.unused)
		return -EINVAL;
	/*
	 * Currently only KVM_TDX_CAPABILITIES is defined for system-scoped
	 * mem_enc_ioctl().
	 */
	if (cmd.id != KVM_TDX_CAPABILITIES)
		return -EINVAL;

	user_caps = (void __user *)cmd.data;
	if (copy_from_user(&caps, user_caps, sizeof(caps)))
		return -EFAULT;

	if (caps.nr_cpuid_configs < tdx_caps.nr_cpuid_configs)
		return -E2BIG;

	caps = (struct kvm_tdx_capabilities) {
		.attrs_fixed0 = tdx_caps.attrs_fixed0,
		.attrs_fixed1 = tdx_caps.attrs_fixed1,
		.xfam_fixed0 = tdx_caps.xfam_fixed0,
		.xfam_fixed1 = tdx_caps.xfam_fixed1,
		.nr_cpuid_configs = tdx_caps.nr_cpuid_configs,
		.padding = 0,
	};

	if (copy_to_user(user_caps, &caps, sizeof(caps)))
		return -EFAULT;
	if (copy_to_user(user_caps->cpuid_configs, &tdx_caps.cpuid_configs,
			 tdx_caps.nr_cpuid_configs *
			 sizeof(struct tdx_cpuid_config)))
		return -EFAULT;

	return 0;
}

/*
 * cpuid entry lookup in TDX cpuid config way.
 * The difference is how to specify index(subleaves).
 * Specify index to TDX_CPUID_NO_SUBLEAF for CPUID leaf with no-subleaves.
 */
static const struct kvm_cpuid_entry2 *tdx_find_cpuid_entry(const struct kvm_cpuid2 *cpuid,
							   u32 function, u32 index)
{
	int i;

	/* In TDX CPU CONFIG, TDX_CPUID_NO_SUBLEAF means index = 0. */
	if (index == TDX_CPUID_NO_SUBLEAF)
		index = 0;

	for (i = 0; i < cpuid->nent; i++) {
		const struct kvm_cpuid_entry2 *e = &cpuid->entries[i];

		if (e->function == function &&
		    (e->index == index ||
		     !(e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)))
			return e;
	}
	return NULL;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params,
			struct kvm_tdx_init_vm *init_vm)
{
	const struct kvm_cpuid2 *cpuid = &init_vm->cpuid;
	const struct kvm_cpuid_entry2 *entry;
	u64 guest_supported_xcr0;
	u64 guest_supported_xss;
	int max_pa;
	int i;

	if (kvm->created_vcpus)
		return -EBUSY;
	td_params->max_vcpus = kvm->max_vcpus;
	td_params->attributes = init_vm->attributes;
	if (td_params->attributes & TDX_TD_ATTRIBUTE_PERFMON) {
		/*
		 * TODO: save/restore PMU related registers around TDENTER.
		 * Once it's done, remove this guard.
		 */
		pr_warn("TD doesn't support perfmon yet. KVM needs to save/restore "
			"host perf registers properly.\n");
		return -EOPNOTSUPP;
	}

	for (i = 0; i < tdx_caps.nr_cpuid_configs; i++) {
		const struct tdx_cpuid_config *config = &tdx_caps.cpuid_configs[i];
		const struct kvm_cpuid_entry2 *entry =
			tdx_find_cpuid_entry(cpuid, config->leaf, config->sub_leaf);
		struct tdx_cpuid_value *value = &td_params->cpuid_values[i];

		if (!entry)
			continue;

		value->eax = entry->eax & config->eax;
		value->ebx = entry->ebx & config->ebx;
		value->ecx = entry->ecx & config->ecx;
		value->edx = entry->edx & config->edx;
	}

	max_pa = 36;
	entry = tdx_find_cpuid_entry(cpuid, 0x80000008, 0);
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
	if (cpu_has_vmx_ept_5levels() && max_pa > 48) {
		td_params->eptp_controls |= VMX_EPTP_PWL_5;
		td_params->exec_controls |= TDX_EXEC_CONTROL_MAX_GPAW;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
	}

	/* Setup td_params.xfam */
	entry = tdx_find_cpuid_entry(cpuid, 0xd, 0);
	if (entry)
		guest_supported_xcr0 = (entry->eax | ((u64)entry->edx << 32));
	else
		guest_supported_xcr0 = 0;
	guest_supported_xcr0 &= kvm_caps.supported_xcr0;

	entry = tdx_find_cpuid_entry(cpuid, 0xd, 1);
	if (entry)
		guest_supported_xss = (entry->ecx | ((u64)entry->edx << 32));
	else
		guest_supported_xss = 0;
	/* PT can be exposed to TD guest regardless of KVM's XSS support */
	guest_supported_xss &= (kvm_caps.supported_xss | XFEATURE_MASK_PT);

	td_params->xfam = guest_supported_xcr0 | guest_supported_xss;
	if (td_params->xfam & XFEATURE_MASK_LBR) {
		/*
		 * TODO: once KVM supports LBR(save/restore LBR related
		 * registers around TDENTER), remove this guard.
		 */
		pr_warn("TD doesn't support LBR yet. KVM needs to save/restore "
			"IA32_LBR_DEPTH properly.\n");
		return -EOPNOTSUPP;
	}

	if (td_params->xfam & XFEATURE_MASK_XTILE) {
		/*
		 * TODO: once KVM supports AMX(save/restore AMX related
		 * registers around TDENTER), remove this guard.
		 */
		pr_warn("TD doesn't support AMX yet. KVM needs to save/restore "
			"IA32_XFD, IA32_XFD_ERR properly.\n");
		return -EOPNOTSUPP;
	}

	td_params->tsc_frequency =
		TDX_TSC_KHZ_TO_25MHZ(kvm->arch.default_tsc_khz);

#define MEMCPY_SAME_SIZE(dst, src)				\
	do {							\
		BUILD_BUG_ON(sizeof(dst) != sizeof(src));	\
		memcpy((dst), (src), sizeof(dst));		\
	} while (0)

	MEMCPY_SAME_SIZE(td_params->mrconfigid, init_vm->mrconfigid);
	MEMCPY_SAME_SIZE(td_params->mrowner, init_vm->mrowner);
	MEMCPY_SAME_SIZE(td_params->mrownerconfig, init_vm->mrownerconfig);

	return 0;
}

static int __tdx_td_init(struct kvm *kvm, struct td_params *td_params)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_module_output out;
	cpumask_var_t packages;
	int ret, i;
	u64 err;

	ret = tdx_keyid_alloc();
	if (ret < 0)
		return ret;
	kvm_tdx->hkid = ret;

	ret = tdx_alloc_td_page(&kvm_tdx->tdr);
	if (ret)
		goto free_hkid;

	kvm_tdx->tdcs = kcalloc(tdx_caps.tdcs_nr_pages, sizeof(*kvm_tdx->tdcs),
				GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!kvm_tdx->tdcs)
		goto free_tdr;
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		ret = tdx_alloc_td_page(&kvm_tdx->tdcs[i]);
		if (ret)
			goto free_tdcs;
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
		pr_warn("All packages need to have online CPU to create TD. Online CPU and retry.\n");
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
	err = tdh_mng_create(kvm_tdx->tdr.pa, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_CREATE, err, NULL);
		ret = -EIO;
		goto free_packages;
	}
	tdx_mark_td_page_added(&kvm_tdx->tdr);

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
				      &kvm_tdx->tdr.pa, true);
		mutex_unlock(&tdx_mng_key_config_lock[pkg]);
		if (ret)
			break;
	}
	if (!ret)
		atomic_inc(&nr_configured_hkid);
	cpus_read_unlock();
	free_cpumask_var(packages);
	if (ret)
		goto teardown;

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx->tdr.pa, kvm_tdx->tdcs[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err, NULL);
			ret = -EIO;
			goto teardown;
		}
		tdx_mark_td_page_added(&kvm_tdx->tdcs[i]);
	}

	err = tdh_mng_init(kvm_tdx->tdr.pa, __pa(td_params), &out);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_INIT, err, &out);
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
	tdx_mmu_release_hkid(kvm);
	tdx_vm_free(kvm);
	return ret;

free_packages:
	cpus_read_unlock();
	free_cpumask_var(packages);
free_tdcs:
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		if (!kvm_tdx->tdcs[i].va)
			continue;
		free_page(kvm_tdx->tdcs[i].va);
	}
	kfree(kvm_tdx->tdcs);
	kvm_tdx->tdcs = NULL;
free_tdr:
	if (kvm_tdx->tdr.va) {
		free_page(kvm_tdx->tdr.va);
		kvm_tdx->tdr.added = false;
		kvm_tdx->tdr.va = 0;
		kvm_tdx->tdr.pa = 0;
	}
free_hkid:
	if (kvm_tdx->hkid != -1)
		tdx_hkid_free(kvm_tdx);
	return ret;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_vm *init_vm = NULL;
	struct td_params *td_params = NULL;
	void *entries_end;
	int ret;

	BUILD_BUG_ON(sizeof(*init_vm) != 16 * 1024);
	BUILD_BUG_ON((sizeof(*init_vm) - offsetof(typeof(*init_vm), entries)) /
		     sizeof(init_vm->entries[0]) < KVM_MAX_CPUID_ENTRIES);
	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	if (is_td_initialized(kvm))
		return -EINVAL;

	if (cmd->flags)
		return -EINVAL;

	init_vm = kzalloc(sizeof(*init_vm), GFP_KERNEL);
	if (copy_from_user(init_vm, (void __user *)cmd->data, sizeof(*init_vm))) {
		ret = -EFAULT;
		goto out;
	}

	ret = -EINVAL;
	if (init_vm->cpuid.padding)
		goto out;
	/* init_vm->entries shouldn't overrun. */
	entries_end = init_vm->entries + init_vm->cpuid.nent;
	if (entries_end > (void *)(init_vm + 1))
		goto out;
	/* Unused part must be zero. */
	if (memchr_inv(entries_end, 0, (void *)(init_vm + 1) - entries_end))
		goto out;

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL);
	if (!td_params) {
		ret = -ENOMEM;
		goto out;
	}

	ret = setup_tdparams(kvm, td_params, init_vm);
	if (ret)
		goto out;

	ret = __tdx_td_init(kvm, td_params);
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
	kfree(init_vm);
	kfree(td_params);
	return ret;
}

void tdx_flush_tlb(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	u64 root_hpa = mmu->root.hpa;

	/* Flush the shared EPTP, if it's valid. */
	if (VALID_PAGE(root_hpa))
		ept_sync_context(construct_eptp(vcpu, root_hpa,
						mmu->root_role.level));

	/*
	 * See tdx_track().  Wait for tlb shootdown initiater to finish
	 * TDH_MEM_TRACK() so that TLB is flushed on the next TDENTER.
	 */
	while (atomic_read(&kvm_tdx->tdh_mem_track))
		cpu_relax();
}

#define TDX_SEPT_PFERR	PFERR_WRITE_MASK

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

	/*
	 * Blindly do TDH_MEM_TRACK after finalizing the measurement to handle
	 * the case where SEPT entries were zapped/blocked, e.g. from failed
	 * NUMA balancing, after they were added to the TD via
	 * tdx_init_mem_region().  TDX module doesn't allow TDH_MEM_TRACK prior
	 * to TDH.MR.FINALIZE, and conversely requires TDH.MEM.TRACK for entries
	 * that were TDH.MEM.RANGE.BLOCK'd prior to TDH.MR.FINALIZE.
	 */
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
	if (tdx_cmd.error || tdx_cmd.unused)
		return -EINVAL;

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

static int tdx_td_vcpu_init(struct kvm_vcpu *vcpu, u64 vcpu_rcx)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int ret, i;
	u64 err;

	if (is_td_vcpu_created(tdx))
		return -EINVAL;

	ret = tdx_alloc_td_page(&tdx->tdvpr);
	if (ret)
		return ret;

	tdx->tdvpx = kcalloc(tdx_caps.tdvpx_nr_pages, sizeof(*tdx->tdvpx),
			     GFP_KERNEL_ACCOUNT);
	if (!tdx->tdvpx) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}
	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		ret = tdx_alloc_td_page(&tdx->tdvpx[i]);
		if (ret)
			goto free_tdvpx;
	}

	err = tdh_vp_create(kvm_tdx->tdr.pa, tdx->tdvpr.pa);
	if (WARN_ON_ONCE(err)) {
		ret = -EIO;
		pr_tdx_error(TDH_VP_CREATE, err, NULL);
		goto td_bugged;
	}
	tdx_mark_td_page_added(&tdx->tdvpr);

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		err = tdh_vp_addcx(tdx->tdvpr.pa, tdx->tdvpx[i].pa);
		if (WARN_ON_ONCE(err)) {
			ret = -EIO;
			pr_tdx_error(TDH_VP_ADDCX, err, NULL);
			goto td_bugged;
		}
		tdx_mark_td_page_added(&tdx->tdvpx[i]);
	}

	err = tdh_vp_init(tdx->tdvpr.pa, vcpu_rcx);
	if (WARN_ON_ONCE(err)) {
		ret = -EIO;
		pr_tdx_error(TDH_VP_INIT, err, NULL);
		goto td_bugged;
	}

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

	return 0;

td_bugged:
	vcpu->kvm->vm_bugged = true;
	return ret;

free_tdvpx:
	/* @i points at the TDVPX page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(tdx->tdvpx[i].va);
	kfree(tdx->tdvpx);
	tdx->tdvpx = NULL;
free_tdvpr:
	free_page(tdx->tdvpr.va);

	return ret;
}

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct kvm_tdx_cmd cmd;
	int ret;

	if (tdx->vcpu_initialized)
		return -EINVAL;

	if (!is_td_initialized(vcpu->kvm) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.error || cmd.unused)
		return -EINVAL;

	/* Currently only KVM_TDX_INTI_VCPU is defined for vcpu operation. */
	if (cmd.flags || cmd.id != KVM_TDX_INIT_VCPU)
		return -EINVAL;

	ret = tdx_td_vcpu_init(vcpu, (u64)cmd.data);
	if (ret)
		return ret;

	tdx->vcpu_initialized = true;
	return 0;
}

static int __init tdx_module_setup(void)
{
	const struct tdsysinfo_struct *tdsysinfo;
	int ret = 0;

	BUILD_BUG_ON(sizeof(*tdsysinfo) != 1024);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

	ret = tdx_enable();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		return ret;
	}

	tdsysinfo = tdx_get_sysinfo();
	if (tdsysinfo->num_cpuid_config > TDX_MAX_NR_CPUID_CONFIGS)
		return -EIO;

	tdx_caps = (struct tdx_capabilities) {
		.tdcs_nr_pages = tdsysinfo->tdcs_base_size / PAGE_SIZE,
		/*
		 * TDVPS = TDVPR(4K page) + TDVPX(multiple 4K pages).
		 * -1 for TDVPR.
		 */
		.tdvpx_nr_pages = tdsysinfo->tdvps_base_size / PAGE_SIZE - 1,
		.attrs_fixed0 = tdsysinfo->attributes_fixed0,
		.attrs_fixed1 = tdsysinfo->attributes_fixed1,
		.xfam_fixed0 =	tdsysinfo->xfam_fixed0,
		.xfam_fixed1 = tdsysinfo->xfam_fixed1,
		.nr_cpuid_configs = tdsysinfo->num_cpuid_config,
	};
	if (!memcpy(tdx_caps.cpuid_configs, tdsysinfo->cpuid_configs,
			tdsysinfo->num_cpuid_config *
			sizeof(struct tdx_cpuid_config)))
		return -EIO;

	pr_info("kvm: TDX is supported. x86 phys bits %d\n",
		boot_cpu_data.x86_phys_bits);

	return 0;
}

bool tdx_is_vm_type_supported(unsigned long type)
{
	/* enable_tdx check is done by the caller. */
	return type == KVM_X86_TDX_VM;
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int max_pkgs;
	int i;
	int r;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	/* MOVDIR64B instruction is needed. */
	if (!static_cpu_has(X86_FEATURE_MOVDIR64B)) {
		pr_warn("Cannot enable TDX with MOVDIR64B supported ");
		return -ENODEV;
	}

	max_pkgs = topology_max_packages();
	tdx_mng_key_config_lock = kcalloc(max_pkgs, sizeof(*tdx_mng_key_config_lock),
				   GFP_KERNEL);
	if (!tdx_mng_key_config_lock)
		return -ENOMEM;
	for (i = 0; i < max_pkgs; i++)
		mutex_init(&tdx_mng_key_config_lock[i]);

	/* TDX requires VMX. */
	r = vmxon_all();
	if (!r)
		r = tdx_module_setup();
	vmxoff_all();
	if (r)
		return r;

	x86_ops->link_private_spt = tdx_sept_link_private_spt;
	x86_ops->free_private_spt = tdx_sept_free_private_spt;
	x86_ops->set_private_spte = tdx_sept_set_private_spte;
	x86_ops->remove_private_spte = tdx_sept_remove_private_spte;
	x86_ops->zap_private_spte = tdx_sept_zap_private_spte;

	return 0;
}

void tdx_hardware_unsetup(void)
{
	/* kfree accepts NULL. */
	kfree(tdx_mng_key_config_lock);
}

int tdx_offline_cpu(void)
{
	int curr_cpu = smp_processor_id();
	cpumask_var_t packages;
	int ret = 0;
	int i;

	if (!atomic_read(&nr_configured_hkid))
		return 0;

	/*
	 * To reclaim hkid, need to call TDH.PHYMEM.PAGE.WBINVD on all packages.
	 * If this is the last online cpu on the package, refuse offline.
	 */
	if (!zalloc_cpumask_var(&packages, GFP_KERNEL))
		return -ENOMEM;

	for_each_online_cpu(i) {
		if (i != curr_cpu)
			cpumask_set_cpu(topology_physical_package_id(i), packages);
	}
	if (!cpumask_test_cpu(topology_physical_package_id(curr_cpu), packages))
		ret = -EBUSY;
	free_cpumask_var(packages);
	if (ret)
		/*
		 * Because it's hard for human operator to understand the
		 * reason, warn it.
		 */
		pr_warn("TDX requires all packages to have an online CPU.  "
			"Delete all TDs in order to offline all CPUs of a package.\n");
	return ret;
}
