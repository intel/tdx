// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "mmu.h"
#include "tdx.h"
#include "vmx.h"
#include "x86.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

bool __read_mostly enable_tdx = true;
module_param_named(tdx, enable_tdx, bool, 0644);

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

/* KeyID used by TDX module */
static u32 tdx_global_keyid __read_mostly;

/* Capabilities of KVM + the TDX module. */
struct tdx_capabilities tdx_caps;

static DEFINE_MUTEX(tdx_lock);
static struct mutex *tdx_mng_key_config_lock;

static u64 hkid_mask __ro_after_init;
static u8 hkid_start_pos __ro_after_init;

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	pa &= ~hkid_mask;
	pa |= (u64)hkid << hkid_start_pos;

	return pa;
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

	/* Zeroing the page is only necessary for systems with MKTME-i. */
	if (!static_cpu_has(X86_FEATURE_MOVDIR64B))
		return;

	for (i = 0; i < 4096; i += 64)
		/* MOVDIR64B [rdx], es:rdi */
		asm (".byte 0x66, 0x0f, 0x38, 0xf8, 0x3a"
		     : : "d" (zero_page), "D" (page + i) : "memory");
}

static int __tdx_reclaim_page(unsigned long va, hpa_t pa, bool do_wb, u16 hkid)
{
	struct tdx_module_output out;
	u64 err;

	err = tdh_phymem_page_reclaim(pa, &out);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_RECLAIM, err, &out);
		return -EIO;
	}

	if (do_wb) {
		err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(pa, hkid));
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			return -EIO;
		}
	}

	tdx_clear_page(va);
	return 0;
}

static int tdx_reclaim_page(unsigned long va, hpa_t pa)
{
	return __tdx_reclaim_page(va, pa, false, 0);
}

static int tdx_alloc_td_page(struct tdx_td_page *page)
{
	page->va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!page->va)
		return -ENOMEM;

	page->pa = __pa(page->va);
	return 0;
}

static void tdx_mark_td_page_added(struct tdx_td_page *page)
{
	WARN_ON_ONCE(page->added);
	page->added = true;
}

static void tdx_reclaim_td_page(struct tdx_td_page *page)
{
	if (page->added) {
		if (tdx_reclaim_page(page->va, page->pa))
			return;

		page->added = false;
	}
	free_page(page->va);
}

static int tdx_do_tdh_phymem_cache_wb(void *param)
{
	u64 err = 0;

	/*
	 * We can destroy multiple the guest TDs simultaneously.  Prevent
	 * tdh_phymem_cache_wb from returning TDX_BUSY by serialization.
	 */
	mutex_lock(&tdx_lock);
	do {
		err = tdh_phymem_cache_wb(!!err);
	} while (err == TDX_INTERRUPTED_RESUMABLE);
	mutex_unlock(&tdx_lock);

	/* Other thread may have done for us. */
	if (err == TDX_NO_HKID_READY_TO_WBCACHE)
		err = TDX_SUCCESS;
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_CACHE_WB, err, NULL);
		return -EIO;
	}

	return 0;
}

void tdx_mmu_prezap(struct kvm *kvm)
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

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_reclaimid(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_RECLAIMID, err, NULL);
		pr_err("tdh_mng_key_reclaimid failed. HKID %d is leaked.\n",
			kvm_tdx->hkid);
		return;
	}

	cpumask_allocated = zalloc_cpumask_var(&packages, GFP_KERNEL);
	for_each_online_cpu(i) {
		if (cpumask_allocated &&
			cpumask_test_and_set_cpu(topology_physical_package_id(i),
						packages))
			continue;

		ret = smp_call_on_cpu(i, tdx_do_tdh_phymem_cache_wb, NULL, 1);
		if (ret)
			break;
	}
	free_cpumask_var(packages);

	mutex_lock(&tdx_lock);
	err = tdh_mng_key_freeid(kvm_tdx->tdr.pa);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err, NULL);
		pr_err("tdh_mng_key_freeid failed. HKID %d is leaked.\n",
			kvm_tdx->hkid);
		return;
	}

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

	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++)
		tdx_reclaim_td_page(&kvm_tdx->tdcs[i]);
	kfree(kvm_tdx->tdcs);

	if (kvm_tdx->tdr.added &&
		__tdx_reclaim_page(kvm_tdx->tdr.va, kvm_tdx->tdr.pa, true,
				tdx_global_keyid))
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

	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_CONFIG, err, NULL);
		return -EIO;
	}

	return 0;
}

int tdx_vm_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	int ret, i;
	u64 err;

	/*
	 * To generate EPT violation to inject #VE instead of EPT MISCONFIG,
	 * set RWX=0.
	 */
	kvm_mmu_set_mmio_spte_mask(kvm, 0, VMX_EPT_RWX_MASK, 0);

	/* TODO: Enable 2mb and 1gb large page support. */
	kvm->arch.tdp_max_page_level = PG_LEVEL_4K;

	/* vCPUs can't be created until after KVM_TDX_INIT_VM. */
	kvm->max_vcpus = 0;

	kvm_tdx->hkid = tdx_keyid_alloc();
	if (kvm_tdx->hkid < 0)
		return -EBUSY;

	ret = tdx_alloc_td_page(&kvm_tdx->tdr);
	if (ret)
		goto free_hkid;

	kvm_tdx->tdcs = kcalloc(tdx_caps.tdcs_nr_pages, sizeof(*kvm_tdx->tdcs),
				GFP_KERNEL_ACCOUNT);
	if (!kvm_tdx->tdcs)
		goto free_tdr;
	for (i = 0; i < tdx_caps.tdcs_nr_pages; i++) {
		ret = tdx_alloc_td_page(&kvm_tdx->tdcs[i]);
		if (ret)
			goto free_tdcs;
	}

	mutex_lock(&tdx_lock);
	err = tdh_mng_create(kvm_tdx->tdr.pa, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_CREATE, err, NULL);
		ret = -EIO;
		goto free_tdcs;
	}
	tdx_mark_td_page_added(&kvm_tdx->tdr);

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_tdcs;
	}
	for_each_online_cpu(i) {
		if (cpumask_test_and_set_cpu(topology_physical_package_id(i),
						packages))
			continue;

		ret = smp_call_on_cpu(i, tdx_do_tdh_mng_key_config,
				&kvm_tdx->tdr.pa, 1);
		if (ret)
			break;
	}
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
	tdx_mmu_prezap(kvm);
	tdx_vm_free(kvm);
	return ret;

free_tdcs:
	/* @i points at the TDCS page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(kvm_tdx->tdcs[i].va);
	kfree(kvm_tdx->tdcs);
free_tdr:
	free_page(kvm_tdx->tdr.va);
free_hkid:
	tdx_hkid_free(kvm_tdx);
	return ret;
}

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int ret, i;

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

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.cr0_guest_owned_bits = -1ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;

	vcpu->arch.tsc_offset = to_kvm_tdx(vcpu->kvm)->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTRIBUTE_DEBUG);

	return 0;

free_tdvpx:
	/* @i points at the TDVPX page that failed allocation. */
	for (--i; i >= 0; i--)
		free_page(tdx->tdvpx[i].va);
	kfree(tdx->tdvpx);
free_tdvpr:
	free_page(tdx->tdvpr.va);

	return ret;
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
	kfree(tdx->tdvpx);
	tdx_reclaim_td_page(&tdx->tdvpr);
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct msr_data apic_base_msr;
	u64 err;
	int i;

	/* TDX doesn't support INIT event. */
	if (WARN_ON(init_event))
		goto td_bugged;
	/* TDX supports only X2APIC enabled. */
	if (WARN_ON(!vcpu->arch.apic))
		goto td_bugged;
	if (WARN_ON(is_td_vcpu_created(tdx)))
		goto td_bugged;

	/*
	 * In TDX case, tsc frequency is per-VM and determined by the parameter
	 * tdh_mng_init().  Forcibly set it instead of max_tsc_khz set by
	 * kvm_arch_vcpu_create().
	 *
	 * This function is called after kvm_arch_vcpu_create() calling
	 * kvm_set_tsc_khz().
	 */
	kvm_set_tsc_khz(vcpu, kvm_tdx->tsc_khz);

	err = tdh_vp_create(kvm_tdx->tdr.pa, tdx->tdvpr.pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_VP_CREATE, err, NULL);
		goto td_bugged;
	}
	tdx_mark_td_page_added(&tdx->tdvpr);

	for (i = 0; i < tdx_caps.tdvpx_nr_pages; i++) {
		err = tdh_vp_addcx(tdx->tdvpr.pa, tdx->tdvpx[i].pa);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_VP_ADDCX, err, NULL);
			goto td_bugged;
		}
		tdx_mark_td_page_added(&tdx->tdvpx[i]);
	}

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
	apic_base_msr.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC;
	if (kvm_vcpu_is_reset_bsp(vcpu))
		apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
	apic_base_msr.host_initiated = true;
	if (WARN_ON(kvm_set_apic_base(vcpu, &apic_base_msr)))
		goto td_bugged;

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

	return;

td_bugged:
	vcpu->kvm->vm_bugged = true;
}

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	td_vmcs_write64(to_tdx(vcpu), SHARED_EPT_POINTER, root_hpa & PAGE_MASK);
}

static void __tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
					enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	hpa_t hpa = pfn_to_hpa(pfn);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	u64 err;

	if (WARN_ON_ONCE(is_error_noslot_pfn(pfn) || kvm_is_reserved_pfn(pfn)))
		return;

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return;

	/* Pin the page, TDX KVM doesn't yet support page migration. */
	get_page(pfn_to_page(pfn));

	if (likely(is_td_finalized(kvm_tdx))) {
		err = tdh_mem_page_aug(kvm_tdx->tdr.pa, gpa, hpa, &out);
		if (KVM_BUG_ON(err, kvm))
			pr_tdx_error(TDH_MEM_PAGE_AUG, err, &out);
		return;
	}
}

static void tdx_sept_set_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level, kvm_pfn_t pfn)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);

	spin_lock(&kvm_tdx->seamcall_lock);
	__tdx_sept_set_private_spte(kvm, gfn, level, pfn);
	spin_unlock(&kvm_tdx->seamcall_lock);
}

static void tdx_sept_drop_private_spte(
	struct kvm *kvm, gfn_t gfn, enum pg_level level, kvm_pfn_t pfn)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = pfn_to_hpa(pfn);
	hpa_t hpa_with_hkid;
	struct tdx_module_output out;
	u64 err = 0;

	/* TODO: handle large pages. */
	if (KVM_BUG_ON(level != PG_LEVEL_4K, kvm))
		return;

	spin_lock(&kvm_tdx->seamcall_lock);
	if (is_hkid_assigned(kvm_tdx)) {
		err = tdh_mem_page_remove(kvm_tdx->tdr.pa, gpa, tdx_level, &out);
		if (KVM_BUG_ON(err, kvm)) {
			pr_tdx_error(TDH_MEM_PAGE_REMOVE, err, &out);
			goto unlock;
		}

		hpa_with_hkid = set_hkid_to_hpa(hpa, (u16)kvm_tdx->hkid);
		err = tdh_phymem_page_wbinvd(hpa_with_hkid);
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err, NULL);
			goto unlock;
		}
	} else
		err = tdx_reclaim_page((unsigned long)__va(hpa), hpa);

unlock:
	spin_unlock(&kvm_tdx->seamcall_lock);

	if (!err)
		put_page(pfn_to_page(pfn));
}

static int tdx_sept_link_private_sp(struct kvm *kvm, gfn_t gfn,
				    enum pg_level level, void *sept_page)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	hpa_t hpa = __pa(sept_page);
	struct tdx_module_output out;
	u64 err;

	spin_lock(&kvm_tdx->seamcall_lock);
	err = tdh_mem_sept_add(kvm_tdx->tdr.pa, gpa, tdx_level, hpa, &out);
	spin_unlock(&kvm_tdx->seamcall_lock);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MEM_SEPT_ADD, err, &out);
		return -EIO;
	}

	return 0;
}

static void tdx_sept_zap_private_spte(struct kvm *kvm, gfn_t gfn,
				      enum pg_level level)
{
	int tdx_level = pg_level_to_tdx_sept_level(level);
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	gpa_t gpa = gfn_to_gpa(gfn);
	struct tdx_module_output out;
	u64 err;

	/* For now large page isn't supported yet. */
	WARN_ON_ONCE(level != PG_LEVEL_4K);
	spin_lock(&kvm_tdx->seamcall_lock);
	err = tdh_mem_range_block(kvm_tdx->tdr.pa, gpa, tdx_level, &out);
	spin_unlock(&kvm_tdx->seamcall_lock);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_RANGE_BLOCK, err, &out);
}

static int tdx_sept_free_private_sp(struct kvm *kvm, gfn_t gfn, enum pg_level level,
				    void *sept_page)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int ret;

	/*
	 * free_private_sp() is (obviously) called when a shadow page is being
	 * zapped.  KVM doesn't (yet) zap private SPs while the TD is active.
	 */
	if (KVM_BUG_ON(is_hkid_assigned(to_kvm_tdx(kvm)), kvm))
		return -EINVAL;

	spin_lock(&kvm_tdx->seamcall_lock);
	ret = tdx_reclaim_page((unsigned long)sept_page, __pa(sept_page));
	spin_unlock(&kvm_tdx->seamcall_lock);

	return ret;
}

static int tdx_sept_tlb_remote_flush(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx;
	u64 err;

	lockdep_assert_held_write(&kvm->mmu_lock);
	if (!is_td(kvm))
		return -EOPNOTSUPP;

	kvm_tdx = to_kvm_tdx(kvm);
	if (!is_hkid_assigned(kvm_tdx))
		return 0;

	/* If TD isn't finalized, it's before any vcpu running. */
	if (unlikely(!is_td_finalized(kvm_tdx)))
		return 0;

	kvm_tdx->tdh_mem_track = true;

	kvm_make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH);

	err = tdh_mem_track(kvm_tdx->tdr.pa);
	if (KVM_BUG_ON(err, kvm))
		pr_tdx_error(TDH_MEM_TRACK, err, NULL);

	WRITE_ONCE(kvm_tdx->tdh_mem_track, false);

	return 0;
}

static void tdx_handle_changed_private_spte(
	struct kvm *kvm, gfn_t gfn, enum pg_level level,
	kvm_pfn_t old_pfn, bool was_present, bool was_leaf,
	kvm_pfn_t new_pfn, bool is_present, bool is_leaf, void *sept_page)
{
	WARN_ON(!is_td(kvm));
	lockdep_assert_held(&kvm->mmu_lock);

	if (is_present) {
		/* TDP MMU doesn't change present -> present */
		WARN_ON(was_present);

		/*
		 * Use different call to either set up middle level
		 * private page table, or leaf.
		 */
		if (is_leaf)
			tdx_sept_set_private_spte(kvm, gfn, level, new_pfn);
		else {
			WARN_ON(!sept_page);
			if (tdx_sept_link_private_sp(kvm, gfn, level, sept_page))
				/* failed to update Secure-EPT.  */
				WARN_ON(1);
		}
	} else if (was_leaf) {
		/* non-present -> non-present doesn't make sense. */
		WARN_ON(!was_present);

		/*
		 * Zap private leaf SPTE.  Zapping private table is done
		 * below in handle_removed_tdp_mmu_page().
		 */
		tdx_sept_zap_private_spte(kvm, gfn, level);

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

		tdx_sept_drop_private_spte(kvm, gfn, level, old_pfn);
	}
}

static int tdx_capabilities(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities caps;

	BUILD_BUG_ON(sizeof(struct kvm_tdx_cpuid_config) !=
		     sizeof(struct tdx_cpuid_config));

	WARN_ON(cmd->id != KVM_TDX_CAPABILITIES);
	if (cmd->metadata)
		return -EINVAL;

	user_caps = (void __user *)cmd->data;
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

	td_params->max_vcpus = init_vm->max_vcpus;

	td_params->attributes = init_vm->attributes;
	if (td_params->attributes & TDX_TD_ATTRIBUTE_PERFMON) {
		pr_warn("TD doesn't support perfmon. KVM needs to save/restore "
			"host perf registers properly.\n");
		return -EOPNOTSUPP;
	}

	/* TODO: Enforce consistent CPUID features for all vCPUs. */
	for (i = 0; i < tdx_caps.nr_cpuid_configs; i++) {
		config = &tdx_caps.cpuid_configs[i];

		entry = tdx_find_cpuid_entry(kvm_tdx, config->leaf,
					     config->sub_leaf);
		if (!entry)
			continue;

		/*
		 * Non-configurable bits must be '0', even if they are fixed to
		 * '1' by the TDX module, i.e. mask off non-configurable bits.
		 */
		value = &td_params->cpuid_values[i];
		value->eax = entry->eax & config->eax;
		value->ebx = entry->ebx & config->ebx;
		value->ecx = entry->ecx & config->ecx;
		value->edx = entry->edx & config->edx;
	}

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

	/* Setup td_params.xfam */
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
	guest_supported_xss &= (supported_xss | XFEATURE_MASK_PT);

	td_params->xfam = guest_supported_xcr0 | guest_supported_xss;
	if (td_params->xfam & XFEATURE_MASK_LBR) {
		pr_warn("TD doesn't support LBR. KVM needs to save/restore "
			"IA32_LBR_DEPTH properly.\n");
		return -EOPNOTSUPP;
	}

	if (td_params->xfam & XFEATURE_MASK_XTILE) {
		pr_warn("TD doesn't support AMX. KVM needs to save/restore "
			"IA32_XFD, IA32_XFD_ERR properly.\n");
		return -EOPNOTSUPP;
	}

	if (init_vm->tsc_khz)
		guest_tsc_khz = init_vm->tsc_khz;
	else
		guest_tsc_khz = max_tsc_khz;
	td_params->tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(guest_tsc_khz);

#define BUILD_BUG_ON_MEMCPY(dst, src)				\
	do {							\
		BUILD_BUG_ON(sizeof(dst) != sizeof(src));	\
		memcpy((dst), (src), sizeof(dst));		\
	} while (0)

	BUILD_BUG_ON_MEMCPY(td_params->mrconfigid, init_vm->mrconfigid);
	BUILD_BUG_ON_MEMCPY(td_params->mrowner, init_vm->mrowner);
	BUILD_BUG_ON_MEMCPY(td_params->mrownerconfig, init_vm->mrownerconfig);

	return 0;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_cpuid2 __user *user_cpuid;
	struct kvm_tdx_init_vm init_vm;
	struct td_params *td_params;
	struct tdx_module_output out;
	struct kvm_cpuid2 cpuid;
	int ret;
	u64 err;

	BUILD_BUG_ON(sizeof(init_vm) != 512);
	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

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

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL_ACCOUNT);
	if (!td_params)
		return -ENOMEM;

	kvm_tdx->cpuid_nent = cpuid.nent;

	ret = setup_tdparams(kvm, td_params, &init_vm);
	if (ret)
		goto free_tdparams;

	err = tdh_mng_init(kvm_tdx->tdr.pa, __pa(td_params), &out);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_INIT, err, &out);
		ret = -EIO;
		goto free_tdparams;
	}

	kvm_tdx->tsc_offset = td_tdcs_exec_read64(kvm_tdx, TD_TDCS_EXEC_TSC_OFFSET);
	kvm_tdx->attributes = td_params->attributes;
	kvm_tdx->xfam = td_params->xfam;
	kvm_tdx->tsc_khz = TDX_TSC_25MHZ_TO_KHZ(td_params->tsc_frequency);
	kvm->max_vcpus = td_params->max_vcpus;

	if (td_params->exec_controls & TDX_EXEC_CONTROL_MAX_GPAW)
		kvm->arch.gfn_shared_mask = gpa_to_gfn(BIT_ULL(51));
	else
		kvm->arch.gfn_shared_mask = gpa_to_gfn(BIT_ULL(47));

free_tdparams:
	kfree(td_params);
	if (ret)
		kvm_tdx->cpuid_nent = 0;
	return ret;
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

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
	case KVM_TDX_CAPABILITIES:
		r = tdx_capabilities(kvm, &tdx_cmd);
		break;
	case KVM_TDX_INIT_VM:
		r = tdx_td_init(kvm, &tdx_cmd);
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
	return 0;
}

static int __tdx_module_setup(void)
{
	const struct tdsysinfo_struct *tdsysinfo;
	int ret = 0;

	BUILD_BUG_ON(sizeof(*tdsysinfo) != 1024);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

	ret = tdx_detect();
	if (ret) {
		pr_info("Failed to detect TDX module.\n");
		return ret;
	}

	ret = tdx_init();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		return ret;
	}

	tdx_global_keyid = tdx_get_global_keyid();

	tdsysinfo = tdx_get_sysinfo();
	if (tdx_caps.nr_cpuid_configs > TDX_MAX_NR_CPUID_CONFIGS)
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

	return 0;
}

int tdx_module_setup(void)
{
	static DEFINE_MUTEX(tdx_init_lock);
	static bool __read_mostly tdx_module_initialized;
	int ret = 0;

	mutex_lock(&tdx_init_lock);

	if (!tdx_module_initialized) {
		if (enable_tdx) {
			ret = __tdx_module_setup();
			if (ret)
				enable_tdx = false;
			else
				tdx_module_initialized = true;
		} else
			ret = -EOPNOTSUPP;
	}

	mutex_unlock(&tdx_init_lock);
	return ret;
}

bool tdx_is_vm_type_supported(unsigned long type)
{
#ifdef CONFIG_X86_TDX_KVM_EXPERIMENTAL
	return type == KVM_X86_TDX_VM && READ_ONCE(enable_tdx);
#else
	return false;
#endif
}

static int __init __tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int max_pkgs;
	u32 max_pa;
	int i;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (!platform_has_tdx()) {
		if (__seamrr_enabled())
			pr_warn("Cannot enable TDX with SEAMRR disabled\n");
		return -ENODEV;
	}

	if (WARN_ON_ONCE(x86_ops->tlb_remote_flush))
		return -EIO;

	max_pkgs = topology_max_packages();
	tdx_mng_key_config_lock = kcalloc(max_pkgs, sizeof(*tdx_mng_key_config_lock),
				   GFP_KERNEL);
	if (!tdx_mng_key_config_lock)
		return -ENOMEM;
	for (i = 0; i < max_pkgs; i++)
		mutex_init(&tdx_mng_key_config_lock[i]);

	max_pa = cpuid_eax(0x80000008) & 0xff;
	hkid_start_pos = boot_cpu_data.x86_phys_bits;
	hkid_mask = GENMASK_ULL(max_pa - 1, hkid_start_pos);

	x86_ops->tlb_remote_flush = tdx_sept_tlb_remote_flush;
	x86_ops->free_private_sp = tdx_sept_free_private_sp;
	x86_ops->handle_changed_private_spte = tdx_handle_changed_private_spte;

	return 0;
}

void __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	/*
	 * This function is called at the initialization.  No need to protect
	 * enable_tdx.
	 */
	if (!enable_tdx)
		return;

	if (__tdx_hardware_setup(&vt_x86_ops))
		enable_tdx = false;
}

void tdx_hardware_unsetup(void)
{
	/* kfree accepts NULL. */
	kfree(tdx_mng_key_config_lock);
}
