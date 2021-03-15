// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/kvm_host.h>

#include "capabilities.h"
#include "tdx_errno.h"
#include "tdx_ops.h"
#include "x86_ops.h"
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
 * The function returns struct tdsysinfo_struct from TDX module provides which
 * is the system wide information about the TDX module.
 * Return NULL if the TDX module is not ready for KVM to use for TDX VM guest
 * life cycle.
 */
#if __has_include(<asm/tdx_host.h>)
#include <asm/tdx_host.h>
#else
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	return NULL;
}
#endif

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

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr.added;
}

static inline bool is_hkid_assigned(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->hkid >= 0;
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
	struct tdx_ex_ret ex_ret;
	u64 err;

	err = tdh_phymem_page_reclaim(pa, &ex_ret);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_RECLAIM, err, &ex_ret);
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

static void tdx_add_td_page(struct tdx_td_page *page)
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

	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_CACHE_WB, err, NULL);
		return -EIO;
	}

	return 0;
}

void tdx_vm_teardown(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
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

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL))
		return;
	ret = 0;
	for_each_online_cpu(i) {
		/* tdh_phymem_cache_wb() is per package operation. */
		if (!cpumask_test_and_set_cpu(topology_physical_package_id(i),
						packages))
			continue;

		ret = smp_call_on_cpu(i, tdx_do_tdh_phymem_cache_wb, NULL, 1);
		if (ret)
			break;
	}
	free_cpumask_var(packages);
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
				tdx_seam_keyid))
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

	kvm_tdx->tdcs = kcalloc(tdx_caps.tdcs_nr_pages, sizeof(*kvm_tdx->tdcs),
				GFP_KERNEL_ACCOUNT);
	if (!kvm_tdx->tdcs)
		goto free_tdr;
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
	tdx_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
	return ret;
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

	if (copy_to_user(user_caps, &caps, sizeof(caps)))
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
		 * '1' by the TDX module, i.e. mask off non-configurable bits.
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
	guest_supported_xss &= (supported_xss | XFEATURE_MASK_PT);

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

	if (td_params->attributes & TDX_TD_ATTRIBUTE_PERFMON) {
		pr_warn("TD doesn't support perfmon. KVM needs to save/restore "
			"host perf registers properly.\n");
		return -EOPNOTSUPP;
	}

	/* Setup td_params.xfam */
	td_params->xfam = guest_supported_xcr0 | guest_supported_xss;
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
		guest_tsc_khz = max_tsc_khz;
	td_params->tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(guest_tsc_khz);

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

	BUILD_BUG_ON(sizeof(init_vm) != 512);

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
	kvm_tdx->tsc_khz = TDX_TSC_25MHZ_TO_KHZ(td_params->tsc_frequency);
	kvm->max_vcpus = td_params->max_vcpus;

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

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int i, max_pkgs;
	u32 max_pa;
	const struct tdsysinfo_struct *tdsysinfo = tdx_get_sysinfo();

	BUILD_BUG_ON(sizeof(*tdsysinfo) != 1024);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

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

	tdx_keyids_init();

	tdx_caps.tdcs_nr_pages = tdsysinfo->tdcs_base_size / PAGE_SIZE;
	tdx_caps.tdvpx_nr_pages = tdsysinfo->tdvps_base_size / PAGE_SIZE - 1;

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
