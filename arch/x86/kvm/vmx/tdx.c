// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <asm/tdx.h>
#include "capabilities.h"
#include "x86_ops.h"
#include "mmu.h"
#include "tdx.h"
#include "tdx_ops.h"


#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

bool enable_tdx __ro_after_init;
module_param_named(tdx, enable_tdx, bool, 0444);

static enum cpuhp_state tdx_cpuhp_state;

static const struct tdx_sysinfo *tdx_sysinfo;

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

/* Maximum number of retries to attempt for SEAMCALLs. */
#define TDX_SEAMCALL_RETRIES	10000

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	return pa | ((hpa_t)hkid << boot_cpu_data.x86_phys_bits);
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

static u64 ____tdx_reclaim_page(hpa_t pa, u64 *rcx, u64 *rdx, u64 *r8)
{
	u64 err;
	int i;

	for (i = TDX_SEAMCALL_RETRIES; i > 0; i--) {
		err = tdh_phymem_page_reclaim(pa, rcx, rdx, r8);
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
	return err;
}

/* TDH.PHYMEM.PAGE.RECLAIM is allowed only when destroying the TD. */
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
	u64 err;
	int i;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	/* KeyID has been allocated but guest is not yet configured */
	if (!is_td_created(kvm_tdx)) {
		tdx_hkid_free(kvm_tdx);
		return;
	}

	packages_allocated = zalloc_cpumask_var(&packages, GFP_KERNEL);
	targets_allocated = zalloc_cpumask_var(&targets, GFP_KERNEL);
	cpus_read_lock();

	/*
	 * TDH.PHYMEM.CACHE.WB tries to acquire the TDX module global lock
	 * and can fail with TDX_OPERAND_BUSY when it fails to get the lock.
	 * Multiple TDX guests can be destroyed simultaneously. Take the
	 * mutex to prevent it from getting error.
	 */
	mutex_lock(&tdx_lock);

	/*
	 * We need three SEAMCALLs, TDH.MNG.VPFLUSHDONE(), TDH.PHYMEM.CACHE.WB(),
	 * and TDH.MNG.KEY.FREEID() to free the HKID. When the HKID is assigned,
	 * we need to use TDH.MEM.SEPT.REMOVE() or TDH.MEM.PAGE.REMOVE(). When
	 * the HKID is free, we need to use TDH.PHYMEM.PAGE.RECLAIM().  Get lock
	 * to not present transient state of HKID.
	 */
	write_lock(&kvm->mmu_lock);

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
	err = tdh_mng_key_freeid(kvm_tdx);
	if (KVM_BUG_ON(err, kvm)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err);
		pr_err("tdh_mng_key_freeid() failed. HKID %d is leaked.\n",
		       kvm_tdx->hkid);
	} else {
		tdx_hkid_free(kvm_tdx);
	}

	write_unlock(&kvm->mmu_lock);
	mutex_unlock(&tdx_lock);
	cpus_read_unlock();
	free_cpumask_var(targets);
	free_cpumask_var(packages);
}

static inline u8 tdx_sysinfo_nr_tdcs_pages(void)
{
	return tdx_sysinfo->td_ctrl.tdcs_base_size / PAGE_SIZE;
}

static inline u8 tdx_sysinfo_nr_tdcx_pages(void)
{
	/*
	 * TDVPS = TDVPR(4K page) + TDCX(multiple 4K pages).
	 * -1 for TDVPR.
	 */
	return tdx_sysinfo->td_ctrl.tdvps_base_size / PAGE_SIZE - 1;
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
		for (i = 0; i < tdx_sysinfo_nr_tdcs_pages(); i++) {
			if (!kvm_tdx->tdcs_pa[i])
				continue;

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
	 * Use a SEAMCALL to ask the TDX module to flush the cache based on the
	 * KeyID. TDX module may access TDR while operating on TD (Especially
	 * when it is reclaiming TDCS).
	 */
	err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(kvm_tdx->tdr_pa,
						     tdx_global_keyid));
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
	err = tdh_mng_key_config(kvm_tdx);

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

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	/* TDX only supports x2APIC, which requires an in-kernel local APIC. */
	if (!vcpu->arch.apic)
		return -EINVAL;

	fpstate_set_confidential(&vcpu->arch.guest_fpu);

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.cr0_guest_owned_bits = -1ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;

	vcpu->arch.tsc_offset = kvm_tdx->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTR_DEBUG);

	if ((kvm_tdx->xfam & XFEATURE_MASK_XTILE) == XFEATURE_MASK_XTILE)
		vcpu->arch.xfd_no_write_intercept = true;

	return 0;
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
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm)))
		return;

	if (tdx->tdcx_pa) {
		for (i = 0; i < tdx_sysinfo_nr_tdcx_pages(); i++) {
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

	/* Ignore INIT silently because TDX doesn't support INIT event. */
	if (init_event)
		return;
	if (is_td_vcpu_created(to_tdx(vcpu)))
		return;

	/*
	 * Don't update mp_state to runnable because more initialization
	 * is needed by TDX_VCPU_INIT.
	 */
}

static int tdx_get_capabilities(struct kvm_tdx_cmd *cmd)
{
	const struct tdx_sysinfo_td_conf *td_conf = &tdx_sysinfo->td_conf;
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
		td_params->exec_controls |= TDX_EXEC_CONTROL_MAX_GPAW;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
	}

	return 0;
}

static int setup_tdparams_cpuids(struct kvm_cpuid2 *cpuid,
				 struct td_params *td_params)
{
	const struct tdx_sysinfo_td_conf *td_conf = &tdx_sysinfo->td_conf;
	const struct kvm_tdx_cpuid_config *c;
	const struct kvm_cpuid_entry2 *entry;
	struct tdx_cpuid_value *value;
	int i;

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

		/*
		 * Check the user input value doesn't set any non-configurable
		 * bits reported by kvm_tdx_caps.
		 */
		if ((entry->eax & c->eax) != entry->eax ||
		    (entry->ebx & c->ebx) != entry->ebx ||
		    (entry->ecx & c->ecx) != entry->ecx ||
		    (entry->edx & c->edx) != entry->edx)
			return -EINVAL;

		value = &td_params->cpuid_values[i];
		value->eax = entry->eax;
		value->ebx = entry->ebx;
		value->ecx = entry->ecx;
		value->edx = entry->edx;

		if (c->leaf == 0x80000008)
			value->eax &= 0xff00ffff;
	}

	return 0;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params,
			struct kvm_tdx_init_vm *init_vm)
{
	const struct tdx_sysinfo_td_conf *td_conf = &tdx_sysinfo->td_conf;
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

	/* td_params->exec_controls = TDX_CONTROL_FLAG_NO_RBP_MOD; */
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

	tdcs_pa = kcalloc(tdx_sysinfo_nr_tdcs_pages(), sizeof(*kvm_tdx->tdcs_pa),
			  GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!tdcs_pa)
		goto free_tdr;

	for (i = 0; i < tdx_sysinfo_nr_tdcs_pages(); i++) {
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
	for (i = 0; i < tdx_sysinfo_nr_tdcs_pages(); i++) {
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

	return 0;

	/*
	 * The sequence for freeing resources from a partially initialized TD
	 * varies based on where in the initialization flow failure occurred.
	 * Simply use the full teardown and destroy, which naturally play nice
	 * with partial initialization.
	 */
teardown:
	for (; i < tdx_sysinfo_nr_tdcs_pages(); i++) {
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
	for (i = 0; i < tdx_sysinfo_nr_tdcs_pages(); i++) {
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

	err = tdh_mng_rd(tdx, field_id, data);

	return err;
}

#define TDX_MD_UNREADABLE_LEAF_MASK	GENMASK(30, 7)
#define TDX_MD_UNREADABLE_SUBLEAF_MASK	GENMASK(31, 7)

static int tdx_mask_cpuid(struct kvm_tdx *tdx, struct kvm_cpuid_entry2 *entry)
{
	u64 field_id = TD_MD_FIELD_ID_CPUID_VALUES;
	u64 ebx_eax, edx_ecx;
	u64 err = 0;

	if (entry->function & TDX_MD_UNREADABLE_LEAF_MASK ||
	    entry->index & TDX_MD_UNREADABLE_SUBLEAF_MASK)
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
	field_id |= ((entry->function & 0x80000000) ? 1 : 0) << 16;
	field_id |= (entry->function & 0x7f) << 9;
	if (entry->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)
		field_id |= (entry->index & 0x7f) << 1;
	else
		field_id |= 0x1fe;

	err = tdx_td_metadata_field_read(tdx, field_id, &ebx_eax);
	if (err) //TODO check for specific errors
		goto err_out;

	entry->eax &= (u32) ebx_eax;
	entry->ebx &= (u32) (ebx_eax >> 32);

	field_id++;
	err = tdx_td_metadata_field_read(tdx, field_id, &edx_ecx);
	/*
	 * It's weird that reading edx_ecx fails while reading ebx_eax
	 * succeeded.
	 */
	if (WARN_ON_ONCE(err))
		goto err_out;

	entry->ecx &= (u32) edx_ecx;
	entry->edx &= (u32) (edx_ecx >> 32);
	return 0;

err_out:
	entry->eax = 0;
	entry->ebx = 0;
	entry->ecx = 0;
	entry->edx = 0;

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

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	/*
	 * Userspace should never set @error. It is used to fill
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
	const struct tdx_sysinfo_module_info *modinfo = &tdx_sysinfo->module_info;
	struct vcpu_tdx *tdx = to_tdx(vcpu);
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
	tdx->tdvpr_pa = __pa(va);

	tdx->tdcx_pa = kcalloc(tdx_sysinfo_nr_tdcx_pages(), sizeof(*tdx->tdcx_pa),
			   GFP_KERNEL_ACCOUNT);
	if (!tdx->tdcx_pa) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}

	err = tdh_vp_create(tdx);
	if (KVM_BUG_ON(err, vcpu->kvm)) {
		tdx->tdvpr_pa = 0;
		ret = -EIO;
		pr_tdx_error(TDH_VP_CREATE, err);
		goto free_tdvpx;
	}

	for (i = 0; i < tdx_sysinfo_nr_tdcx_pages(); i++) {
		va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!va) {
			ret = -ENOMEM;
			goto free_tdvpx;
		}
		tdx->tdcx_pa[i] = __pa(va);

		err = tdh_vp_addcx(tdx, tdx->tdcx_pa[i]);
		if (KVM_BUG_ON(err, vcpu->kvm)) {
			pr_tdx_error(TDH_VP_ADDCX, err);
			/* vcpu_free method frees TDCX and TDR donated to TDX */
			return -EIO;
		}
	}

	if (modinfo->tdx_features0 & MD_FIELD_ID_FEATURES0_TOPOLOGY_ENUM)
		err = tdh_vp_init_apicid(tdx, vcpu_rcx, vcpu->vcpu_id);
	else
		err = tdh_vp_init(tdx, vcpu_rcx);

	if (KVM_BUG_ON(err, vcpu->kvm)) {
		pr_tdx_error(TDH_VP_INIT, err);
		return -EIO;
	}

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	tdx->td_vcpu_created = true;

	return 0;

free_tdvpx:
	for (i = 0; i < tdx_sysinfo_nr_tdcx_pages(); i++) {
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

/*
 * This function is used in two cases:
 * 1. mask KVM unsupported/unknown bits from the configurable CPUIDs reported
 *    by TDX module. in setup_kvm_tdx_caps().
 * 2. mask KVM unsupported/unknown bits from the actual CPUID value of TD that
 *    read from TDX module. in tdx_vcpu_get_cpuid().
 *
 * For both cases, it needs fixup for the field that consists of multiple bits.
 * For multi-bits field, we need a mask however what
 * kvm_get_supported_cpuid_internal() returns is just a default value.
 */
static int tdx_get_kvm_supported_cpuid(struct kvm_cpuid2 **cpuid)
{
	int r;
	static const u32 funcs[] = {
		0, 0x80000000, KVM_CPUID_SIGNATURE,
	};
	struct kvm_cpuid_entry2 *entry;

	*cpuid = kzalloc(sizeof(struct kvm_cpuid2) +
			sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES,
			GFP_KERNEL);
	if (!*cpuid)
		return -ENOMEM;
	(*cpuid)->nent = KVM_MAX_CPUID_ENTRIES;
	r = kvm_get_supported_cpuid_internal(*cpuid, funcs, ARRAY_SIZE(funcs));
	if (r)
		goto err;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x0, 0);
	if (WARN_ON(!entry))
		goto err;
	/* Fixup of maximum basic leaf */
	entry->eax |= 0x000000FF;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x1, 0);
	if (WARN_ON(!entry))
		goto err;
	/* Fixup of FMS */
	entry->eax |= 0x0fff3fff;
	/* Fixup of maximum logical processors per package */
	entry->ebx |= 0x00ff0000;

	/*
	 * Fixup of CPUID leaf 4, which enmerates cache info, all of the
	 * non-reserved fields except EBX[11:0] (System Coherency Line Size)
	 * are configurable for TDs.
	 */
	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x4, 0);
	if (WARN_ON(!entry))
		goto err;
	entry->eax |= 0xffffc3ff;
	entry->ebx |= 0xfffff000;
	entry->ecx |= 0xffffffff;
	entry->edx |= 0x00000007;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x4, 1);
	if (WARN_ON(!entry))
		goto err;
	entry->eax |= 0xffffc3ff;
	entry->ebx |= 0xfffff000;
	entry->ecx |= 0xffffffff;
	entry->edx |= 0x00000007;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x4, 2);
	if (WARN_ON(!entry))
		goto err;
	entry->eax |= 0xffffc3ff;
	entry->ebx |= 0xfffff000;
	entry->ecx |= 0xffffffff;
	entry->edx |= 0x00000007;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x4, 3);
	if (WARN_ON(!entry))
		goto err;
	entry->eax |= 0xffffc3ff;
	entry->ebx |= 0xfffff000;
	entry->ecx |= 0xffffffff;
	entry->edx |= 0x00000007;

	/* Fixup of CPUID leaf 0xB */
	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0xb, 0);
	if (WARN_ON(!entry))
		goto err;
	entry->eax = 0x0000001f;
	entry->ebx = 0x0000ffff;
	entry->ecx = 0x0000ffff;

	/*
	 * Fixup of CPUID leaf 0x1f, which is totally configurable for TDs.
	 */
	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x1f, 0);
	if (WARN_ON(!entry))
		goto err;
	entry->eax = 0x0000001f;
	entry->ebx = 0x0000ffff;
	entry->ecx = 0x0000ffff;

	for (int i = 1; i <= 5; i++) {
		entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x1f, i);
		if (!entry) {
			entry = &(*cpuid)->entries[(*cpuid)->nent];
			entry->function = 0x1f;
			entry->index = i;
			entry->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
			(*cpuid)->nent++;
		}
		entry->eax = 0x0000001f;
		entry->ebx = 0x0000ffff;
		entry->ecx = 0x0000ffff;
	}

	return 0;
err:
	kfree(*cpuid);
	*cpuid = NULL;
	return r;
}

static int tdx_vcpu_get_cpuid(struct kvm_vcpu *vcpu, struct kvm_tdx_cmd *cmd)
{
	struct kvm_cpuid2 __user *output, *td_cpuid;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct kvm_cpuid2 *supported_cpuid;
	int r = 0, i, j = 0;

	output = u64_to_user_ptr(cmd->data);
	td_cpuid = kzalloc(sizeof(*td_cpuid) +
			sizeof(output->entries[0]) * KVM_MAX_CPUID_ENTRIES,
			GFP_KERNEL);
	if (!td_cpuid)
		return -ENOMEM;

	r = tdx_get_kvm_supported_cpuid(&supported_cpuid);
	if (r)
		goto out;

	for (i = 0; i < supported_cpuid->nent; i++) {
		struct kvm_cpuid_entry2 *supported = &supported_cpuid->entries[i];
		struct kvm_cpuid_entry2 *output_e = &td_cpuid->entries[j];

		*output_e = *supported;

		/* Only allow values of bits that KVM's supports to be exposed */
		if (tdx_mask_cpuid(kvm_tdx, output_e))
			continue;

		/*
		 * Work around missing support on old TDX modules, fetch
		 * guest maxpa from gfn_direct_bits.
		 */
		if (output_e->function == 0x80000008) {
			gpa_t gpa_bits = gfn_to_gpa(kvm_gfn_direct_bits(vcpu->kvm));
			unsigned int g_maxpa = __ffs(gpa_bits) + 1;

			output_e->eax &= ~0x00ff0000;
			output_e->eax |= g_maxpa << 16;
		}

		j++;
	}
	td_cpuid->nent = j;

	if (copy_to_user(output, td_cpuid, sizeof(*output))) {
		r = -EFAULT;
		goto out;
	}
	if (copy_to_user(output->entries, td_cpuid->entries,
			 td_cpuid->nent * sizeof(struct kvm_cpuid_entry2)))
		r = -EFAULT;

out:
	kfree(td_cpuid);
	kfree(supported_cpuid);
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

	tdx->initialized = true;
	return 0;
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

	if (cmd.hw_error)
		return -EINVAL;

	switch (cmd.id) {
	case KVM_TDX_INIT_VCPU:
		ret = tdx_vcpu_init(vcpu, &cmd);
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

#define KVM_SUPPORTED_TD_ATTRS (TDX_TD_ATTR_SEPT_VE_DISABLE)

static int __init setup_kvm_tdx_caps(void)
{
	const struct tdx_sysinfo_td_conf *td_conf = &tdx_sysinfo->td_conf;
	struct kvm_cpuid_entry2 *cpuid_e;
	struct kvm_cpuid2 *supported_cpuid;
	u64 kvm_supported;
	int i, r = -EIO;

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

	r = tdx_get_kvm_supported_cpuid(&supported_cpuid);
	if (r)
		goto err;

	kvm_tdx_caps->num_cpuid_config = td_conf->num_cpuid_config;
	for (i = 0; i < td_conf->num_cpuid_config; i++) {
		struct kvm_tdx_cpuid_config source = {
			.leaf = (u32)td_conf->cpuid_config_leaves[i],
			.sub_leaf = td_conf->cpuid_config_leaves[i] >> 32,
			.eax = (u32)td_conf->cpuid_config_values[i].eax_ebx,
			.ebx = td_conf->cpuid_config_values[i].eax_ebx >> 32,
			.ecx = (u32)td_conf->cpuid_config_values[i].ecx_edx,
			.edx = td_conf->cpuid_config_values[i].ecx_edx >> 32,
		};
		struct kvm_tdx_cpuid_config *dest =
			&kvm_tdx_caps->cpuid_configs[i];

		memcpy(dest, &source, sizeof(struct kvm_tdx_cpuid_config));
		if (dest->sub_leaf == KVM_TDX_CPUID_NO_SUBLEAF)
			dest->sub_leaf = 0;

		/* Work around missing support on old TDX modules */
		if (dest->leaf == 0x80000008)
			dest->eax |= 0x00ff0000;

		cpuid_e = kvm_find_cpuid_entry2(supported_cpuid->entries, supported_cpuid->nent,
						dest->leaf, dest->sub_leaf);
		if (!cpuid_e) {
			dest->eax = dest->ebx = dest->ecx = dest->edx = 0;
		} else {
			dest->eax &= cpuid_e->eax;
			dest->ebx &= cpuid_e->ebx;
			dest->ecx &= cpuid_e->ecx;
			dest->edx &= cpuid_e->edx;
		}
	}

	kfree(supported_cpuid);
	return 0;
err:
	kfree(kvm_tdx_caps);
	return r;
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
	const struct tdx_sysinfo_td_conf *td_conf;
	int r;

	if (!cpu_feature_enabled(X86_FEATURE_MOVDIR64B)) {
		pr_warn("MOVDIR64B is reqiured for TDX\n");
		return -EOPNOTSUPP;
	}

	if (!enable_ept) {
		pr_err("Cannot enable TDX with EPT disabled.\n");
		return -EINVAL;
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
