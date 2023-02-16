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

static int __tdx_td_init(struct kvm *kvm);

int tdx_vm_init(struct kvm *kvm)
{
	kvm->arch.has_private_mem = true;

	/*
	 * TDX has its own limit of the number of vcpus in addition to
	 * KVM_MAX_VCPUS.
	 */
	kvm->max_vcpus = min(kvm->max_vcpus,
			tdx_sysinfo->td_conf.max_vcpus_per_td);

	/* Place holder for TDX specific logic. */
	return __tdx_td_init(kvm);
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

static int __tdx_td_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	unsigned long *tdcs_pa = NULL;
	unsigned long tdr_pa = 0;
	unsigned long va;
	int ret, i;
	u64 err;

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

#define KVM_SUPPORTED_TD_ATTRS (TDX_TD_ATTR_SEPT_VE_DISABLE)

static int __init setup_kvm_tdx_caps(void)
{
	const struct tdx_sysinfo_td_conf *td_conf = &tdx_sysinfo->td_conf;
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
					 tdx_online_cpu, NULL);
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
