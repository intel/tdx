// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <asm/tdx.h>
#include "capabilities.h"
#include "x86_ops.h"
#include "mmu.h"
#include "tdx.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

bool enable_tdx __ro_after_init;
module_param_named(tdx, enable_tdx, bool, 0444);

static enum cpuhp_state tdx_cpuhp_state;

static const struct tdx_sysinfo *tdx_sysinfo;

/* TDX KeyID pool */
static DEFINE_IDA(tdx_guest_keyid_pool);

static int __used tdx_guest_keyid_alloc(void)
{
	return ida_alloc_range(&tdx_guest_keyid_pool, tdx_guest_keyid_start,
			       tdx_guest_keyid_start + tdx_nr_guest_keyids - 1,
			       GFP_KERNEL);
}

static void __used tdx_guest_keyid_free(int keyid)
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
