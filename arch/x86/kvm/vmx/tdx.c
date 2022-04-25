// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "x86.h"
#include "tdx.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define TDX_MAX_NR_CPUID_CONFIGS					\
	((TDSYSINFO_STRUCT_SIZE -					\
		offsetof(struct tdsysinfo_struct, cpuid_configs))	\
		/ sizeof(struct tdx_cpuid_config))

int tdx_dev_ioctl(void __user *argp)
{
	struct kvm_tdx_capabilities __user *user_caps;
	const struct tdsysinfo_struct *tdsysinfo;
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

	tdsysinfo = tdx_get_sysinfo();
	if (!tdsysinfo)
		return -ENOTSUPP;

	user_caps = (void __user *)cmd.data;
	if (copy_from_user(&caps, user_caps, sizeof(caps)))
		return -EFAULT;

	if (caps.nr_cpuid_configs < tdsysinfo->num_cpuid_config)
		return -E2BIG;

	caps = (struct kvm_tdx_capabilities) {
		.attrs_fixed0 = tdsysinfo->attributes_fixed0,
		.attrs_fixed1 = tdsysinfo->attributes_fixed1,
		.xfam_fixed0 = tdsysinfo->xfam_fixed0,
		.xfam_fixed1 = tdsysinfo->xfam_fixed1,
		.nr_cpuid_configs = tdsysinfo->num_cpuid_config,
		.padding = 0,
	};

	if (copy_to_user(user_caps, &caps, sizeof(caps)))
		return -EFAULT;
	if (copy_to_user(user_caps->cpuid_configs, &tdsysinfo->cpuid_configs,
			 tdsysinfo->num_cpuid_config *
			 sizeof(struct tdx_cpuid_config)))
		return -EFAULT;

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

	/* Sanitary check just in case. */
	tdsysinfo = tdx_get_sysinfo();
	WARN_ON(tdsysinfo->num_cpuid_config > TDX_MAX_NR_CPUID_CONFIGS);

	pr_info("TDX is supported.\n");
	return 0;
}

bool tdx_is_vm_type_supported(unsigned long type)
{
	/* enable_tdx check is done by the caller. */
	return type == KVM_X86_PROTECTED_VM;
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int r = 0;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	r = kvm_hardware_enable_all_nolock();
	if (!r) {
		r = tdx_module_setup();
		kvm_hardware_disable_all_nolock();
	}
	cpus_read_unlock();

	return r;
}
