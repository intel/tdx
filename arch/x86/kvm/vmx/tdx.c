// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "x86.h"
#include "mmu.h"
#include "tdx.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define TDX_MAX_NR_CPUID_CONFIGS					\
	((TDSYSINFO_STRUCT_SIZE -					\
		offsetof(struct tdsysinfo_struct, cpuid_configs))	\
		/ sizeof(struct tdx_cpuid_config))

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
	int r = 0;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (!zalloc_cpumask_var(&vmx_tdx.vmx_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	on_each_cpu(vmx_tdx_on, &vmx_tdx, true);	/* TDX requires vmxon. */
	r = atomic_read(&vmx_tdx.err);
	if (!r)
		r = tdx_module_setup();
	else
		r = -EIO;
	on_each_cpu(vmx_off, &vmx_tdx.vmx_enabled, true);
	cpus_read_unlock();
	free_cpumask_var(vmx_tdx.vmx_enabled);

out:
	return r;
}
