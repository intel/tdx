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

struct tdx_info {
	u64 attributes_fixed0;
	u64 attributes_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;

	u16 num_cpuid_config;
	DECLARE_FLEX_ARRAY(struct tdx_cpuid_config, cpuid_configs);
};

/* Info about the TDX module. */
static struct tdx_info *tdx_info;

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

static int tdx_get_capabilities(struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities *caps = NULL;
	int ret = 0;

	BUILD_BUG_ON(sizeof(struct kvm_tdx_cpuid_config) !=
		     sizeof(struct tdx_cpuid_config));

	if (cmd->flags)
		return -EINVAL;

	caps = kmalloc(sizeof(*caps), GFP_KERNEL);
	if (!caps)
		return -ENOMEM;

	user_caps = (void __user *)cmd->data;
	if (copy_from_user(caps, user_caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}

	if (caps->nr_cpuid_configs < tdx_info->num_cpuid_config) {
		ret = -E2BIG;
		goto out;
	}

	*caps = (struct kvm_tdx_capabilities) {
		.attrs_fixed0 = tdx_info->attributes_fixed0,
		.attrs_fixed1 = tdx_info->attributes_fixed1,
		.xfam_fixed0 = tdx_info->xfam_fixed0,
		.xfam_fixed1 = tdx_info->xfam_fixed1,
		.supported_gpaw = TDX_CAP_GPAW_48 |
		(kvm_get_shadow_phys_bits() >= 52 &&
		 cpu_has_vmx_ept_5levels()) ? TDX_CAP_GPAW_52 : 0,
		.nr_cpuid_configs = tdx_info->num_cpuid_config,
		.padding = 0,
	};

	if (copy_to_user(user_caps, caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}
	if (copy_to_user(user_caps->cpuid_configs, &tdx_info->cpuid_configs,
			 tdx_info->num_cpuid_config *
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
	u16 num_cpuid_config;
	u64 data, err;
	int ret;
	u32 i;

#define MD_FID_OFFSET(field, member)					\
	{ TDX_MD_FID_GLOBAL_##field, offsetof(struct tdx_info, member) }

	struct {
		u64 field;
		int offset;
	} md64[] = {
		MD_FID_OFFSET(ATTRS_FIXED0, attributes_fixed0),
		MD_FID_OFFSET(ATTRS_FIXED1, attributes_fixed1),
		MD_FID_OFFSET(XFAM_FIXED0, xfam_fixed0),
		MD_FID_OFFSET(XFAM_FIXED1, xfam_fixed1),
	};

	ret = tdx_enable();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		return ret;
	}

	err = tdh_sys_rd16(TDX_MD_FID_GLOBAL_NUM_CPUID_CONFIG, &num_cpuid_config);
	if (err) {
		pr_tdx_error(TDH_SYS_RD, err, NULL);
		return -EIO;
	}

	tdx_info = kzalloc(sizeof(*tdx_info) +
			   sizeof(*tdx_info->cpuid_configs) * num_cpuid_config,
			   GFP_KERNEL);
	if (!tdx_info)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(md64); i++) {
		err = tdh_sys_rd64(md64[i].field, (void*)tdx_info + md64[i].offset);
		if (err)
			goto error_sys_rd;
	}

	tdx_info->num_cpuid_config = num_cpuid_config;
	for (i = 0; i < num_cpuid_config; i++) {
		struct tdx_cpuid_config *c = &tdx_info->cpuid_configs[i];

		err = tdh_sys_rd64(TDX_MD_FID_GLOBAL_CPUID_CONFIG_LEAVES + i,
				   &data);
		if (err)
			goto error_sys_rd;
		c->leaf_sub_leaf = (struct tdx_cpuid_config_leaf) {
			.leaf = (u32)data,
			.sub_leaf = data >> 32,
		};

		err = tdh_sys_rd64(TDX_MD_FID_GLOBAL_CPUID_CONFIG_VALUES + i * 2,
				   &data);
		if (err)
			goto error_sys_rd;
		c->eax = (u32)data;
		c->ebx = data >> 32;

		err = tdh_sys_rd64(TDX_MD_FID_GLOBAL_CPUID_CONFIG_VALUES + i * 2 + 1,
				   &data);
		if (err)
			goto error_sys_rd;
		c->ecx = (u32)data;
		c->edx = data >> 32;
	}

	return 0;

error_sys_rd:
       ret = -EIO;
       pr_tdx_error(TDH_SYS_RD, err, NULL);
       /* kfree() accepts NULL. */
       kfree(tdx_info);
       return ret;
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
