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

struct tdx_info {
	u64 features0;
	u64 attributes_fixed0;
	u64 attributes_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;

	u16 num_cpuid_config;
	/* This must the last member. */
	DECLARE_FLEX_ARRAY(struct kvm_tdx_cpuid_config, cpuid_configs);
};

/* Info about the TDX module. */
static struct tdx_info *tdx_info;

static int tdx_get_capabilities(struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities *caps = NULL;
	int ret = 0;

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
		((kvm_get_shadow_phys_bits() >= 52 &&
		  cpu_has_vmx_ept_5levels()) ? TDX_CAP_GPAW_52 : 0),
		.nr_cpuid_configs = tdx_info->num_cpuid_config,
		.padding = 0,
	};

	if (copy_to_user(user_caps, caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}
	if (copy_to_user(user_caps->cpuid_configs, &tdx_info->cpuid_configs,
			 tdx_info->num_cpuid_config *
			 sizeof(tdx_info->cpuid_configs[0]))) {
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
	struct st {
		u16 num_cpuid_config;
		/* More member will come. */
	} st;
	int ret;
	u32 i;

#define TDX_INFO_MAP(_field_id, _member)		\
	TD_SYSINFO_MAP(_field_id, struct st, _member)

	struct tdx_metadata_field_mapping st_fields[] = {
		TDX_INFO_MAP(NUM_CPUID_CONFIG, num_cpuid_config),
	};
#undef TDX_INFO_MAP

#define TDX_INFO_MAP(_field_id, _member)			\
	TD_SYSINFO_MAP(_field_id, struct tdx_info, _member)

	struct tdx_metadata_field_mapping fields[] = {
		TDX_INFO_MAP(FEATURES0, features0),
		TDX_INFO_MAP(ATTRS_FIXED0, attributes_fixed0),
		TDX_INFO_MAP(ATTRS_FIXED1, attributes_fixed1),
		TDX_INFO_MAP(XFAM_FIXED0, xfam_fixed0),
		TDX_INFO_MAP(XFAM_FIXED1, xfam_fixed1),
	};
#undef TDX_INFO_MAP

	ret = tdx_enable();
	if (ret)
		return ret;

	ret = tdx_sys_metadata_read(st_fields, ARRAY_SIZE(st_fields), &st);
	if (ret)
		return ret;

	tdx_info = kzalloc(sizeof(*tdx_info) +
			   sizeof(*tdx_info->cpuid_configs) * st.num_cpuid_config,
			   GFP_KERNEL);
	if (!tdx_info)
		return -ENOMEM;
	tdx_info->num_cpuid_config = st.num_cpuid_config;

	ret = tdx_sys_metadata_read(fields, ARRAY_SIZE(fields), tdx_info);
	if (ret)
		goto error_out;

	for (i = 0; i < st.num_cpuid_config; i++) {
		struct kvm_tdx_cpuid_config *c = &tdx_info->cpuid_configs[i];
		struct cpuid_st {
			u64 leaf;
			u64 eax_ebx;
			u64 ecx_edx;
		} cpuid_st;

#define TDX_INFO_MAP(_field_id, _member)			\
	TD_SYSINFO_MAP(_field_id, struct cpuid_st, _member)

		struct tdx_metadata_field_mapping cpuid_fields[] = {
			TDX_INFO_MAP(CPUID_CONFIG_LEAVES + i, leaf),
			TDX_INFO_MAP(CPUID_CONFIG_VALUES + i * 2, eax_ebx),
			TDX_INFO_MAP(CPUID_CONFIG_VALUES + i * 2 + 1, ecx_edx),
		};
#undef TDX_INFO_MAP

		ret = tdx_sys_metadata_read(cpuid_fields, ARRAY_SIZE(cpuid_fields),
					    &cpuid_st);
		if (ret)
			goto error_out;

		c->leaf = (u32)cpuid_st.leaf;
		c->sub_leaf = cpuid_st.leaf >> 32;
		c->eax = (u32)cpuid_st.eax_ebx;
		c->ebx = cpuid_st.eax_ebx >> 32;
		c->ecx = (u32)cpuid_st.ecx_edx;
		c->edx = cpuid_st.ecx_edx >> 32;
	}

	return 0;

error_out:
	/* kfree() accepts NULL. */
	kfree(tdx_info);
	return ret;
}

struct tdx_enabled {
	cpumask_var_t enabled;
	atomic_t err;
};

static void __init tdx_on(void *_enable)
{
	struct tdx_enabled *enable = _enable;
	int r;

	r = vmx_hardware_enable();
	if (!r) {
		cpumask_set_cpu(smp_processor_id(), enable->enabled);
		r = tdx_cpu_enable();
	}
	if (r)
		atomic_set(&enable->err, r);
}

static void __init vmx_off(void *_enabled)
{
	cpumask_var_t *enabled = (cpumask_var_t *)_enabled;

	if (cpumask_test_cpu(smp_processor_id(), *enabled))
		vmx_hardware_disable();
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	struct tdx_enabled enable = {
		.err = ATOMIC_INIT(0),
	};
	int r = 0;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (!zalloc_cpumask_var(&enable.enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	on_each_cpu(tdx_on, &enable, true); /* TDX requires vmxon. */
	r = atomic_read(&enable.err);
	if (!r)
		r = tdx_module_setup();
	else
		r = -EIO;
	on_each_cpu(vmx_off, &enable.enabled, true);
	cpus_read_unlock();
	free_cpumask_var(enable.enabled);

out:
	return r;
}

void tdx_hardware_unsetup(void)
{
	kfree(tdx_info);
}
