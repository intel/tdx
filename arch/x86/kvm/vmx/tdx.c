// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "x86.h"
#include "mmu.h"
#include "tdx_arch.h"
#include "tdx.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/*
 * Key id globally used by TDX module: TDX module maps TDR with this TDX global
 * key id.  TDR includes key id assigned to the TD.  Then TDX module maps other
 * TD-related pages with the assigned key id.  TDR requires this TDX global key
 * id for cache flush unlike other TD-related pages.
 */
/* TDX KeyID pool */
static DEFINE_IDA(tdx_guest_keyid_pool);

static int __used tdx_guest_keyid_alloc(void)
{
	if (WARN_ON_ONCE(!tdx_guest_keyid_start || !tdx_nr_guest_keyids))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_guest_keyid_pool, tdx_guest_keyid_start,
			       tdx_guest_keyid_start + tdx_nr_guest_keyids - 1,
			       GFP_KERNEL);
}

static void __used tdx_guest_keyid_free(int keyid)
{
	/* keyid = 0 is reserved. */
	if (WARN_ON_ONCE(keyid <= 0))
		return;

	ida_free(&tdx_guest_keyid_pool, keyid);
}

#define TDX_MD_MAP(_fid, _ptr)			\
	{ .fid = MD_FIELD_ID_##_fid,		\
	  .ptr = (_ptr), }

struct tdx_md_map {
	u64 fid;
	void *ptr;
};

static size_t tdx_md_element_size(u64 fid)
{
	switch (TDX_MD_ELEMENT_SIZE_CODE(fid)) {
	case TDX_MD_ELEMENT_SIZE_8BITS:
		return 1;
	case TDX_MD_ELEMENT_SIZE_16BITS:
		return 2;
	case TDX_MD_ELEMENT_SIZE_32BITS:
		return 4;
	case TDX_MD_ELEMENT_SIZE_64BITS:
		return 8;
	default:
		WARN_ON_ONCE(1);
		return 0;
	}
}

static int tdx_md_read(struct tdx_md_map *maps, int nr_maps)
{
	struct tdx_md_map *m;
	int ret, i;
	u64 tmp;

	for (i = 0; i < nr_maps; i++) {
		m = &maps[i];
		ret = tdx_sys_metadata_field_read(m->fid, &tmp);
		if (ret)
			return ret;

		memcpy(m->ptr, &tmp, tdx_md_element_size(m->fid));
	}

	return 0;
}

struct tdx_info {
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
	u16 num_cpuid_config;
	int ret;
	u32 i;

	struct tdx_md_map mds[] = {
		TDX_MD_MAP(NUM_CPUID_CONFIG, &num_cpuid_config),
	};

#define TDX_INFO_MAP(_field_id, _member)			\
	TD_SYSINFO_MAP(_field_id, struct tdx_info, _member)

	struct tdx_metadata_field_mapping tdx_info_md[] = {
		TDX_INFO_MAP(ATTRS_FIXED0, attributes_fixed0),
		TDX_INFO_MAP(ATTRS_FIXED1, attributes_fixed1),
		TDX_INFO_MAP(XFAM_FIXED0, xfam_fixed0),
		TDX_INFO_MAP(XFAM_FIXED1, xfam_fixed1),
	};

	ret = tdx_enable();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		return ret;
	}

	ret = tdx_md_read(mds, ARRAY_SIZE(mds));
	if (ret)
		return ret;

	tdx_info = kzalloc(sizeof(*tdx_info) +
			   sizeof(*tdx_info->cpuid_configs) * num_cpuid_config,
			   GFP_KERNEL);
	if (!tdx_info)
		return -ENOMEM;
	tdx_info->num_cpuid_config = num_cpuid_config;

	ret = tdx_sys_metadata_read(tdx_info_md, ARRAY_SIZE(tdx_info_md), tdx_info);
	if (ret)
		return ret;

	for (i = 0; i < num_cpuid_config; i++) {
		struct kvm_tdx_cpuid_config *c = &tdx_info->cpuid_configs[i];
		u64 leaf, eax_ebx, ecx_edx;
		struct tdx_md_map cpuids[] = {
			TDX_MD_MAP(CPUID_CONFIG_LEAVES + i, &leaf),
			TDX_MD_MAP(CPUID_CONFIG_VALUES + i * 2, &eax_ebx),
			TDX_MD_MAP(CPUID_CONFIG_VALUES + i * 2 + 1, &ecx_edx),
		};

		ret = tdx_md_read(cpuids, ARRAY_SIZE(cpuids));
		if (ret)
			goto error_sys_rd;

		c->leaf = (u32)leaf;
		c->sub_leaf = leaf >> 32;
		c->eax = (u32)eax_ebx;
		c->ebx = eax_ebx >> 32;
		c->ecx = (u32)ecx_edx;
		c->edx = ecx_edx >> 32;
	}

	return 0;

error_sys_rd:
	ret = -EIO;
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

void tdx_hardware_unsetup(void)
{
	kfree(tdx_info);
}
