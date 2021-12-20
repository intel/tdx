// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "tdx.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

static bool __read_mostly enable_tdx = true;
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

/* Capabilities of KVM + the TDX module. */
struct tdx_capabilities tdx_caps;

static u64 hkid_mask __ro_after_init;
static u8 hkid_start_pos __ro_after_init;

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
	return type == KVM_X86_TDX_VM && READ_ONCE(enable_tdx);
}

static int __init __tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	u32 max_pa;

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

	max_pa = cpuid_eax(0x80000008) & 0xff;
	hkid_start_pos = boot_cpu_data.x86_phys_bits;
	hkid_mask = GENMASK_ULL(max_pa - 1, hkid_start_pos);

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
