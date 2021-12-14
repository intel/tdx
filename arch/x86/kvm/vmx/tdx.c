// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

static u64 hkid_mask __ro_after_init;
static u8 hkid_start_pos __ro_after_init;

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
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
	pr_info("hkid start pos %d mask 0x%llx\n", hkid_start_pos, hkid_mask);

	return 0;
}
