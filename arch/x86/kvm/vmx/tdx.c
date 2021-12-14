// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/kvm_host.h>

#include <asm/tdx_host.h>

#include "capabilities.h"
#include "tdx_errno.h"
#include "tdx_ops.h"
#include "x86_ops.h"
#include "cpuid.h"
#include "lapic.h"
#include "tdx.h"

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

	if (!detect_tdx())
		return -ENODEV;

	if (WARN_ON_ONCE(x86_ops->tlb_remote_flush))
		return -EIO;

	max_pa = cpuid_eax(0x80000008) & 0xff;
	hkid_start_pos = boot_cpu_data.x86_phys_bits;
	hkid_mask = GENMASK_ULL(max_pa - 1, hkid_start_pos);

	return 0;
}
