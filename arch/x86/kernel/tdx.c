// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "x86/tdx: " fmt

#include <linux/protected_guest.h>

#include <asm/tdx.h>

static inline bool cpuid_has_tdx_guest(void)
{
	u32 eax, sig[3];

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2], &sig[1]);

	return !memcmp("IntelTDX    ", sig, 12);
}

bool tdx_prot_guest_has(unsigned long flag)
{
	switch (flag) {
	case PATTR_GUEST_TDX:
		return cpu_feature_enabled(X86_FEATURE_TDX_GUEST);
	}

	return false;
}
EXPORT_SYMBOL_GPL(tdx_prot_guest_has);

void __init tdx_early_init(void)
{
	if (!cpuid_has_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	pr_info("Guest initialized\n");
}
