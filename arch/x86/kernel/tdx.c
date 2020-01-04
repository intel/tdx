// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "x86/tdx: " fmt

#include <asm/tdx.h>

static inline bool cpuid_has_tdx_guest(void)
{
	u32 eax, sig[3];

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[1], &sig[2]);

	return !memcmp("IntelTDX    ", sig, 12);
}

void __init tdx_early_init(void)
{
	if (!cpuid_has_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	pr_info("Guest initialized\n");
}
