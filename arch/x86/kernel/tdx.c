// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <asm/tdx.h>

bool is_tdx_guest(void)
{
	static int tdx_guest = -1;
	u32 eax, sig[3];

	if (tdx_guest >= 0)
		goto done;

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID) {
		tdx_guest = 0;
		goto done;
	}

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2], &sig[1]);

	tdx_guest = !memcmp("IntelTDX    ", sig, 12);

done:
	return !!tdx_guest;
}

void __init tdx_early_init(void)
{
	if (!is_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	pr_info("Guest initialized\n");
}
