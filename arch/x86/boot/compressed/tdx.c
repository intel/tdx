// SPDX-License-Identifier: GPL-2.0
/*
 * tdx.c - Early boot code for TDX
 */

#include "../cpuflags.h"
#include "../string.h"

#define TDX_CPUID_LEAF_ID                       0x21

static int tdx_guest = -1;

static inline bool early_cpuid_has_tdx_guest(void)
{
	u32 eax = TDX_CPUID_LEAF_ID, sig[3] = {0};

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[1], &sig[2]);

	return !memcmp("IntelTDX    ", sig, 12);
}

bool early_is_tdx_guest(void)
{
	if (tdx_guest < 0)
		tdx_guest = early_cpuid_has_tdx_guest();

	return !!tdx_guest;
}
