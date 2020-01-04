// SPDX-License-Identifier: GPL-2.0
/*
 * tdx.c - Early boot code for TDX
 */

#include "../cpuflags.h"
#include "../string.h"

#define TDX_CPUID_LEAF_ID                       0x21

static bool tdx_guest_detected;

void early_tdx_detect(void)
{
	u32 eax, sig[3];

	if (cpuid_max_leaf() < TDX_CPUID_LEAF_ID)
		return;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp("IntelTDX    ", sig, 12))
		return;

	/* Cache TDX guest feature status */
	tdx_guest_detected = true;
}

bool early_is_tdx_guest(void)
{
	return tdx_guest_detected;
}
