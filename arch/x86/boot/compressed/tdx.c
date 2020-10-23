// SPDX-License-Identifier: GPL-2.0
/*
 * tdx.c - Early boot code for TDX
 */

#include <asm/tdx.h>

static int __ro_after_init tdx_guest = -1;

int cmdline_find_option_bool(const char *option);

static inline bool native_cpuid_has_tdx_guest(void)
{
	u32 eax = TDX_CPUID_LEAF_ID, signature[3] = {0};

	if (native_cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	native_cpuid(&eax, &signature[0], &signature[1], &signature[2]);

	if (memcmp("IntelTDX    ", signature, 12))
		return false;

	return true;
}

bool is_tdx_guest(void)
{
	if (tdx_guest < 0)
		tdx_guest = native_cpuid_has_tdx_guest() ||
			    cmdline_find_option_bool("force_tdx_guest");

	return !!tdx_guest;
}
