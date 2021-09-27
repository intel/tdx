// SPDX-License-Identifier: GPL-2.0
/*
 * Convert all types of TDX capable memory to final TDX memory.
 */

#define pr_fmt(fmt) "tdx: " fmt

#include "tdx-tdmr.h"
#include "tdmr-sysmem.h"

int __init build_tdx_memory(void)
{
	int ret;

	ret = tdx_sysmem_build();
	if (ret)
		goto out;

out:
	if (ret)
		cleanup_subtype_tdx_memory();
	return ret;
}

/**
 * cleanup_subtype_tdx_memory: Clean up all subtypes TDX memory
 *
 * Clean up all subtypes TDX memory as resource cleanup in case of any error
 * before build_tdx_memory().
 */
void __init cleanup_subtype_tdx_memory(void)
{
	tdx_sysmem_cleanup();
}
