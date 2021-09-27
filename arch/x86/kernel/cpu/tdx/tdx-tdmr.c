// SPDX-License-Identifier: GPL-2.0
/*
 * Convert all types of TDX capable memory to final TDX memory.
 */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/types.h>
#include <linux/errno.h>
#include "tdx-tdmr.h"

/*
 * Final TDX memory which contains all memory blocks that can be used by TDX.
 * Use this to construct final TDMRs.
 */
struct tdx_memory tmem_all __initdata;

/*
 * Merge subtype TDX memory to final TDX memory.
 */
static int __init merge_subtype_tdx_memory(struct tdx_memory *final_tmem,
		struct tdx_memory *subtype_tmem, char *subtype_name)
{
	int ret;

	ret = tdx_memory_merge(final_tmem, subtype_tmem);
	if (ret)
		pr_err("Fail to merge %s as TDX memory\n", subtype_name);

	return ret;
}

/**
 * build_final_tdx_memory:	Build final TDX memory which contains all TDX
 *				capable memory blocks.
 *
 * Build final TDX memory which contains all TDX capable memory blocks by
 * merging all sub-types of TDX capable memory that have been built.  After
 * this function, all TDX capable memory blocks will be in @tmem_all.  In case
 * of any error, all TDX memory intances are destroyed internally.
 */
int __init build_final_tdx_memory(void)
{
	int ret;

	tdx_memory_init(&tmem_all);

	ret = merge_subtype_tdx_memory(&tmem_all, &tmem_sysmem,
			"system memory");
	if (ret)
		goto err;

#ifdef CONFIG_ENABLE_TDX_FOR_X86_PMEM_LEGACY
	ret = merge_subtype_tdx_memory(&tmem_all, &tmem_legacy_pmem,
			"legacy PMEM");
#endif
	if (ret)
		goto err;

	return 0;
err:
	tdx_memory_destroy(&tmem_all);
	cleanup_subtype_tdx_memory();
	return ret;
}

/**
 * cleanup_subtype_tdx_memory:	Clean up all subtypes TDX memory
 *
 * Clean up all subtypes TDX memory as resource cleanup in case of any error
 * before build_final_tdx_memory().
 */
void __init cleanup_subtype_tdx_memory(void)
{
	tdx_sysmem_cleanup();
#ifdef CONFIG_ENABLE_TDX_FOR_X86_PMEM_LEGACY
	tdx_legacy_pmem_cleanup();
#endif
}
