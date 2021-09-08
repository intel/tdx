// SPDX-License-Identifier: GPL-2.0
/*
 * Convert all types of TDX capable memory to final TDX memory.
 */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/printk.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/cache.h>

#include <asm/page_types.h>
#include <asm/tdx_host.h>

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

/**
 * construct_tdx_tdmrs:	Construct final TDMRs to cover all TDX memory
 *
 * @cmr_array:		Arrry of CMR entries
 * @cmr_num:		Number of CMR entries
 * @desc:		TDX module descriptor for constructing final TMDRs
 * @tdmr_info_array:	Array of final TDMRs
 * @tdmr_num:		Number of final TDMRs
 *
 * Construct final TDMRs to cover all TDX memory blocks in @tmem_sysmem.
 * Caller needs to allocate enough storage for @tdmr_info_array, i.e. by
 * allocating enough entries indicated by desc->max_tdmr_num.
 *
 * Upon success, all TDMRs are stored in @tdmr_info_array, with @tdmr_num
 * indicting the actual TDMR number.
 */
int __init construct_tdx_tdmrs(struct cmr_info *cmr_array, int cmr_num,
		struct tdx_module_descriptor *desc,
		struct tdmr_info *tdmr_info_array, int *tdmr_num)
{
	int ret = 0;
	int i;
	struct tdx_memblock *tmb;

	/* No TDX memory available */
	if (list_empty(&tmem_sysmem.tmb_list))
		return -EFAULT;

	ret = tdx_memory_construct_tdmrs(&tmem_sysmem, cmr_array, cmr_num,
			desc, tdmr_info_array, tdmr_num);
	if (ret) {
		pr_err("Failed to construct TDMRs\n");
		goto out;
	}

	i = 0;
	list_for_each_entry(tmb, &tmem_sysmem.tmb_list, list) {
		pr_info("TDX TDMR[%2d]: base 0x%016lx size 0x%016lx\n",
			i, tmb->start_pfn << PAGE_SHIFT,
			tmb->end_pfn << PAGE_SHIFT);
		if (tmb->pamt)
			pr_info("TDX PAMT[%2d]: base 0x%016lx size 0x%016lx\n",
				i, tmb->pamt->pamt_pfn << PAGE_SHIFT,
				tmb->pamt->total_pages << PAGE_SHIFT);
		i++;
	}

out:
	/*
	 * Always discard @tmem_sysmem no matter whether constructing TDMRs
	 * was successful or not, since it is not needed anymore.
	 */
	tdx_memory_destroy(&tmem_sysmem);
	return ret;
}
