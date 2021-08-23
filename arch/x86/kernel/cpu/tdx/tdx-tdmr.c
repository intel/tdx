// SPDX-License-Identifier: GPL-2.0
/*
 * Convert all types of TDX capable memory to final TDX memory.
 */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <asm/tdx_host.h>
#include "tdx-tdmr.h"

/*
 * Final TDX memory which contains all memory blocks that can be used by TDX.
 * Use this to generate final TDMRs which are used to configure TDX module.
 */
static struct tdx_memory tmem_all;

/*
 * Merge subtype TDX memory to final TDX memory.  In case of merge failure,
 * @final_tmem is not impacted.  And caller is responsible for cleaning up
 * @subtype_tmem, although when merge is successful, it will be empty anyway.
 */
static void __init merge_subtype_tdx_memory(struct tdx_memory *final_tmem,
		struct tdx_memory *subtype_tmem, char *subtype_name)
{
	int ret;

	/* Building TDX memory for specific type wasn't successful */
	if (!tdx_memory_minimal_tdmrs(subtype_tmem)) {
		ret = -EFAULT;
		goto out;
	}

	ret = tdx_memory_merge(final_tmem, subtype_tmem);
out:
	/*
	 * tdx_memory_merge() guarantees @final_tmem won't be impacted if it
	 * fails to merge @subtype_tmem, so nothing needs to be done for
	 * @final_tmem in case of error.
	 */
	if (ret)
		pr_err("Unable to convert %s to TDX memory\n", subtype_name);
}

/**
 * build_final_tdx_memory:	Build final TDX memory which contains all TDX
 *				capable memory blocks.
 *
 * Build final TDX memory which contains all TDX capable memory blocks by
 * merging all sub-types of TDX capable memory that have been built.  After
 * this function, all TDX capable memory blocks will be in @tmem_all.  In case
 * of any error when merging any sub-type TDX memory, the sub-type TDX memory
 * is destroyed internally.
 */
void __init build_final_tdx_memory(void)
{
	tdx_memory_init(&tmem_all);

	merge_subtype_tdx_memory(&tmem_all, &tmem_sysmem, "system memory");
	/*
	 * Always destroy @tmem_sysmem, to catch merge error in
	 * merge_subtype_tdx_memory() above.  If merge was successful, then
	 * @tmem_sysmem is already empty, and destroy it does nothing.
	 */
	tdx_memory_destroy(&tmem_sysmem);

	if (!tdx_memory_minimal_tdmrs(&tmem_all)) {
		pr_info("Disable TDX as it requires at least system memory being enabled.\n");
		return;
	}

#ifdef CONFIG_ENABLE_TDX_FOR_X86_PMEM_LEGACY
	merge_subtype_tdx_memory(&tmem_all, &tmem_legacy_pmem, "legacy PMEM");
	tdx_memory_destroy(&tmem_legacy_pmem);
#endif
}

/**
 * cleanup_subtype_tdx_memory:	Cleanup all subtypes TDX memory
 *
 * Cleanup all subtypes TDX memory as resource cleanup in case of any error
 * before build_final_tdx_memory().
 */
void __init cleanup_subtype_tdx_memory(void)
{
	tdx_memory_destroy(&tmem_sysmem);
#ifdef CONFIG_ENABLE_TDX_FOR_X86_PMEM_LEGACY
	tdx_memory_destroy(&tmem_legacy_pmem);
#endif
}

/**
 * construct_tdx_tdmrs:	Construct final TDMRs to cover all memory that can
 *			potentially be used by TDX
 *
 * @cmr_array:	Arrry of CMR entries
 * @cmr_num:	Number of CMR entries
 * @desc:	TDX module descriptor for constructing final TMDRs
 * @tdmr_array:	Array of final TDMRs
 * @tdmr_num:	Number of final TDMRs
 *
 * Construct final TDMRs to cover all TDX capable memory blocks that are
 * kept in @tmem_all.  Caller needs to allocate enough storage for @tdmr_array,
 * i.e. by allocating enough entries indicated by desc->max_tdmr_num.
 *
 * Upon success, all TDMRs are stored in @tdmr_array, with @tdmr_num indicting
 * the actual TDMR number.
 */
int __init construct_tdx_tdmrs(struct cmr_info *cmr_array, int cmr_num,
		struct tdx_module_descriptor *desc,
		struct tdmr_info *tdmr_array, int *tdmr_num)
{
	int mininal_tdmrs, ret = 0;
	bool merge_non_contig = false;

	mininal_tdmrs = tdx_memory_minimal_tdmrs(&tmem_all);
	if (!mininal_tdmrs) {
		pr_err("No usable TDX memory.\n");
		ret = -EFAULT;
		goto out;
	}

	/* Sanity check against CMRs first */
	ret = tdx_memory_sanity_check_cmrs(&tmem_all, cmr_array, cmr_num);
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	/* Handle rare case that TDMR ranges are two discrete */
	while ((mininal_tdmrs = tdx_memory_minimal_tdmrs(&tmem_all)) >
			desc->max_tdmr_num) {
		int new_minimal_tdmrs;

		tdx_memory_merge_tdmr_ranges(&tmem_all, merge_non_contig,
				false);
		new_minimal_tdmrs = tdx_memory_minimal_tdmrs(&tmem_all);
		/*
		 * While there are still contiguous TDMR ranges, merge
		 * them first.
		 */
		if (new_minimal_tdmrs < mininal_tdmrs)
			continue;
		/* Try harder to merge non-contiguous TDMR ranges */
		merge_non_contig = true;
	}

	ret = tdx_memory_construct_tdmrs(&tmem_all, cmr_array, cmr_num,
			desc, tdmr_array, tdmr_num);
	if (ret) {
		pr_err("Failed to construct TDMRs\n");
		goto out;
	}

out:
	/*
	 * Keep @tmem_all if constructing TDMRs was successfully done, since
	 * memory hotplug needs it to check whether new memory can be added
	 * or not.
	 */
	if (ret)
		tdx_memory_destroy(&tmem_all);
	return ret;
}

/**
 * range_is_tdx_memory:		Check whether range is TDX memory
 *
 * @start:	Range start physical address
 * @end:	Range end physical address
 *
 * Check whether given range is TDX memory.  This can be helpful when caller
 * wants to see the memory range was originally covered by TDX TDMRs and make
 * properly decision (such as whether to allow memory online/offline).
 *
 * This function should be called after TDX module is properly initialized.
 */
bool range_is_tdx_memory(phys_addr_t start, phys_addr_t end)
{
	struct tdx_memblock_iter iter;

	/*
	 * Use TDX memory blocks in tmem_all to check whether target range is
	 * covered by TDMR, instead of using TDMRs, since former is a lot easier
	 * due to: 1) target range may cross multiple TDMRs; 2) need to check
	 * target range against reserved areas in TDMRs to see whether target
	 * range is truely TDX memory.
	 */
	for_each_tdx_memblock(&iter, &tmem_all) {
		if (iter.tmb->start <= start && iter.tmb->end >= end)
			return true;
	}

	return false;
}
