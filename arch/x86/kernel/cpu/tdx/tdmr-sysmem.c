// SPDX-License-Identifier: GPL-2.0
/*
 * Convert system memory to TDX memory.
 */
#define pr_fmt(fmt) "tdx: " fmt

#include <linux/memblock.h>
#include "tdmr-sysmem.h"

/* TDX memory instance which contains all system memory blocks */
struct tdx_memory tmem_sysmem __initdata;

/* Intermediate TDX memory instances for each node */
static struct tdx_memory tmem_sysmem_nodes[MAX_NUMNODES] __initdata;

static void __init sysmem_tmb_free(struct tdx_memblock *tmb) { }

static struct tdx_memtype_ops sysmem_ops = {
	.tmb_free = sysmem_tmb_free,
};

static int __init tdx_sysmem_add_block(struct tdx_memory *tmem,
		unsigned long start_pfn, unsigned long end_pfn, int nid)
{
	struct tdx_memblock *tmb;

	tmb = tdx_memblock_create(start_pfn << PAGE_SHIFT,
			end_pfn << PAGE_SHIFT, nid, NULL,
			&sysmem_ops);
	if (!tmb)
		return -ENOMEM;

	return tdx_memory_add_block(tmem, tmb);
}

static int __init __tdx_sysmem_build(void)
{
	unsigned long start_pfn, end_pfn;
	unsigned long last_tdmr_end_pfn;
	int last_nid, nid, i, ret;
	struct tdx_memory *tmem_nid;

	last_nid = MAX_NUMNODES;
	last_tdmr_end_pfn = 0;
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		/*
		 * If two boundary of two adjacent nodes is not 1G
		 * aligned, the last TDMR range of first node and the
		 * first TDMR range of second will overlap.  Two
		 * overlapping TDMR ranges are merged unconditionally,
		 * which would cause PAMT being allocated from one
		 * node to cover both TDMR ranges (which both could
		 * be large).  This may cause bad performance when
		 * access part of TDMR memory (due to remote PAMT
		 * access).
		 *
		 * In this case, put all memory blocks, or part of
		 * big memory block that within the first 1G area of
		 * second node to TDX memory of previous node, so that
		 * they can just be merged to previous one without
		 * impacting TDMR ranges of second node.
		 */
		if (last_nid != MAX_NUMNODES && nid != last_nid) {
			unsigned long tdmr_start_pfn;

			tdmr_start_pfn = ALIGN_DOWN(start_pfn,
					TDMR_PFN_ALIGNMENT);

			/*
			 * Still working on TDX memory for previous node,
			 * otherwise it's bug.
			 */
			WARN_ON_ONCE(tmem_nid !=
					&tmem_sysmem_nodes[last_nid]);

			if (tdmr_start_pfn < last_tdmr_end_pfn) {
				unsigned long last_end_pfn = end_pfn;

				if (last_end_pfn > last_tdmr_end_pfn)
					last_end_pfn = last_tdmr_end_pfn;

				ret = tdx_sysmem_add_block(tmem_nid,
						start_pfn, last_end_pfn, nid);
				if (ret)
					goto err;

				start_pfn = last_end_pfn;

				last_tdmr_end_pfn = ALIGN(last_end_pfn,
						TDMR_PFN_ALIGNMENT);

				/*
				 * If the block is fully within first 1G area
				 * that is overlapping with previous node's
				 * last TDMR range, loop to next block and
				 * handle again.
				 */
				if (start_pfn >= end_pfn)
					continue;
			}

			/*
			 * Done with building TDX memory for previous node.
			 * Merge all contiguous TDMR ranges to reduce final
			 * TDMR ranges.
			 */
			tdx_memory_merge_tdmr_ranges(tmem_nid, false, true);

			/* Loop into building TDX memory for next node. */
			last_nid = nid;
			tmem_nid = &tmem_sysmem_nodes[nid];
		}

		/* Special handling for first memory block */
		if (last_nid == MAX_NUMNODES) {
			last_nid = nid;
			tmem_nid = &tmem_sysmem_nodes[nid];
		}

		/* Make sure working on correct TDX memory */
		WARN_ON_ONCE(tmem_nid != &tmem_sysmem_nodes[nid]);

		ret = tdx_sysmem_add_block(tmem_nid, start_pfn,
				end_pfn, nid);
		if (ret)
			goto err;

		last_tdmr_end_pfn = ALIGN(end_pfn, TDMR_PFN_ALIGNMENT);
	}

	/* Haven't finalized TDX memory for last node yet, do it */
	tdx_memory_merge_tdmr_ranges(tmem_nid, false, true);

	/* Now merge all TDX memory instances for all nodes into single one */
	for_each_online_node(nid) {
		ret = tdx_memory_merge(&tmem_sysmem, &tmem_sysmem_nodes[nid]);
		if (ret)
			goto err;
	}

	return 0;
err:
	tdx_sysmem_cleanup();
	return ret;
}

static void __init tdx_sysmem_init(void)
{
	int nid;

	tdx_memory_init(&tmem_sysmem);
	for_each_online_node(nid)
		tdx_memory_init(&tmem_sysmem_nodes[nid]);
}

/**
 * tdx_sysmem_build:	Build TDX memory with all system memory blocks across
 *			all NUMA nodes
 *
 * Build TDX memory which contains all system memory for all NUMA nodes, by
 * gathering each node's all memory blocks as TDX memory blocks, and merge them
 * together to @tmem_sysmem.
 */
int __init tdx_sysmem_build(void)
{
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SEAM))
		return 0;

	pr_info("Build all system memory blocks as TDX memory.\n");

	tdx_sysmem_init();

	ret = __tdx_sysmem_build();
	if (ret)
		goto err;

	return 0;
err:
	pr_err("Fail to build system meory as TDX memory.\n");
	tdx_sysmem_cleanup();
	return ret;
}

/**
 * tdx_sysmem_cleanup:	Cleanup TDX system memory
 *
 * Cleanup TDX memory instances built from system memory for all NUMA nodes.
 */
void __init tdx_sysmem_cleanup(void)
{
	int nid;

	for_each_online_node(nid)
		tdx_memory_destroy(&tmem_sysmem_nodes[nid]);
	tdx_memory_destroy(&tmem_sysmem);
}
