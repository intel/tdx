// SPDX-License-Identifier: GPL-2.0
/*
 * Convert system memory to TDX memory.
 */
#define pr_fmt(fmt) "tdx: " fmt

#include <linux/memblock.h>
#include "tdmr-sysmem.h"

/* TDX memory instance which contains all system memory blocks */
struct tdx_memory tmem_sysmem __initdata;

static int __init tdx_sysmem_add_block(struct tdx_memory *tmem,
		unsigned long start_pfn, unsigned long end_pfn, int nid)
{
	struct tdx_memblock *tmb;
	int ret;

	tmb = tdx_memblock_create(start_pfn, end_pfn, nid, NULL);
	if (!tmb)
		return -ENOMEM;

	ret = tdx_memory_add_block(tmem, tmb);
	if (ret) {
		tdx_memblock_free(tmb);
		return ret;
	}

	return 0;
}

/**
 * tdx_sysmem_build:	Build TDX memory for system memory
 *
 * Build TDX memory @tmem_sysmem for system memory, by gathering all memory
 * blocks from memblock.
 */
int __init tdx_sysmem_build(void)
{
	unsigned long start_pfn, end_pfn;
	int i, nid, ret;

	pr_info("Build all system memory blocks as TDX memory.\n");

	tdx_memory_init(&tmem_sysmem);

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		ret = tdx_sysmem_add_block(&tmem_sysmem, start_pfn, end_pfn,
				nid);
		if (ret)
			goto err;
	}

	return 0;
err:
	pr_err("Fail to build system memory as TDX memory.\n");
	tdx_sysmem_cleanup();
	return ret;
}

/**
 * tdx_sysmem_cleanup:	Clean up TDX memory for system memory
 *
 * Clean up TDX memory instances built from system memory for all NUMA nodes.
 */
void __init tdx_sysmem_cleanup(void)
{
	tdx_memory_destroy(&tmem_sysmem);
}
