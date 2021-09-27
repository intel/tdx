// SPDX-License-Identifier: GPL-2.0
/*
 * Convert system memory to TDX memory.
 */
#define pr_fmt(fmt) "tdx: " fmt

#include <linux/memblock.h>
#include <linux/sizes.h>
#include "tdmr-sysmem.h"

/* TDX memory instance which contains all system memory blocks */
struct tdx_memory tmem_sysmem __initdata;

unsigned long __init sysmem_pamt_alloc(struct tdx_memblock *tmb,
				unsigned long nr_pages)
{
	struct page *page;

	page = alloc_contig_pages(nr_pages, GFP_KERNEL, tmb->nid,
			NULL);
	if (!page)
		page = alloc_contig_pages(nr_pages, GFP_KERNEL, tmb->nid,
				&node_online_map);

	return page ? page_to_pfn(page) : 0;
}

void __init sysmem_pamt_free(struct tdx_memblock *tmb,
			unsigned long pamt_pfn, unsigned long nr_pages)
{
	free_contig_range(pamt_pfn, nr_pages);
}

static int __init tdx_sysmem_add_block(struct tdx_memory *tmem,
		unsigned long start_pfn, unsigned long end_pfn, int nid)
{
	struct tdx_memblock *tmb;
	int ret;

	/*
	 * Before constructing TDMRs to convert convertible memory as TDX
	 * memory, kernel checks whether all TDX memory blocks are fully
	 * covered by BIOS provided convertible memory regions (CMRs),
	 * and refuses to convert if any is not.
	 *
	 * The BIOS generated CMRs won't contain memory below 1MB.  To avoid
	 * above check failure, explicitly skip memory below 1MB as TDX
	 * memory block.  This is fine since memory below 1MB is already
	 * reserved in setup_arch(), and won't be managed by page allocator
	 * anyway.
	 */
	if (start_pfn < (SZ_1M >> PAGE_SHIFT))
		start_pfn = (SZ_1M >> PAGE_SHIFT);

	if (start_pfn >= end_pfn)
		return 0;

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
