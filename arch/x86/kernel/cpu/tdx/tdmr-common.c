// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Trust Domain Extensions (TDX) memory initialization
 */
#define pr_fmt(fmt) "tdx: " fmt

#include <linux/pgtable.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include "tdmr-common.h"

/**
 * tdx_memblock_create:	Create one TDX memory block
 *
 * @start_pfn:	Start PFN of the TDX memory block
 * @end_pfn:	End PFN of the TDX memory block
 * @nid:	Node the TDX memory block belongs to
 * @data:	Type-specific TDX memory block opaque data
 *
 * Create one TDX memory block with type-specific data.
 */
struct tdx_memblock * __init tdx_memblock_create(unsigned long start_pfn,
		unsigned long end_pfn, int nid, void *data)
{
	struct tdx_memblock *tmb;

	tmb = kzalloc(sizeof(*tmb), GFP_KERNEL);
	if (!tmb)
		return NULL;

	INIT_LIST_HEAD(&tmb->list);
	tmb->start_pfn = start_pfn;
	tmb->end_pfn = end_pfn;
	tmb->data = data;

	return tmb;
}

/**
 * tdx_memblock_free:	Free the TDX memory block
 *
 * @tmb:	TDX memory block to free
 */
void __init tdx_memblock_free(struct tdx_memblock *tmb)
{
	if (!tmb)
		return;

	kfree(tmb);
}

/**
 * tdx_memory_init:	Initialize one TDX memory instance
 *
 * @tmem:	The TDX memory to initialize.
 */
void __init tdx_memory_init(struct tdx_memory *tmem)
{
	INIT_LIST_HEAD(&tmem->tmb_list);
}

/**
 * tdx_memory_destroy:	Destroy one TDX memory instance
 *
 * @tmem:	The TDX memory to destroy
 */
void __init tdx_memory_destroy(struct tdx_memory *tmem)
{
	while (!list_empty(&tmem->tmb_list)) {
		struct tdx_memblock *tmb = list_first_entry(&tmem->tmb_list,
				struct tdx_memblock, list);

		list_del(&tmb->list);
		tdx_memblock_free(tmb);
	}
}

/**
 * tdx_memory_add_block:	Add a TDX memory block to TDX memory instance
 *
 * @tmem:	The TDX memory instance to add to
 * @tmb:	The TDX memory block to add
 *
 * Add a TDX memory block to TDX memory instance in address ascending order.
 *
 * Returns 0 on success, or failure if the new block overlaps with any existing
 * ones in TDX memory.
 */
int __init tdx_memory_add_block(struct tdx_memory *tmem,
		struct tdx_memblock *tmb)
{
	struct tdx_memblock *p;

	/* Insert new @tmb to @tr in address ascending order */
	list_for_each_entry_reverse(p, &tmem->tmb_list, list) {
		if (p->start_pfn >= tmb->end_pfn)
			continue;
		/*
		 * Found memory block at lower position.  Sanity check the new
		 * block doesn't overlap with the existing one.
		 */
		if (WARN_ON_ONCE(p->end_pfn > tmb->start_pfn))
			return -EFAULT;

		break;
	}

	/*
	 * @p is either head, or valid memory block which is at lower
	 * position than @tmb.
	 */
	list_add(&tmb->list, &p->list);

	return 0;
}

/**
 * tdx_memory_merge:	Merge two TDX memory instances to one
 *
 * @tmem_dst:	The first TDX memory as destination
 * @tmem_src:	The second TDX memory as source
 *
 * Merge all TDX memory blocks in @tmem_src to @tmem_dst.  This allows caller
 * to build multiple intermediate TDX memory instances based on TDX memory type
 * (for instance, system memory, or x86 legacy PMEM) and/or NUMA locality, and
 * merge them together as final TDX memory to generate final TDMRs.
 *
 * On success, @tmem_src will be empty.  In case of any error, some TDX memory
 * blocks in @tmem_src may have already been moved to @tmem_dst.  Caller is
 * responsible for destroying both @tmem_src and @tmem_dst.
 */
int __init tdx_memory_merge(struct tdx_memory *tmem_dst,
		struct tdx_memory *tmem_src)
{
	while (!list_empty(&tmem_src->tmb_list)) {
		struct tdx_memblock *tmb = list_first_entry(&tmem_src->tmb_list,
				struct tdx_memblock, list);
		int ret;

		list_del(&tmb->list);

		ret = tdx_memory_add_block(tmem_dst, tmb);
		if (ret) {
			/*
			 * Add @tmb back to @tmem_src, so it can be properly
			 * freed by caller.
			 */
			list_add(&tmb->list, &tmem_src->tmb_list);
			return ret;
		}
	}

	return 0;
}
