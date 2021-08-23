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

/*
 * Create one TDMR range to cover given TDX memory block.  Initially one TDMR
 * range covers one TDX memory block.  More TDX memory blocks can be added to
 * it later.  TDMR range may be extended when new block is added to cover all
 * blocks.
 */
static struct tdx_tdmr_range * __init tdmr_range_create(
		struct tdx_memblock *tmb)
{
	struct tdx_tdmr_range *tr = kzalloc(sizeof(*tr), GFP_KERNEL);

	if (tr) {
		INIT_LIST_HEAD(&tr->tmb_list);

		tr->start_pfn = ALIGN_DOWN(tmb->start, TDMR_ALIGNMENT) >>
			PAGE_SHIFT;
		tr->end_pfn = ALIGN(tmb->end, TDMR_ALIGNMENT) >> PAGE_SHIFT;

		list_add_tail(&tmb->list, &tr->tmb_list);
	}

	return tr;
}

static void __init tdmr_range_free(struct tdx_tdmr_range *tr)
{
	if (!tr)
		return;

	/* Free all TDX memory blocks within the TDMR range. */
	while (!list_empty(&tr->tmb_list)) {
		struct tdx_memblock *tmb = list_first_entry(&tr->tmb_list,
				struct tdx_memblock, list);

		list_del(&tmb->list);
		tdx_memblock_free(tmb);
	}

	kfree(tr);
}

/*
 * Add a TDX memory block to existing TDMR range in address ascending order.
 * It doesn't check or extend TDMR range.  Caller must guarantee that.
 *
 * Return error if the new block overlaps with any existing.
 */
#define ADD_BLOCK_ERROR_MSG	\
	"Unable to add memory block [0x%llx, 0x%llx]: conflicts with [0x%llx, 0x%llx]\n"
static int __init tdmr_range_add_block(struct tdx_tdmr_range *tr,
		struct tdx_memblock *tmb)
{
	struct tdx_memblock *p;

	/* Insert new @tmb to @tr in address ascending order */
	list_for_each_entry_reverse(p, &tr->tmb_list, list) {
		if (p->start >= tmb->end)
			continue;
		/*
		 * Found memory block at lower position (hopefully), and do
		 * sanity check the new memory block doesn't overlap or fully
		 * include the existing memory block.
		 */
		if (p->end > tmb->start) {
			pr_err(ADD_BLOCK_ERROR_MSG, tmb->start, tmb->end,
					p->start, p->end);
			return -EFAULT;
		}

		break;
	}

	/*
	 * @p is either head, or valid memory block which is at lower
	 * position than @tmb.
	 */
	list_add(&tmb->list, &p->list);

	return 0;
}

/*
 * Merge second TDMR range @tr2 to the first one @tr1.
 *
 * Note on failure, some memory blocks (possibly even different memory type)
 * in @tr2 may have already been moved to @tr1.
 */
static int __init tdmr_range_merge(struct tdx_tdmr_range *tr1,
		struct tdx_tdmr_range *tr2)
{
	int ret = 0;

	/*
	 * Cannot do as simple list_splice_tail_init() since although memory
	 * blocks within each TDMR range are in ascending order, but memory
	 * blocks in @tr2 may within two blocks in @tr1.
	 */
	while (!list_empty(&tr2->tmb_list)) {
		struct tdx_memblock *tmb = list_first_entry(&tr2->tmb_list,
				struct tdx_memblock, list);

		list_del(&tmb->list);
		ret = tdmr_range_add_block(tr1, tmb);
		if (ret) {
			/* Add @tmb back so it can be properly freed */
			list_add(&tmb->list, &tr2->tmb_list);
			return ret;
		}
	}

	/* Extend TDMR range */
	if (tr2->start_pfn < tr1->start_pfn)
		tr1->start_pfn = tr2->start_pfn;
	if (tr2->end_pfn > tr1->end_pfn)
		tr1->end_pfn = tr2->end_pfn;

	return ret;
}

/*
 * Add new TDMR range (i.e. new created one when adding memory block) to TDX
 * memory.  The new TDMR range will be merged with existing ones when it
 * overlaps with any existing TDMR range.
 *
 * Note on failure, caller should be responsible for freeing @new_tr, and
 * TDX memory blocks originally within @tmem may have been moved to @new_tr.
 */
static int __init tdx_memory_add_tdmr_range(struct tdx_memory *tmem,
		struct tdx_tdmr_range *new_tr)
{
	struct tdx_tdmr_range *first_tr, *last_tr;
	int ret = 0;

	/* Skip lower TDMR ranges that don't overlap with @new_tr */
	list_for_each_entry(first_tr, &tmem->tr_list, list)
		if (first_tr->end_pfn > new_tr->start_pfn)
			break;
	/* Get the first (lower) TDMR range that doesn't overlap with @new_tr */
	first_tr = list_prev_entry(first_tr, list);

	/* Skip higher TDMR ranges that don't overlap with @new_tr */
	list_for_each_entry_reverse(last_tr, &tmem->tr_list, list)
		if (last_tr->start_pfn < new_tr->end_pfn)
			break;
	/* Get the last (higher) TDMR range that doesn't overlap with @new_tr */
	last_tr = list_next_entry(last_tr, list);

	/* Merge all existing TDMR ranges which overlap with @new_tr to it */
	while (list_next_entry(first_tr, list) != last_tr) {
		struct tdx_tdmr_range *tr = list_next_entry(first_tr, list);

		list_del(&tr->list);

		ret = tdmr_range_merge(new_tr, tr);
		if (ret) {
			/* Add @tr back so it can be properly freed */
			list_add(&tr->list, &first_tr->list);
			return ret;
		}
	}

	/* Otherwise, add @new_tr to list */
	list_add(&new_tr->list, &first_tr->list);

	return 0;
}

/******************************* External APIs *****************************/

/**
 * tdx_memblock_create:	Create one TDX memory block
 *
 * @start:	Start address of the TDX memory block
 * @end:	End address
 * @nid:	Node the memory lock belongs to
 * @data:	Type-specific opaque data
 * @ops:	Type-specific ops
 *
 * Create one TDX memory block object with type-specific data and ops.
 */
struct tdx_memblock * __init tdx_memblock_create(phys_addr_t start,
		phys_addr_t end, int nid, void *data,
		struct tdx_memtype_ops *ops)
{
	struct tdx_memblock *tmb;

	tmb = kzalloc(sizeof(*tmb), GFP_KERNEL);
	if (!tmb)
		return NULL;

	INIT_LIST_HEAD(&tmb->list);
	tmb->start = start;
	tmb->end = end;
	tmb->data = data;
	tmb->ops = ops;

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

	tmb->ops->tmb_free(tmb);
	kfree(tmb);
}

/**
 * tdx_memory_init:	Initialize TDX memory
 *
 * @tmem:	TDX memory to initialize.
 */
void __init tdx_memory_init(struct tdx_memory *tmem)
{
	INIT_LIST_HEAD(&tmem->tr_list);
	INIT_LIST_HEAD(&tmem->pamt_list);
}

/**
 * tdx_memory_destroy:	Destroy TDX memory
 *
 * @tmem:	TDX memory to destroy
 */
void __init tdx_memory_destroy(struct tdx_memory *tmem)
{
	while (!list_empty(&tmem->tr_list)) {
		struct tdx_tdmr_range *tr = list_first_entry(&tmem->tr_list,
				struct tdx_tdmr_range, list);

		list_del(&tr->list);
		tdmr_range_free(tr);
	}
}

/**
 * tdx_memory_add_block:	Add a new memory block to TDX memory
 *
 * @tmem:	TDX memory to add to
 * @tmb:	Memory block to add
 *
 * Add new TDX memory block to TDX memory.  Internally, if the TDMR range covers
 * the new block overlaps with any existing TDMR range, the new block is merged
 * to the overlapping TDMR range, with its range extended.  Otherwise a new TDMR
 * range is created to cover the new block.
 */
int __init tdx_memory_add_block(struct tdx_memory *tmem,
		struct tdx_memblock *tmb)
{
	struct tdx_tdmr_range *tr;
	int ret;

	tr = tdmr_range_create(tmb);
	if (!tr)
		return -ENOMEM;

	ret = tdx_memory_add_tdmr_range(tmem, tr);
	if (ret)
		tdmr_range_free(tr);

	return ret;
}
