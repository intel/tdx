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

/* Check whether first range is fully covered by second */
static bool __init is_range_fully_covered(u64 r1_start, u64 r1_end,
		u64 r2_start, u64 r2_end)
{
	return (r1_start >= r2_start && r1_end <= r2_end) ? true : false;
}

/* Check whether physical address range is covered by CMR or not. */
static bool __init phys_range_covered_by_cmrs(struct cmr_info *cmr_array,
		int cmr_num, phys_addr_t start, phys_addr_t end)
{
	int i;

	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		if (is_range_fully_covered((u64)start, (u64)end,
					cmr->base, cmr->base + cmr->size))
			return true;
	}

	return false;
}

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
		/*
		 * PAMT is not allocated here, but must be allocated after
		 * all TDMR ranges are finalized.
		 */
	}

	return tr;
}

static void __init tdmr_range_free(struct tdx_tdmr_range *tr)
{
	if (!tr)
		return;

	/*
	 * Free all TDX memory blocks within the TDMR range.  PAMTs are freed
	 * in tdx_memory_destroy() before freeing all TDMR ranges.
	 */
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
 * Merge second TDMR range @tr2 to the first one @tr1, with assumption they
 * don't overlap.
 */
#define MERGE_NON_CONTIG_TR_MSG	\
	"Merge TDMR ranges with hole: [0x%lx, 0x%lx], [0x%lx, 0x%lx] -> [0x%lx, 0x%lx].  PAMT may be wasted for the hole.\n"
static void __init tdmr_range_merge_non_overlapping(struct tdx_tdmr_range *tr1,
		struct tdx_tdmr_range *tr2)
{
	/* Expecting non-overlapping TDMR ranges */
	WARN_ON_ONCE(tr1->end_pfn > tr2->start_pfn);
	/*
	 * Merging TDMR ranges with address hole may result in PAMT being
	 * allocated for the hole (which is wasteful), i.e. when there's one
	 * TDMR covers entire TDMR range.  Give a msg to let user know.
	 */
	if (unlikely(tr1->end_pfn < tr2->start_pfn))
		pr_info(MERGE_NON_CONTIG_TR_MSG, tr1->start_pfn << PAGE_SHIFT,
				tr1->end_pfn << PAGE_SHIFT,
				tr2->start_pfn << PAGE_SHIFT,
				tr2->end_pfn << PAGE_SHIFT,
				tr1->start_pfn << PAGE_SHIFT,
				tr2->end_pfn << PAGE_SHIFT);

	/* Move TDX memory blocks in @tr2 to @tr1, and empty @tr2. */
	list_splice_tail_init(&tr2->tmb_list, &tr1->tmb_list);
	/* Extend @tr1's address range */
	tr1->end_pfn = tr2->end_pfn;
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

	/* PAMT is only allocated after final TDMR ranges are finalized. */
	if (WARN_ON_ONCE(!list_empty(&tmem->pamt_list) || new_tr->pamt))
		return -EFAULT;

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

/*
 * Mark TDX memory as @duplicated.  Destroying a duplicated TDX memory will
 * only free common data structures, but will not call memory type specific
 * callbacks to truely free TDX memory block, etc.
 */
static void __init tdx_memory_set_duplicated(struct tdx_memory *tmem,
		bool duplicated)
{
	struct tdx_memblock_iter iter;

	for_each_tdx_memblock(&iter, tmem)
		iter.tmb->duplicated = duplicated;
}

/*
 * Create a duplicated TDX memory based on @tmem.  This is only supposed to be
 * used to preserve an intermediate TDX memory instance during TDX memory merge
 * so any merge failure won't impact original one.
 */
static int __init tdx_memory_duplicate(struct tdx_memory *tmem,
		struct tdx_memory *tmemdup)
{
	struct tdx_tdmr_range *tr;
	struct tdx_memblock *tmb;
	int ret = 0;

	tdx_memory_init(tmemdup);

	list_for_each_entry(tr, &tmem->tr_list, list) {
		struct tdx_tdmr_range *new_tr;

		new_tr = kzalloc(sizeof(*new_tr), GFP_KERNEL);
		if (!new_tr) {
			ret = -ENOMEM;
			goto err;
		}

		new_tr->start_pfn = tr->start_pfn;
		new_tr->end_pfn = tr->end_pfn;
		INIT_LIST_HEAD(&new_tr->tmb_list);
		/*
		 * Add @new_tr to @tmemdup so it can be properly freed
		 * when adding memory blocks to it fails.
		 */
		list_add_tail(&new_tr->list, &tmemdup->tr_list);

		/* Add memory blocks to it */
		list_for_each_entry(tmb, &tr->tmb_list, list) {
			struct tdx_memblock *new_tmb =
				kzalloc(sizeof(*new_tmb), GFP_KERNEL);

			if (!new_tmb) {
				ret = -ENOMEM;
				goto err;
			}

			memcpy(new_tmb, tmb, sizeof(*tmb));
			INIT_LIST_HEAD(&new_tmb->list);
			/* Mark it as duplicated one */
			new_tmb->duplicated = true;
			list_add_tail(&new_tmb->list, &new_tr->tmb_list);
		}
	}

	return 0;
err:
	tdx_memory_destroy(tmemdup);
	return ret;
}

/*
 * Destroy TDX memory @tmem_dst and replace it with @tmem_src.  It is only
 * supposed to be used when @tmem_dst is a duplicated TDX memory during merging
 * multiple TDX memory instances, and is not required anymore.
 */
static void __init tdx_memory_replace(struct tdx_memory *tmem_dst,
		struct tdx_memory *tmem_src)
{
	/* Free all memory blocks and TDMR ranges in @tmem_dst */
	tdx_memory_destroy(tmem_dst);

	list_splice_tail_init(&tmem_src->tr_list, &tmem_dst->tr_list);
}

/*
 * Commit changes made to duplication @tmemdup to original @tmem.  It is done
 * by mark @tmem as duplicated, mark @tmemdup as non-duplicated, and replace
 * @tmem as @tmemdup
 */
static void __init tdx_memory_commit_duplicated(struct tdx_memory *tmem,
		struct tdx_memory *tmemdup)
{
	tdx_memory_set_duplicated(tmem, true);
	tdx_memory_set_duplicated(tmemdup, false);
	tdx_memory_replace(tmem, tmemdup);
}


/*
 * Merge TDX memory @tmem_src to @tmem_dst without preserving @tmem_dst and
 * @tmem_src when merge fails.  This is only supposed to be used for two
 * duplicated TDX memory instances.
 */
static int __init tdx_memory_merge_no_preserve(struct tdx_memory *tmem_dst,
		struct tdx_memory *tmem_src)
{
	int ret = 0;

	/*
	 * Cannot do simple list_splice_tail_init() since although TDMR ranges
	 * in each TDX memory instance are already in ascending order, but
	 * cannot guarantee all TDMR ranges in @tmem_src are above those in
	 * @tmem_dst.
	 */
	while (!list_empty(&tmem_src->tr_list)) {
		struct tdx_tdmr_range *tr = list_first_entry(&tmem_src->tr_list,
				struct tdx_tdmr_range, list);

		list_del(&tr->list);

		ret = tdx_memory_add_tdmr_range(tmem_dst, tr);
		if (ret) {
			/* Add @tr back so it can be properly freed */
			list_add(&tr->list, &tmem_src->tr_list);
			return ret;
		}
	}

	return 0;
}

/*
 * Merge TDX memory @tmem_src to @tmem_dst with both properly preserved.
 *
 * On success, @tmem_src will be empty.  In case of error, both @tmem_dst and
 * @tmem_src remain unchanged.
 */
static int __init tdx_memory_merge_preserve(struct tdx_memory *tmem_dst,
		struct tdx_memory *tmem_src)
{
	struct tdx_memory tmemdup_dst, tmemdup_src;
	int ret = 0;

	/* PAMT is only allocated after final TDMR ranges are finalized. */
	if (WARN_ON_ONCE(!list_empty(&tmem_dst->pamt_list) ||
				!list_empty(&tmem_src->pamt_list)))
		return -EFAULT;

	/*
	 * Preserve @tmem_dst and @tmem_src by duplicating them.  Further merge
	 * will be done against duplicated ones.
	 */
	ret = tdx_memory_duplicate(tmem_dst, &tmemdup_dst);
	if (ret)
		goto out;

	ret = tdx_memory_duplicate(tmem_src, &tmemdup_src);
	if (ret)
		goto out;

	ret = tdx_memory_merge_no_preserve(&tmemdup_dst, &tmemdup_src);
	if (ret)
		goto out;

	tdx_memory_commit_duplicated(tmem_dst, &tmemdup_dst);

	/* Destroy @tmem_src since it has been successfully merged */
	tdx_memory_set_duplicated(tmem_src, true);
	tdx_memory_destroy(tmem_src);

	return 0;
out:
	tdx_memory_destroy(&tmemdup_src);
	tdx_memory_destroy(&tmemdup_dst);
	return ret;
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

	/* Don't truely free a duplicated TDX memory block */
	if (!tmb->duplicated)
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
	/*
	 * Destroy PAMT before destroying TDMR ranges (and memory blocks), since
	 * PAMT is allocated on basis of TDMR range.
	 */
	while (!list_empty(&tmem->pamt_list)) {
		struct tdx_pamt *pamt = list_first_entry(&tmem->pamt_list,
				struct tdx_pamt, list);

		list_del(&pamt->list);
		pamt->tmb->ops->pamt_free(pamt->tmb, pamt->pamt_pfn,
				pamt->total_pages);
		kfree(pamt);
	}

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

/**
 * tdx_memory_merge_tdmr_ranges:	Merge TDMR ranges within TDX memory
 *
 * @tmem:		TDX memory
 * @merge_non_contig:	Whether to merge non-contiguous TDMR ranges
 * @merge_all:		Whether to merge all concerned TDMR ranges
 *
 * Merge TDMR ranges within TDX memory.  This can be used to reduce number of
 * TDMR ranges within one TDX memory, when otherwise the number of final TDMRs
 * may exceed maximum number TDX can support (one TDMR cannot cross two TDMR
 * ranges).  @merge_non_contig indicates whether to merge non-contiguous TDMR
 * ranges, which are only supposed to be merged after merging all contiguous
 * TDMR ranges, because merging non-contiguous TDMR ranges will result in
 * including big address hole (one or multiple GBs) into final TDMRs and
 * allocating unnecessary PAMT to cover it.  @merge_all indicate whether to
 * only merge all concerned TDMRs (contiguous only, or all), or just merge
 * once.
 *
 * Note this function doesn't deal with NUMA locality, but simply loop over
 * all TDMRs and merge.
 */
void __init tdx_memory_merge_tdmr_ranges(struct tdx_memory *tmem,
		bool merge_non_contig, bool merge_all)
{
	struct tdx_tdmr_range *tr, *prev_tr;

	list_for_each_entry_safe_reverse(tr, prev_tr, &tmem->tr_list, list) {
		/* If there's only one TDMR range left, just return */
		if (list_entry_is_head(prev_tr, &tmem->tr_list, list))
			return;

		/* TDMR range cannot overlap.  Just try to catch bug.*/
		WARN_ON_ONCE(prev_tr->end_pfn > tr->start_pfn);

		/*
		 * Skip non-contiguous TDMR ranges when @merge_non_contig is
		 * not true.
		 */
		if (!merge_non_contig && (prev_tr->end_pfn < tr->start_pfn))
			continue;

		list_del(&tr->list);
		tdmr_range_merge_non_overlapping(prev_tr, tr);
		tdmr_range_free(tr);

		if (!merge_all)
			return;
	}
}

/**
 * tdx_memory_minimal_tdmrs:	Minimal number of TDMRs that the TDX memory
 *				can generate.
 *
 * @tmem:	The TDX memory
 *
 * Return minimal number of TDMRs that TDX memory can generate in best way.
 *
 * Return 0, which means TDX memory is empty, or any positive integer.
 */
int __init tdx_memory_minimal_tdmrs(struct tdx_memory *tmem)
{
	struct tdx_tdmr_range *tr;
	int tr_num = 0;

	list_for_each_entry(tr, &tmem->tr_list, list)
		tr_num++;

	return tr_num;
}

/**
 * tdx_memory_merge:	Merge two TDX memory instances to one
 *
 * @tmem_dst:	The first TDX memory as destination
 * @tmem_src:	The second TDX memory as source
 *
 * Merge TDX memory @tmem_src to @tmem_dst.  This allows caller to build
 * multiple intermediate TDX memory instances, for instance, based on memory
 * type and/or NUMA locality, and merge them together as final TDX memory to
 * generate final TDMRs.
 *
 * On success, @tmem_src will be empty.  In case of any error, both @tmem_src
 * and @tmem_dst remain unchanged.
 */
int __init tdx_memory_merge(struct tdx_memory *tmem_dst,
		struct tdx_memory *tmem_src)
{
	return tdx_memory_merge_preserve(tmem_dst, tmem_src);
}

/**
 * tdx_memory_sanity_check_cmrs:	Sanity check whether all TDX memory
 *					blocks are fully covered by CMRs
 *
 * @tmem:	TDX memory
 * @cmr_array:	CMR array
 * @cmr_num:	Number of CMRs
 *
 * Sanity check whether all TDX memory blocks in TDX memory are fully covered by
 * CMRs.  Only memory covered by CMRs can truely be used by TDX.
 *
 * Return 0 on success, otherwise failure.
 */
int __init tdx_memory_sanity_check_cmrs(struct tdx_memory *tmem,
		struct cmr_info *cmr_array, int cmr_num)
{
	struct tdx_memblock_iter iter;

	/*
	 * Check CMRs against entire TDX memory, rather than against individual
	 * TDX memory block to allow more flexibility, i.e. to allow adding TDX
	 * memory block before CMR info is available.
	 */
	for_each_tdx_memblock(&iter, tmem)
		if (!phys_range_covered_by_cmrs(cmr_array, cmr_num,
				iter.tmb->start, iter.tmb->end))
			break;

	/* All blocks are checked, thus all blocks are covered by CMRs. */
	if (!tdx_memblock_iter_valid(&iter))
		return 0;

	/*
	 * TDX cannot be enabled in this case.  Explicitly give a message
	 * so user can know the reason of failure.
	 */
	pr_info("Memory [0x%llx, 0x%llx] not fully covered by CMR\n",
				iter.tmb->start, iter.tmb->end);
	return -EFAULT;
}
