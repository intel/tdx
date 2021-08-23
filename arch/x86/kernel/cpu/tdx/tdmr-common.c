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

/* @_npages must be 1G aligned */
#define NPAGES_TO_1G_AREAS(_npages)	((_npages) / TDMR_PFN_ALIGNMENT)

static unsigned long __init tdx_memory_total_tdmr_pages(struct tdx_memory *tmem)
{
	unsigned long total_pfns = 0;
	struct tdx_tdmr_range *tr;

	list_for_each_entry(tr, &tmem->tr_list, list)
		total_pfns += (tr->end_pfn - tr->start_pfn);

	return total_pfns;
}

/*
 * Distribute TDMR range into number of TDMRs specified by @tdmr_num.  To
 * distribute TDMRs as evenly as possible, each TDMR's size is total TDMR
 * range size divided by @tdmr_num.  If there's remainder, the remainder
 * is evenly distributed to first @remainder number of TDMRs.
 *
 * The result TDMRs will be stored in @tdmr_array.  Caller must guarantee
 * storage for @tdmr_array has already been allocated.
 */
static void __init distribute_tdmrs_within_range(struct tdx_tdmr_range *tr,
		int tdmr_num, struct tdmr_info *tdmr_array)
{
	unsigned long tr_1g_areas, tdmr_1g_areas;
	unsigned long remainder;
	unsigned long last_end_pfn;
	int i;

	/*
	 * Calcualte total 1G areas of TDMR range, TDMR's 1G areas, and
	 * remainder.  The remainder will be distributed to first TDMRs
	 * evenly.
	 */
	tr_1g_areas = NPAGES_TO_1G_AREAS(tr->end_pfn - tr->start_pfn);
	tdmr_1g_areas = tr_1g_areas / tdmr_num;
	remainder = tr_1g_areas % tdmr_num;
	last_end_pfn = tr->start_pfn;
	for (i = 0; i < tdmr_num; i++) {
		unsigned long areas_1g = tdmr_1g_areas;
		struct tdmr_info *tdmr;

		tdmr = &tdmr_array[i];

		/* Distribute remainder 1G areas evenly to first TDMRs */
		if (remainder > 0) {
			areas_1g++;
			remainder--;
		}

		tdmr->base = last_end_pfn << PAGE_SHIFT;
		tdmr->size = areas_1g * TDMR_ALIGNMENT;
		last_end_pfn = last_end_pfn + (tdmr->size >> PAGE_SHIFT);
	}
}

/*
 * Fist step of constructing final TDMRs:
 *
 * Distribute TDMRs on TDMR ranges saved in array as evan as possible.  It walks
 * through all TDMR ranges, and calculate number of TDMRs for given TDMR range
 * by comparing TDMR range's size and total size of all TDMR ranges.  Upon
 * success, the distributed TDMRs' address ranges will be updated to each entry
 * in @tdmr_array.
 */
static int __init distribute_tdmrs_across_tdmr_ranges(struct tdx_memory *tmem,
		struct tdmr_info *tdmr_array, int *actual_tdmr_num,
		int max_tdmr_num)
{
	struct tdx_tdmr_range *tr;
	unsigned long remain_1g_areas;
	int remain_tdmr_num;
	int last_tdmr_idx;

	/*
	 * Distribute TDMRs on basis of 'struct tdx_tdmr_range' one by one.
	 * This also handles 'max_tdmr_num == tmem->tr_num' case.
	 */
	remain_1g_areas = NPAGES_TO_1G_AREAS(tdx_memory_total_tdmr_pages(tmem));
	remain_tdmr_num = max_tdmr_num;
	last_tdmr_idx = 0;
	list_for_each_entry(tr, &tmem->tr_list, list) {
		unsigned long tr_1g_areas;
		int tdmr_num_tr;

		/*
		 * Always calaculate number of TDMRs for this TDMR range using
		 * remaining number of TDMRs, and remaining total range of TDMR
		 * ranges, so that number of all TDMRs for all TDMR ranges won't
		 * exceed @max_tdmr_num.
		 */
		tr_1g_areas = NPAGES_TO_1G_AREAS(tr->end_pfn - tr->start_pfn);
		tdmr_num_tr = tr_1g_areas * remain_tdmr_num / remain_1g_areas;

		/*
		 * It's possible @tdmr_num_tr can be 0, when this TDMR range is
		 * too small, comparing to total TDMR ranges.  In this case,
		 * just use one TDMR to cover it.
		 */
		if (!tdmr_num_tr)
			tdmr_num_tr = 1;

		/*
		 * When number of all TDMR range's total 1G areas is smaller
		 * than maximum TDMR number, the TDMR number distributed to one
		 * TDMR range will be larger than its 1G areas.  Reduce TDMR
		 * number to number of 1G areas in this case.
		 */
		if (tdmr_num_tr > tr_1g_areas)
			tdmr_num_tr = tr_1g_areas;

		/* Distribute @tdmr_num_tr TDMRs for this TDMR range */
		distribute_tdmrs_within_range(tr, tdmr_num_tr,
				tdmr_array + last_tdmr_idx);

		last_tdmr_idx += tdmr_num_tr;

		remain_1g_areas -= tr_1g_areas;
		remain_tdmr_num -= tdmr_num_tr;
	}

	WARN_ON_ONCE(last_tdmr_idx > max_tdmr_num);
	WARN_ON_ONCE(remain_1g_areas);

	*actual_tdmr_num = last_tdmr_idx;

	return 0;
}

static unsigned long __init get_pamt_sz(unsigned long start_pfn,
		unsigned long end_pfn, enum tdx_page_sz pgsz,
		int pamt_entry_sz)
{
	unsigned long pamt_sz;

	pamt_sz = ((end_pfn - start_pfn) >> (9 * pgsz)) * pamt_entry_sz;
	/* PAMT size must be 4K aligned */
	pamt_sz = ALIGN(pamt_sz, PAGE_SIZE);

	return pamt_sz;
}

/* Find the largest memory block with TDMR range for PAMT allocation. */
static struct tdx_memblock * __init tdmr_range_find_largest_block(
		struct tdx_tdmr_range *tr)
{
	struct tdx_memblock *tmb = NULL, *p;
	phys_addr_t tmb_sz = 0;

	/* All memory blocks are in ascending order, and don't overlap. */
	list_for_each_entry(p, &tr->tmb_list, list) {
		phys_addr_t sz = p->end - p->start;

		if (tmb_sz < sz) {
			tmb_sz = sz;
			tmb = p;
		}
	}

	return tmb;
}

/*
 * Allocate PAMT for given TDMR range.  To reduce number of non-contiguous
 * PAMTs, PAMT is allocated at once with large enough size to cover entire TDMR
 * range.  PAMT for each individual TDMR within TDMR range is divided from the
 * large PAMT.
 */
static int __init tdmr_range_alloc_pamt(struct tdx_tdmr_range *tr,
		int *pamt_entry_sz_array)
{
	unsigned long areas_1g, pamt_pfn, pamt_sz;
	enum tdx_page_sz pgsz;
	struct tdx_memblock *tmb;
	struct tdx_pamt *pamt;

	pamt = kzalloc(sizeof(*pamt), GFP_KERNEL);
	if (!pamt)
		return -ENOMEM;

	/*
	 * Calcuate large enough PAMT size to cover entire TDMR range.
	 *
	 * FIXME:
	 *
	 * So far there's no data structure to track which TDMRs are within TDMR
	 * range, so just treat all TDMRs are 1G.  This would waste small memory
	 * (roughly 1MB per 1TB), since PAMT size for one big TDMR and many
	 * small TDMRs may not be the same due to PAMT size needs to be page
	 * (4K) aligned for each TDMR (this is especially true for PAMT size for
	 * 1G page -- for instance, "one 10G TDMR" would have one 4K page as
	 * PAMT, but "10 1G TDMRs" would end up with 10 4K pages as PAMT).
	 */
	areas_1g = NPAGES_TO_1G_AREAS(tr->end_pfn - tr->start_pfn);
	pamt_sz = 0;
	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++) {
		pamt_sz += get_pamt_sz(0, TDMR_PFN_ALIGNMENT, pgsz,
				pamt_entry_sz_array[pgsz]) * areas_1g;
	}

	/* Try to allocate PAMT from largest memory block */
	tmb = tdmr_range_find_largest_block(tr);
	if (WARN_ON_ONCE(!tmb)) {
		kfree(pamt);
		return -EFAULT;
	}

	pamt_pfn = tmb->ops->pamt_alloc(tmb, pamt_sz >> PAGE_SHIFT);
	if (pamt_pfn)
		goto done;

	/*
	 * If allocation from largest block wasn't successful, just try all
	 * blocks until allocation is done.
	 */
	list_for_each_entry(tmb, &tr->tmb_list, list) {
		pamt_pfn = tmb->ops->pamt_alloc(tmb, pamt_sz >> PAGE_SHIFT);
		if (pamt_pfn)
			goto done;
	}

	kfree(pamt);
	return -ENOMEM;

done:
	pamt->pamt_pfn = pamt_pfn;
	pamt->total_pages = pamt_sz >> PAGE_SHIFT;
	pamt->free_pages = pamt_sz >> PAGE_SHIFT;
	pamt->tmb = tmb;

	tr->pamt = pamt;

	return 0;
}

static int __init tdx_memory_allocate_pamts(struct tdx_memory *tmem,
		int *pamt_entry_sz_array)
{
	struct tdx_tdmr_range *tr;
	int ret;

	list_for_each_entry(tr, &tmem->tr_list, list) {
		ret = tdmr_range_alloc_pamt(tr,  pamt_entry_sz_array);
		if (ret)
			return ret;

		list_add_tail(&tr->pamt->list, &tmem->pamt_list);
	}

	return ret;
}

/* Simple alloc helpers for getting PAMT from TDMR's large PAMT pool. */
static unsigned long __init pamt_pool_alloc(struct tdx_pamt *pamt,
		unsigned long npages)
{
	unsigned long pamt_pfn;

	if (WARN_ON_ONCE(npages > pamt->free_pages))
		return 0;

	pamt_pfn = pamt->pamt_pfn + (pamt->total_pages - pamt->free_pages);
	pamt->free_pages -= npages;

	return pamt_pfn;
}

static void __init tdmr_setup_pamt(struct tdmr_info *tdmr,
		struct tdx_pamt *pamt, int *pamt_entry_sz_array)
{
	unsigned long pamt_pfn[TDX_PG_MAX];
	unsigned long pamt_sz[TDX_PG_MAX];
	unsigned long start_pfn, end_pfn;
	enum tdx_page_sz pgsz;

	start_pfn = tdmr->base >> PAGE_SHIFT;
	end_pfn = (tdmr->base + tdmr->size) >> PAGE_SHIFT;
	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++) {
		unsigned long sz = get_pamt_sz(start_pfn, end_pfn, pgsz,
				pamt_entry_sz_array[pgsz]);

		pamt_pfn[pgsz] = pamt_pool_alloc(pamt, sz >> PAGE_SHIFT);
		pamt_sz[pgsz] = sz;
	}

	tdmr->pamt_4k_base = pamt_pfn[TDX_PG_4K] << PAGE_SHIFT;
	tdmr->pamt_4k_size = pamt_sz[TDX_PG_4K];
	tdmr->pamt_2m_base = pamt_pfn[TDX_PG_2M] << PAGE_SHIFT;
	tdmr->pamt_2m_size = pamt_sz[TDX_PG_2M];
	tdmr->pamt_1g_base = pamt_pfn[TDX_PG_1G] << PAGE_SHIFT;
	tdmr->pamt_1g_size = pamt_sz[TDX_PG_1G];
}

static struct tdx_tdmr_range * __init tdx_memory_find_tdmr_range(
		struct tdx_memory *tmem, struct tdmr_info *tdmr)
{
	unsigned long start_pfn, end_pfn;
	struct tdx_tdmr_range *tr;

	start_pfn = tdmr->base >> PAGE_SHIFT;
	end_pfn = (tdmr->base + tdmr->size) >> PAGE_SHIFT;

	list_for_each_entry(tr, &tmem->tr_list, list) {
		if (start_pfn >= tr->start_pfn && end_pfn <= tr->end_pfn)
			return tr;
	}

	return NULL;
}


static int __init tdx_memory_setup_pamts(struct tdx_memory *tmem,
		struct tdmr_info *tdmr_array, int tdmr_num,
		int *pamt_entry_sz_array)
{
	int i;

	for (i = 0; i < tdmr_num; i++) {
		struct tdmr_info *tdmr = &tdmr_array[i];
		struct tdx_tdmr_range *tr;

		/*
		 * FIXME:
		 *
		 * This isn't nice, but we don't have data structure to
		 * track TDMRs within one TDMR range.
		 */
		tr = tdx_memory_find_tdmr_range(tmem, tdmr);
		if (WARN_ON_ONCE(!tr))
			return -EFAULT;

		tdmr_setup_pamt(tdmr, tr->pamt, pamt_entry_sz_array);
	}

	return 0;
}

/*
 * Second step of constructing final TDMRs:
 *
 * Allocate and setup all PAMTs for all distributed TDMRs.  PAMT must be
 * allocated after distributing all TDMRs on final TDX memory, since PAMT size
 * depends on this.
 */
static int __init setup_pamts_across_tdmrs(struct tdx_memory *tmem,
		struct tdmr_info *tdmr_array, int tdmr_num,
		int *pamt_entry_sz_array)
{
	int ret;

	ret = tdx_memory_allocate_pamts(tmem, pamt_entry_sz_array);
	if (ret)
		return ret;

	/* In case of error, PAMT is freed in tdx_memory_destroy() */
	return tdx_memory_setup_pamts(tmem, tdmr_array, tdmr_num,
			pamt_entry_sz_array);
}

/************************Fill up TDMR reserved areas ************************/

/* Temporary context used to insert PAMTs to TDMR's reserved areas */
struct rsvd_pamt {
	struct list_head list;
	u64 base;
	u64 sz;
	bool inserted;
};

struct rsvd_pamt_ctx {
	struct list_head pamt_list;
};

static void __init rsvd_pamt_ctx_init(struct rsvd_pamt_ctx *pamt_ctx)
{
	INIT_LIST_HEAD(&pamt_ctx->pamt_list);
}

/* Insert new PAMT into context and keep all PAMTs in ascending order */
static int __init rsvd_pamt_ctx_insert(struct rsvd_pamt_ctx *pamt_ctx,
		u64 base, u64 sz)
{
	struct rsvd_pamt *pamt, *p;

	/* Find entry which is lower than base */
	list_for_each_entry_reverse(p, &pamt_ctx->pamt_list, list) {
		if (p->base < base)
			break;
	}

	/* PAMTs cannot overlap */
	if (WARN_ON_ONCE(!list_entry_is_head(p, &pamt_ctx->pamt_list, list) &&
			((p->base + p->sz) > base)))
		return -EFAULT;

	pamt = kzalloc(sizeof(*pamt), GFP_KERNEL);
	if (!pamt)
		return -ENOMEM;

	pamt->base = base;
	pamt->sz = sz;

	list_add(&pamt->list, &p->list);

	return 0;
}

/*
 * Prepare all PAMT ranges that need to be put into TDMR, by walking through
 * all allocated PAMTs in global tdx_pamt_list, and finding those PAMT ranges
 * that fall into TDMR range.  Note the PAMTs found here are not the PAMTs
 * allocated for 'struct tdx_tdmr_range', because PAMTs won't necessarily reside
 * within 'struct tdx_tdmr_range'.
 */
static int __init prepare_rsvd_pamt_ctx(struct tdx_memory *tmem,
		unsigned long tdmr_start_pfn, unsigned long tdmr_end_pfn,
		struct rsvd_pamt_ctx *pamt_ctx)
{
	struct tdx_pamt *pamt;
	int ret;

	rsvd_pamt_ctx_init(pamt_ctx);

	list_for_each_entry(pamt, &tmem->pamt_list, list) {
		unsigned long pamt_start_pfn = pamt->pamt_pfn;
		unsigned long pamt_end_pfn = pamt_start_pfn + pamt->total_pages;
		u64 base, sz;

		/* Skip PAMT which doesn't overlap with TDMR */
		if (pamt_start_pfn >= tdmr_end_pfn ||
				pamt_end_pfn < tdmr_start_pfn)
			continue;

		/*
		 * PAMT overlaps with TDMR range.  The overlap part
		 * needs to be include into TDMR's reserved area
		 */
		if (pamt_start_pfn < tdmr_start_pfn)
			pamt_start_pfn = tdmr_start_pfn;
		if (pamt_end_pfn > tdmr_end_pfn)
			pamt_end_pfn = tdmr_end_pfn;

		base = pamt_start_pfn << PAGE_SHIFT;
		sz = (pamt_end_pfn - pamt_start_pfn) << PAGE_SHIFT;

		ret = rsvd_pamt_ctx_insert(pamt_ctx, base, sz);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Fill up one reserved area at index @p_idx with @addr and @size.  Return
 * -E2BIG if @p_idx has already reached maximum reserved areas, or -EFAULT
 * for other errors, otherwise setup the reserved area, and increase @p_idx
 * by 1.
 */
static int __init fillup_tdmr_reserved_area(struct tdmr_info *tdmr,
		int *p_idx, u64 addr, u64 size, int max_tdmr_rsvd_area_num)
{
	struct tdmr_reserved_area *rsvd_areas = tdmr->reserved_areas;
	int idx = *p_idx;

	/* Reserved area must be 4K aligned in offset and size */
	if (WARN_ON_ONCE(addr & ~PAGE_MASK || size & ~PAGE_MASK))
		return -EFAULT;

	/* Cannot exceed maximum reserved areas supported by TDX */
	if (idx >= max_tdmr_rsvd_area_num)
		return -E2BIG;

	rsvd_areas[idx].offset = addr - tdmr->base;	/* offset */
	rsvd_areas[idx].size = size;

	*p_idx = idx + 1;

	return 0;
}

/*
 * Fill up TDMR's one reserved area at index @p_idx, with @addr and @size.
 * Also fill up PAMTs to reserved area too, if they are at lower position than
 * target range.  PAMTs in @pamts_sorted[] array must already have been in
 * ascending order.  Upon success, update @p_idx to next free reserved area,
 * and @pamts_sorted entries also get updated to reflect whether they have been
 * inserted or not.
 *
 * Return 0 upon success, or -E2BIG if maximum reserved area is reached, or
 * -EFAULT for other errors.
 */
static int __init fillup_tdmr_reserved_area_with_pamt(struct tdmr_info *tdmr,
		int *p_idx, u64 addr, u64 size, struct rsvd_pamt_ctx *pamt_ctx,
		int max_tdmr_rsvd_area_num)
{
	struct rsvd_pamt *pamt;

	/*
	 * Loop over all PAMTs, and fill up all PAMTs that are at lower position
	 * than target range, since all reserved area need to be in ascending
	 * order.
	 */
	list_for_each_entry(pamt, &pamt_ctx->pamt_list, list) {
		/* Skip PAMT which is already reserved area */
		if (pamt->inserted)
			continue;

		/* Caller must guarantee PAMT and target range is different */
		if (WARN_ON_ONCE(pamt->base == addr))
			return -EFAULT;

		if (pamt->base < addr) {
			/* Reserved area cannot overlap */
			if (WARN_ON_ONCE(pamt->base + pamt->sz > addr))
				return -EFAULT;

			/*
			 * Merge PAMT with target range to save reserved area
			 * if possible, otherwise just fillup PAMT first.
			 */
			if (pamt->base + pamt->sz == addr) {
				addr = pamt->base;
				size += pamt->sz;
			} else {
				if (fillup_tdmr_reserved_area(tdmr, p_idx,
							pamt->base, pamt->sz,
							max_tdmr_rsvd_area_num))
					return -E2BIG;
			}
			pamt->inserted = true;
			/* Loop to next PAMT */
			continue;
		}

		/* Reserved area cannot overlap */
		if (WARN_ON_ONCE(addr + size > pamt->base))
			return -EFAULT;
		/*
		 * Merge PAMT with target range if possible, otherwise break
		 * to fillup target range.
		 */
		if (addr + size == pamt->base) {
			size += pamt->sz;
			pamt->inserted = true;
		}
		/* Break to fillup target range */
		break;
	}

	return fillup_tdmr_reserved_area(tdmr, p_idx, addr, size,
			max_tdmr_rsvd_area_num);
}

/*
 * Fill up TDMR's reserved areas with holes between TDX memory blocks, and
 * PAMTs that are within TDMR address range, in ascending order.  @tdmr's
 * base, size must already been set.
 *
 * Return 0 upon success, or -E2BIG if maximum reserved area is reached, or
 * other fatal errors.
 */
static int __init fillup_tdmr_reserved_areas(struct tdx_memory *tmem,
		struct tdmr_info *tdmr, int max_tdmr_rsvd_area_num)
{
	struct tdx_memblock *tmb, *prev_tmb;
	struct tdx_memblock_iter iter;
	struct rsvd_pamt_ctx pamt_ctx;
	struct rsvd_pamt *pamt;
	u64 tdmr_start, tdmr_end;
	u64 addr, size;
	int rsvd_idx = 0;
	int ret = 0;

	if (WARN_ON_ONCE(max_tdmr_rsvd_area_num != TDX_MAX_NR_RSVD_AREAS))
		return -EINVAL;

	/* TDMR_INFO's base and size must have been setup */
	tdmr_start = tdmr->base;
	tdmr_end = tdmr->base + tdmr->size;

	/*
	 * Prepare all the PAMT ranges that need to be put into TDMR's reserved
	 * areas.  Note the PAMT ranges in reserved area are not the PAMTs that
	 * are used to cover all pages in the TDMR.  It doesn't guarantee PAMTs
	 * are allocated within the 'struct tdx_tdmr_range'.
	 */
	ret = prepare_rsvd_pamt_ctx(tmem, tdmr_start >> PAGE_SHIFT,
				tdmr_end >> PAGE_SHIFT, &pamt_ctx);
	if (ret)
		goto out;

	/* Find the first memory block that has overlap with TDMR */
	for_each_tdx_memblock(&iter, tmem)
		if (iter.tmb->end > tdmr_start)
			break;

	/* Unable to find? Something is wrong here. */
	if (WARN_ON_ONCE(!tdx_memblock_iter_valid(&iter))) {
		ret = -EINVAL;
		goto out;
	}

	tmb = iter.tmb;

	/*
	 * If memory block's start is beyond TDMR start, put [tdmr_start,
	 * tmb_start] into reserved area.
	 */
	if (tmb->start > tdmr_start) {
		addr = tdmr_start;
		/*
		 * TODO:
		 *
		 * A rare case is that the entire TDMR may fall in address
		 * hole between two TDX memory blocks, when the TDMR range
		 * structure is merged from two adjacent ones with address
		 * hole between them.  It's not entirely impossible to avoid
		 * generating TDMR within address hole when distributing
		 * TDMRs, but it brings a lot more code complexity, so for
		 * now it's still possible one TDMR may fall in address hole
		 * between two TDX memory blcoks.  In this case, put TDMR's
		 * range into reserved area.
		 */
		size = tmb->start > tdmr_end ? (tdmr_end - tdmr_start) :
			(tmb->start - tdmr_start);
		if (fillup_tdmr_reserved_area_with_pamt(tdmr, &rsvd_idx,
					addr, size, &pamt_ctx,
					max_tdmr_rsvd_area_num)) {
			ret = -E2BIG;
			goto out;
		}
	}

	/* If this memory block has already covered entire TDMR, it's done. */
	if (tmb->end >= tdmr_end)
		goto done;

	/*
	 * Keep current block as previous block, and continue to walk through
	 * all blcoks to check whether there's anya holes between them within
	 * TDMR, and if there's any, put to reserved areas.
	 */
	prev_tmb = tmb;
	for_each_tdx_memblock_continue(&iter, tmem) {
		tmb = iter.tmb;

		/*
		 * If next block's start is beyond TDMR range, then the loop is
		 * done, and only need to put [prev_tr->end, tdmr_end] to
		 * reserved area. Just break out to handle.
		 */
		if (tmb->start >= tdmr_end)
			break;

		/*
		 * Otherwise put hole between previous block and current one
		 * into reserved area.
		 */
		addr = prev_tmb->end;
		size = tmb->start - addr;
		if (fillup_tdmr_reserved_area_with_pamt(tdmr, &rsvd_idx, addr,
					size, &pamt_ctx,
					max_tdmr_rsvd_area_num)) {
			ret = -E2BIG;
			goto out;
		}

		/* Update previous block and keep looping */
		prev_tmb = tmb;
	}

	/*
	 * When above loop never happened (when memory block is the last one),
	 * or when it hit memory block's start is beyond TDMR range, add
	 * [prev_tmb->end, tdmr_end] to reserved area, when former is less.
	 */
	if (prev_tmb->end >= tdmr_end)
		goto done;

	addr = prev_tmb->end;
	size = tdmr_end - addr;
	if (fillup_tdmr_reserved_area_with_pamt(tdmr, &rsvd_idx, addr, size,
				&pamt_ctx, max_tdmr_rsvd_area_num)) {
		ret = -E2BIG;
		goto out;
	}

done:
	/* PAMTs may not have been handled, handle them here */
	list_for_each_entry(pamt, &pamt_ctx.pamt_list, list) {
		if (pamt->inserted)
			continue;
		if (fillup_tdmr_reserved_area(tdmr, &rsvd_idx, pamt->base,
					pamt->sz, max_tdmr_rsvd_area_num)) {
			ret = -E2BIG;
			goto out;
		}
	}
out:
	return ret;
}

/*
 * Last step of constructing final TDMRs, when all TDMR ranges are ready in
 * array:
 *
 * Fill up reserved areas for all TDMRs based on CMR info and PAMTs.
 */
static int __init fillup_reserved_areas_across_tdmrs(struct tdx_memory *tmem,
		struct tdmr_info *tdmr_array, int tdmr_num,
		int max_tdmr_rsvd_area_num)
{
	int i, ret;

	for (i = 0; i < tdmr_num; i++) {
		ret = fillup_tdmr_reserved_areas(tmem, &tdmr_array[i],
				max_tdmr_rsvd_area_num);
		if (ret)
			return ret;
	}

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

/**
 * tdx_memory_construct_tdmrs:	Construct final TDMRs to cover all TDX memory
 *				blocks in final TDX memory
 *
 * @tmem:	The final TDX memory
 * @cmr_array:	Arrry of CMR entries
 * @cmr_num:	Number of CMR entries
 * @desc:	TDX module descriptor for constructing final TMDRs
 * @tdmr_array:	Array of constructed final TDMRs
 * @tdmr_num:	Number of final TDMRs
 *
 * Construct final TDMRs to cover all TDX memory blcoks in final TDX memory,
 * based on CMR info and TDX module descriptor.  Caller is responsible for
 * allocating enough space for array of final TDMRs @tdmr_array (i.e. by
 * allocating enough space based on @desc.max_tdmr_num).
 *
 * Upon success, all final TDMRs will be stored in @tdmr_array, and @tdmr_num
 * will have the actual number of TDMRs.
 */
int __init tdx_memory_construct_tdmrs(struct tdx_memory *tmem,
		struct cmr_info *cmr_array, int cmr_num,
		struct tdx_module_descriptor *desc,
		struct tdmr_info *tdmr_array, int *tdmr_num)
{
	int ret;

	/*
	 * Sanity check TDX module descriptor.  TDX module should have the
	 * archtectural values in TDX spec.
	 */
	if (WARN_ON_ONCE((desc->max_tdmr_num != TDX_MAX_NR_TDMRS) ||
		(desc->max_tdmr_rsvd_area_num != TDX_MAX_NR_RSVD_AREAS) ||
		(desc->pamt_entry_size[TDX_PG_4K] != TDX_PAMT_ENTRY_SIZE) ||
		(desc->pamt_entry_size[TDX_PG_2M] != TDX_PAMT_ENTRY_SIZE) ||
		(desc->pamt_entry_size[TDX_PG_1G] != TDX_PAMT_ENTRY_SIZE)))
		return -EINVAL;

	/*
	 * Sanity check number of CMR entries.  It should not exceed maximum
	 * value defined by TDX spec.
	 */
	if (WARN_ON_ONCE((cmr_num > TDX_MAX_NR_CMRS) || (cmr_num <= 0)))
		return -EINVAL;

	/*
	 * Caller should make sure number of TDMR ranges doesn't exceed maximum
	 * number of TDMRs supported by TDX.
	 */
	if (tdx_memory_minimal_tdmrs(tmem) > desc->max_tdmr_num)
		return -EINVAL;

	ret = distribute_tdmrs_across_tdmr_ranges(tmem, tdmr_array, tdmr_num,
			desc->max_tdmr_num);
	if (ret)
		goto err;

	ret = setup_pamts_across_tdmrs(tmem, tdmr_array, *tdmr_num,
			desc->pamt_entry_size);
	if (ret)
		goto err;

	ret = fillup_reserved_areas_across_tdmrs(tmem, tdmr_array,
			*tdmr_num, desc->max_tdmr_rsvd_area_num);
	if (ret)
		goto err;

	return 0;
err:
	return ret;
}
