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
 * Sanity check whether all TDX memory blocks are fully covered by CMRs.
 * Only convertible memory can truly be used by TDX.
 */
static int __init sanity_check_cmrs(struct tdx_memory *tmem,
		struct cmr_info *cmr_array, int cmr_num)
{
	struct tdx_memblock *tmb;

	/*
	 * Check CMRs against entire TDX memory, rather than against individual
	 * TDX memory block to allow more flexibility, i.e. to allow adding TDX
	 * memory block before CMR info is available.
	 */
	list_for_each_entry(tmb, &tmem->tmb_list, list)
		if (!phys_range_covered_by_cmrs(cmr_array, cmr_num,
				tmb->start_pfn << PAGE_SHIFT,
				tmb->end_pfn << PAGE_SHIFT))
			break;

	/* Return success if all blocks have passed CMR check */
	if (list_entry_is_head(tmb, &tmem->tmb_list, list))
		return 0;

	/*
	 * TDX cannot be enabled in this case.  Explicitly give a message
	 * so user can know the reason of failure.
	 */
	pr_info("Memory [0x%lx, 0x%lx] not fully covered by CMR\n",
				tmb->start_pfn << PAGE_SHIFT,
				tmb->end_pfn << PAGE_SHIFT);
	return -EFAULT;
}

/**************************** Distributing TDMRs ***************************/

/* TDMRs must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

#define TDX_MEMBLOCK_TDMR_START(_tmb)	\
	(ALIGN_DOWN((_tmb)->start_pfn, TDMR_PFN_ALIGNMENT) << PAGE_SHIFT)
#define TDX_MEMBLOCK_TDMR_END(_tmb)	\
	(ALIGN((_tmb)->end_pfn, TDMR_PFN_ALIGNMENT) << PAGE_SHIFT)

#define TDMR_SIZE_TO_1G_AREAS(_size_1g_aligned)		\
	((_size_1g_aligned) / TDMR_ALIGNMENT)
#define TDMR_RANGE_TO_1G_AREAS(_start_1g, _end_1g)	\
	TDMR_SIZE_TO_1G_AREAS((_end_1g) - (_start_1g))

/*
 * Structure to describe an address range, referred as TDMR range, which meets
 * TDMR's 1G alignment.  It is used to assist constructing TDMRs.  Final TDMRs
 * are generated on basis of TDMR range, meaning one TDMR range can have one or
 * multiple TDMRs, but one TDMR cannot cross two TDMR ranges.
 *
 * @start_1g and @end_1g are 1G aligned.  @first_tmb and @last_tmb are the first
 * and last TDX memory block that the TDMR range covers.  Note both @first_tmb
 * and @last_tmb may only have part of it covered by the TDMR range.
 */
struct tdmr_range {
	struct list_head list;
	phys_addr_t start_1g;
	phys_addr_t end_1g;
	int nid;
	struct tdx_memblock *first_tmb;
	struct tdx_memblock *last_tmb;
};

/*
 * Context of a set of TDMR ranges.  It is generated to cover all TDX memory
 * blocks to assist constructing TDMRs.  It can be discarded after TDMRs are
 * generated.
 */
struct tdmr_range_ctx {
	struct tdx_memory *tmem;
	struct list_head tr_list;
	int tr_num;
};

/*
 * Create a TDMR range which covers the TDX memory block @tmb.  @shrink_start
 * indicates whether to shrink first 1G, i.e. when boundary of @tmb and
 * previous block falls into the middle of 1G area, but a new TDMR range for
 * @tmb is desired.
 */
static struct tdmr_range * __init tdmr_range_create(
		struct tdx_memblock *tmb, bool shrink_start)
{
	struct tdmr_range *tr = kzalloc(sizeof(*tr), GFP_KERNEL);

	if (!tr)
		return NULL;

	INIT_LIST_HEAD(&tr->list);

	tr->start_1g = TDX_MEMBLOCK_TDMR_START(tmb);
	if (shrink_start)
		tr->start_1g += TDMR_ALIGNMENT;
	tr->end_1g = TDX_MEMBLOCK_TDMR_END(tmb);
	tr->nid = tmb->nid;
	tr->first_tmb = tr->last_tmb = tmb;

	return tr;
}

static void __init tdmr_range_free(struct tdmr_range *tr)
{
	/* kfree() is NULL safe */
	kfree(tr);
}

/*
 * Extend existing TDMR range to cover new TDX memory block @tmb.
 * The TDMR range which covers @tmb and the existing TDMR range must
 * not have address hole between them.
 */
static void __init tdmr_range_extend(struct tdmr_range *tr,
		struct tdx_memblock *tmb)
{
	WARN_ON_ONCE(TDX_MEMBLOCK_TDMR_START(tmb) > tr->end_1g);
	WARN_ON_ONCE(tr->nid != tmb->nid);
	tr->end_1g = ALIGN(tmb->end_pfn, TDMR_PFN_ALIGNMENT) << PAGE_SHIFT;
	tr->last_tmb = tmb;
}

/* Initialize the context for constructing TDMRs for given TDX memory. */
static void __init tdmr_range_ctx_init(struct tdmr_range_ctx *tr_ctx,
		struct tdx_memory *tmem)
{
	INIT_LIST_HEAD(&tr_ctx->tr_list);
	tr_ctx->tr_num = 0;
	tr_ctx->tmem = tmem;
}

/* Destroy the context for constructing TDMRs */
static void __init tdmr_range_ctx_destroy(struct tdmr_range_ctx *tr_ctx)
{
	while (!list_empty(&tr_ctx->tr_list)) {
		struct tdmr_range *tr = list_first_entry(&tr_ctx->tr_list,
				struct tdmr_range, list);

		list_del(&tr->list);
		tdmr_range_free(tr);
	}
	tr_ctx->tr_num = 0;
	tr_ctx->tmem = NULL;
}

/*
 * Generate a list of TDMR ranges for given TDX memory @tmem, as a preparation
 * to construct final TDMRs.
 */
static int __init generate_tdmr_ranges(struct tdmr_range_ctx *tr_ctx)
{
	struct tdx_memory *tmem = tr_ctx->tmem;
	struct tdx_memblock *tmb;
	struct tdmr_range *last_tr = NULL;

	list_for_each_entry(tmb, &tmem->tmb_list, list) {
		struct tdmr_range *tr;

		/* Create a new TDMR range for the first @tmb */
		if (!last_tr) {
			tr = tdmr_range_create(tmb, false);
			if (!tr)
				return -ENOMEM;
			/* Add to tail to keep TDMR ranges in ascending order */
			list_add_tail(&tr->list, &tr_ctx->tr_list);
			tr_ctx->tr_num++;
			last_tr = tr;
			continue;
		}

		/*
		 * Always create a new TDMR range if @tmb belongs to a new NUMA
		 * node, to ensure the TDMR and the PAMT which covers it are on
		 * the same NUMA node.
		 */
		if (tmb->nid != last_tr->last_tmb->nid) {
			/*
			 * If boundary of two NUMA nodes falls into the middle
			 * of 1G area, then part of @tmb has already been
			 * covered by first node's last TDMR range.  In this
			 * case, shrink the new TDMR range.
			 */
			bool shrink_start = TDX_MEMBLOCK_TDMR_START(tmb) <
				last_tr->end_1g ? true : false;

			tr = tdmr_range_create(tmb, shrink_start);
			if (!tr)
				return -ENOMEM;
			list_add_tail(&tr->list, &tr_ctx->tr_list);
			tr_ctx->tr_num++;
			last_tr = tr;
			continue;
		}

		/*
		 * Always extend existing TDMR range to cover new @tmb if part
		 * of @tmb has already been covered, regardless memory type of
		 * @tmb.
		 */
		if (TDX_MEMBLOCK_TDMR_START(tmb) < last_tr->end_1g) {
			tdmr_range_extend(last_tr, tmb);
			continue;
		}

		/*
		 * By reaching here, the new @tmb is in the same NUMA node, and
		 * is not covered by last TDMR range.  Always create a new TDMR
		 * range in this case, so that final TDMRs won't cross TDX
		 * memory block boundary.
		 */
		tr = tdmr_range_create(tmb, false);
		if (!tr)
			return -ENOMEM;
		list_add_tail(&tr->list, &tr_ctx->tr_list);
		tr_ctx->tr_num++;
		last_tr = tr;
	}

	return 0;
}

/*
 * Merge second TDMR range @tr2 to the first one @tr1, with assumption they
 * don't overlap.
 */
#define MERGE_NON_CONTIG_TR_MSG	\
	"Merge TDMR ranges with hole: [0x%llx, 0x%llx], [0x%llx, 0x%llx] -> [0x%llx, 0x%llx].  PAMT may be wasted for the hole.\n"

static void __init tdmr_range_merge(struct tdmr_range *tr1,
		struct tdmr_range *tr2)
{
	/*
	 * Merging TDMR ranges with address hole may result in PAMT being
	 * allocated for the hole (which is wasteful), i.e. when there's one
	 * TDMR covers entire TDMR range.  Give a message to let user know.
	 */
	if (tr1->end_1g < tr2->start_1g)
		pr_info(MERGE_NON_CONTIG_TR_MSG, tr1->start_1g, tr1->end_1g,
				tr2->start_1g, tr2->end_1g,
				tr1->start_1g, tr2->end_1g);

	/* Extend @tr1's address range */
	tr1->end_1g = tr2->end_1g;
	tr1->last_tmb = tr2->last_tmb;
}

/* Merge TDMR ranges with different types of TDX memory blocks */
#define TR_MERGE_TYPELESS	BIT(0)
/* Merge non-contiguous TDMR ranges */
#define TR_MERGE_NON_CONTIG	BIT(1)

/*
 * Try to merge two adjacent TDMR ranges into single one.  @nid indicates only
 * merge ranges on particular node, or on all nodes if @nid is NUMA_NO_NODE.
 * @merge_flags controls how to merge.
 *
 * Return true if merge happened, or false if not.
 */
static bool __init merge_tdmr_ranges_node(struct tdmr_range_ctx *tr_ctx,
		int nid, int merge_flags)
{
	struct tdmr_range *tr, *prev_tr;

	list_for_each_entry_safe_reverse(tr, prev_tr, &tr_ctx->tr_list, list) {

		/* Skip other nodes if merge only one node */
		if (nid != NUMA_NO_NODE && tr->nid != nid)
			continue;

		/* Return if @tr is the last range */
		if (list_entry_is_head(prev_tr, &tr_ctx->tr_list, list))
			return false;

		/*
		 * Return if two ranges belong to different nodes, and merge
		 * on the same node is intended.
		 */
		if (nid != NUMA_NO_NODE && prev_tr->nid != tr->nid)
			return false;

		/*
		 * Don't merge ranges with different types of TDX memory blocks
		 * if TR_MERGE_TYPELESS is not specified.  Note only check last
		 * block of @tr, and first block of @next_tr, although one range
		 * can have multiple types of blocks.
		 */
		if (!(merge_flags & TR_MERGE_TYPELESS) &&
			(prev_tr->last_tmb->ops != tr->first_tmb->ops))
			continue;

		/*
		 * Don't merge non-contiguous ranges when TR_MERGE_NON_CONTIG
		 * is not specified.
		 */
		if (!(merge_flags & TR_MERGE_NON_CONTIG) &&
			(prev_tr->end_1g < tr->start_1g))
			continue;

		/* Merge two ranges */
		list_del(&tr->list);
		tdmr_range_merge(prev_tr, tr);
		tdmr_range_free(tr);
		tr_ctx->tr_num--;

		return true;
	}

	return false;
}

/*
 * Try to shrink TDMR ranges to @target_tr_num by merging TDMR ranges on @nid.
 * If @nid is NUMA_NO_NODE then try all nodes.a
 *
 * Return true if @target_tr_num is reached, or false.
 */
static bool __init shrink_tdmr_ranges_node(struct tdmr_range_ctx *tr_ctx,
		int nid, int target_tr_num)
{
	int merge_flags = 0;
	bool merged;
again:
	do {
		merged = merge_tdmr_ranges_node(tr_ctx, nid,
			merge_flags);
	} while (merged && tr_ctx->tr_num > target_tr_num);

	if (tr_ctx->tr_num <= target_tr_num)
		return true;

	/* Try again with TR_MERGE_TYPELESS if not */
	if (!(merge_flags & TR_MERGE_TYPELESS)) {
		merge_flags |= TR_MERGE_TYPELESS;
		goto again;
	}

	/* Then try to merge non-contiguous ranges */
	if (!(merge_flags & TR_MERGE_NON_CONTIG)) {
		merge_flags |= TR_MERGE_NON_CONTIG;
		goto again;
	}

	return false;
}

static int __init shrink_tdmr_ranges(struct tdmr_range_ctx *tr_ctx,
		int target_tr_num)
{
	int nid;

	if (target_tr_num <= 0)
		return -EINVAL;

	if (tr_ctx->tr_num <= target_tr_num)
		return 0;

	/* Firstly, try to merge ranges within the same NUMA node */
	for_each_online_node(nid) {
		if (shrink_tdmr_ranges_node(tr_ctx, nid, target_tr_num))
			return 0;
	}

	/*
	 * Now there should be only one TDMR range on each node.
	 * Continue to merge cross nodes.
	 */
	if (shrink_tdmr_ranges_node(tr_ctx, NUMA_NO_NODE, target_tr_num))
		return 0;

	/*
	 * This should not happen, since TDMR ranges can be merged
	 * until there's only one.
	 */
	WARN_ON_ONCE(1);
	return -EFAULT;
}

/* Prepare storage for constructing TDMRs */
static int __init construct_tdmrs_prepare(struct tdx_memory *tmem,
		int max_tdmr_num)
{
	struct tdx_tdmr *tdmr_array;

	/*
	 * Don't know the actual number of TDMRs yet, because it depends on
	 * the process of distributing TDMRs.  Allocate enough space using
	 * @max_tdmr_num entries.
	 */
	tdmr_array = kcalloc(max_tdmr_num, sizeof(struct tdx_tdmr),
			GFP_KERNEL);
	if (!tdmr_array)
		return -ENOMEM;

	tmem->tdmr_array = tdmr_array;
	tmem->tdmr_num = 0;

	return 0;
}

static void __init construct_tdmrs_cleanup(struct tdx_memory *tmem)
{
	/*
	 * Destroy PAMTs before destroying all TDX memory blocks, since
	 * how PAMTs are allocated from TDX memory blocks are memory type
	 * specific.
	 */
	while (!list_empty(&tmem->pamt_list)) {
		struct tdx_pamt *pamt = list_first_entry(&tmem->pamt_list,
				struct tdx_pamt, list);

		list_del(&pamt->list);
		pamt->tmb->ops->pamt_free(pamt->tmb, pamt->pamt_pfn,
				pamt->total_pages);
		kfree(pamt);
	}

	/* kfree() is NULL safe */
	kfree(tmem->tdmr_array);
	tmem->tdmr_array = NULL;
}

/* Calculate total size of all TDMR ranges */
static phys_addr_t __init calculate_total_tdmr_range_size(
		struct tdmr_range_ctx *tr_ctx)
{
	struct tdmr_range *tr;
	unsigned long total_sz = 0;

	list_for_each_entry(tr, &tr_ctx->tr_list, list)
		total_sz += (tr->end_1g - tr->start_1g);

	return total_sz;
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
static void __init tdmr_range_distribute_tdmrs(struct tdmr_range *tr,
		int tdmr_num, struct tdx_tdmr *tdmr_array)
{
	unsigned long tr_1g_areas, tdmr_1g_areas;
	unsigned long remainder;
	unsigned long last_end_1g;
	int i;

	/*
	 * Calculate total 1G areas of TDMR range, TDMR's 1G areas, and
	 * remainder.  The remainder will be distributed to first TDMRs
	 * evenly.
	 */
	tr_1g_areas = TDMR_RANGE_TO_1G_AREAS(tr->start_1g, tr->end_1g);
	tdmr_1g_areas = tr_1g_areas / tdmr_num;
	remainder = tr_1g_areas % tdmr_num;
	last_end_1g = tr->start_1g;
	for (i = 0; i < tdmr_num; i++) {
		unsigned long areas_1g = tdmr_1g_areas;
		struct tdx_tdmr *tdmr = &tdmr_array[i];

		/* Distribute remainder 1G areas evenly to first TDMRs */
		if (remainder > 0) {
			areas_1g++;
			remainder--;
		}

		tdmr->start_1g = last_end_1g;
		tdmr->end_1g = last_end_1g + areas_1g * TDMR_ALIGNMENT;
		last_end_1g = tdmr->end_1g;
	}
}

/* Set up base and size to TDMR_INFO */
static void __init tdmr_info_setup_address_range(struct tdx_tdmr *tdmr,
		struct tdmr_info *tdmr_info)
{
	tdmr_info->base = tdmr->start_1g;
	tdmr_info->size = tdmr->end_1g - tdmr->start_1g;
}

/* Set up base and size for all TDMR_INFO entries */
static void __init tmem_setup_tdmr_info_address_ranges(struct tdx_memory *tmem,
		struct tdmr_info *tdmr_info_array)
{
	int i;

	for (i = 0; i < tmem->tdmr_num; i++)
		tdmr_info_setup_address_range(&tmem->tdmr_array[i],
				&tdmr_info_array[i]);
}

/*
 * Second step of constructing final TDMRs:
 *
 * Distribute TDMRs on TDMR ranges saved in array as even as possible.  It walks
 * through all TDMR ranges, and calculate number of TDMRs for given TDMR range
 * by comparing TDMR range's size and total size of all TDMR ranges.  Upon
 * success, the distributed TDMRs' address ranges will be updated to each entry
 * in @tdmr_array.
 */
static int __init distribute_tdmrs_across_tdmr_ranges(
		struct tdmr_range_ctx *tr_ctx, int max_tdmr_num,
		struct tdmr_info *tdmr_info_array)
{
	struct tdx_memory *tmem = tr_ctx->tmem;
	struct tdx_tdmr *tdmr_array = tmem->tdmr_array;
	struct tdmr_range *tr;
	unsigned long remain_1g_areas;
	int remain_tdmr_num;
	int last_tdmr_idx;

	if (WARN_ON_ONCE(!tdmr_array))
		return -EFAULT;

	/* Distribute TDMRs on basis of 'struct tdmr_range' one by one. */
	remain_1g_areas =
		TDMR_SIZE_TO_1G_AREAS(calculate_total_tdmr_range_size(tr_ctx));
	remain_tdmr_num = max_tdmr_num;
	last_tdmr_idx = 0;
	list_for_each_entry(tr, &tr_ctx->tr_list, list) {
		unsigned long tr_1g_areas;
		int tdmr_num_tr;

		/*
		 * Always calculate number of TDMRs for this TDMR range using
		 * remaining number of TDMRs, and remaining total range of TDMR
		 * ranges, so that number of all TDMRs for all TDMR ranges won't
		 * exceed @max_tdmr_num.
		 */
		tr_1g_areas = TDMR_RANGE_TO_1G_AREAS(tr->start_1g, tr->end_1g);
		tdmr_num_tr = remain_tdmr_num * tr_1g_areas / remain_1g_areas;

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
		tdmr_range_distribute_tdmrs(tr, tdmr_num_tr,
				tdmr_array + last_tdmr_idx);

		last_tdmr_idx += tdmr_num_tr;

		remain_1g_areas -= tr_1g_areas;
		remain_tdmr_num -= tdmr_num_tr;
	}

	WARN_ON_ONCE(last_tdmr_idx > max_tdmr_num);
	WARN_ON_ONCE(remain_1g_areas);

	/* Save actual number of TDMRs */
	tmem->tdmr_num = last_tdmr_idx;

	/* Set up base and size to all TDMR_INFO entries */
	tmem_setup_tdmr_info_address_ranges(tmem, tdmr_info_array);

	return 0;
}

/***************************** PAMT allocation *****************************/

/*
 * For given TDMR, among all TDX memory blocks (full or part) that are within
 * the TDMR, find one TDX memory block as candidate for PAMT allocation.  So
 * far just find the largest block as candidate.
 */
static void __init tdmr_setup_pamt_candidate(struct tdx_memory *tmem,
		struct tdx_tdmr *tdmr)
{
	struct tdx_memblock *tmb, *largest_tmb = NULL;
	unsigned long largest_tmb_pfn = 0;

	list_for_each_entry(tmb, &tmem->tmb_list, list) {
		unsigned long start_pfn = tmb->start_pfn;
		unsigned long end_pfn = tmb->end_pfn;
		unsigned long tmb_pfn;

		/* Skip those fully below @tdmr */
		if (TDX_MEMBLOCK_TDMR_END(tmb) <= tdmr->start_1g)
			continue;

		/* Skip those fully above @tdmr */
		if (TDX_MEMBLOCK_TDMR_START(tmb) >= tdmr->end_1g)
			break;

		/* Only calculate size of the part that is within TDMR */
		if (start_pfn < (tdmr->start_1g >> PAGE_SHIFT))
			start_pfn = (tdmr->start_1g >> PAGE_SHIFT);
		if (end_pfn > (tdmr->end_1g >> PAGE_SHIFT))
			end_pfn = (tdmr->end_1g >> PAGE_SHIFT);

		tmb_pfn = end_pfn - start_pfn;
		if (largest_tmb_pfn < tmb_pfn) {
			largest_tmb_pfn = tmb_pfn;
			largest_tmb = tmb;
		}
	}

	/*
	 * There must be at least one block (or part of it) within one TDMR,
	 * otherwise it is a bug.
	 */
	if (WARN_ON_ONCE(!largest_tmb))
		largest_tmb = list_first_entry(&tmem->tmb_list,
				struct tdx_memblock, list);

	tdmr->tmb = largest_tmb;
}

/*
 * First step of allocating PAMTs for TDMRs:
 *
 * Find one TDX memory block for each TDMR as candidate for PAMT allocation.
 * After this, each TDMR will have one block for PAMT allocation, but the same
 * block may be used by multiple TDMRs for PAMT allocation.
 */
static void __init tmem_setup_pamt_candidates(struct tdx_memory *tmem)
{
	int i;

	for (i = 0; i < tmem->tdmr_num; i++)
		tdmr_setup_pamt_candidate(tmem, &tmem->tdmr_array[i]);
}

/* Calculate PAMT size of one page size for one TDMR */
static unsigned long __init tdmr_range_to_pamt_sz(phys_addr_t start_1g,
		phys_addr_t end_1g, enum tdx_page_sz pgsz, int pamt_entry_sz)
{
	unsigned long pamt_sz;

	pamt_sz = ((end_1g - start_1g) >> ((9 * pgsz) + PAGE_SHIFT)) *
		pamt_entry_sz;
	/* PAMT size must be 4K aligned */
	pamt_sz = ALIGN(pamt_sz, PAGE_SIZE);

	return pamt_sz;
}

/*
 * Calculate PAMT size for one TDMR.  PAMTs for all supported page sizes are
 * calculated together as a whole size, so caller can just allocate all PAMTs
 * in one pamt_alloc() call.
 */
static unsigned long __init tdmr_get_pamt_sz(struct tdx_tdmr *tdmr,
		int pamt_entry_sz_array[TDX_PG_MAX])
{
	enum tdx_page_sz pgsz;
	unsigned long pamt_sz;

	pamt_sz = 0;
	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++) {
		pamt_sz += tdmr_range_to_pamt_sz(tdmr->start_1g, tdmr->end_1g,
				pgsz, pamt_entry_sz_array[pgsz]);
	}

	return pamt_sz;
}

/* Allocate one PAMT pool for all TDMRs that use given TDX memory block. */
static int __init tmb_alloc_pamt_pool(struct tdx_memory *tmem,
		struct tdx_memblock *tmb, int pamt_entry_sz_array[TDX_PG_MAX])
{
	struct tdx_pamt *pamt;
	unsigned long pamt_pfn, pamt_sz;
	int i;

	/* Get all TDMRs that use the same @tmb as PAMT allocation */
	pamt_sz = 0;
	for (i = 0; i < tmem->tdmr_num; i++)  {
		struct tdx_tdmr *tdmr = &tmem->tdmr_array[i];

		if (tdmr->tmb != tmb)
			continue;

		pamt_sz += tdmr_get_pamt_sz(tdmr, pamt_entry_sz_array);
	}

	/*
	 * If one TDMR range has multiple TDX memory blocks, it's possible
	 * all TDMRs within this range use one block as PAMT candidate, in
	 * which case other blocks won't be PAMT candidate for any TDMR.
	 * Just skip in this case.
	 */
	if (!pamt_sz)
		return 0;

	pamt = kzalloc(sizeof(*pamt), GFP_KERNEL);
	if (!pamt)
		return -ENOMEM;

	pamt_pfn = tmb->ops->pamt_alloc(tmb, pamt_sz >> PAGE_SHIFT);
	if (!pamt_pfn) {
		kfree(pamt);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&pamt->list);
	pamt->pamt_pfn = pamt_pfn;
	pamt->total_pages = pamt_sz >> PAGE_SHIFT;
	pamt->free_pages = pamt_sz >> PAGE_SHIFT;
	/* In order to use tmb->ops->pamt_free() */
	pamt->tmb = tmb;
	/* Setup TDX memory block's PAMT pool */
	tmb->pamt = pamt;
	/*
	 * Add PAMT to @tmem->pamt_list, so they can be easily freed before
	 * freeing any TDX memory block.
	 */
	list_add_tail(&pamt->list, &tmem->pamt_list);

	return 0;
}

/*
 * Second step of allocating PAMTs for TDMRs:
 *
 * Allocate one PAMT pool for all TDMRs that use the same TDX memory block for
 * PAMT allocation.  PAMT for each TDMR will later be divided from the pool.
 * This helps to minimize number of PAMTs and reduce consumption of TDMR's
 * reserved areas for PAMTs.
 */
static int __init tmem_alloc_pamt_pools(struct tdx_memory *tmem,
		int pamt_entry_sz_array[TDX_PG_MAX])
{
	struct tdx_memblock *tmb;

	list_for_each_entry(tmb, &tmem->tmb_list, list) {
		int ret;

		ret = tmb_alloc_pamt_pool(tmem, tmb, pamt_entry_sz_array);
		/*
		 * Just return in case of error.  PAMTs are freed in
		 * tdx_memory_destroy() before freeing any TDX memory
		 * blocks.
		 */
		if (ret)
			return ret;
	}

	return 0;
}

/* Simple helper for getting PAMT from TDMR's large PAMT pool. */
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

/* Set up PAMT for given TDMR from PAMT pool. */
static void __init tdmr_setup_pamt(struct tdx_tdmr *tdmr,
		int pamt_entry_sz_array[TDX_PG_MAX])
{
	unsigned long npages =
		tdmr_get_pamt_sz(tdmr, pamt_entry_sz_array) >> PAGE_SHIFT;

	tdmr->pamt_pfn = pamt_pool_alloc(tdmr->tmb->pamt, npages);
}

/*
 * Third step of allocating PAMTs for TDMRs:
 *
 * Set up PAMTs for all TDMRs by dividing PAMTs from PAMT pools.
 */
static void __init tmem_setup_pamts(struct tdx_memory *tmem,
		int pamt_entry_sz_array[TDX_PG_MAX])
{
	int i;

	for (i = 0; i < tmem->tdmr_num; i++)
		tdmr_setup_pamt(&tmem->tdmr_array[i], pamt_entry_sz_array);
}

/* Set up PAMT info in TDMR_INFO, which is used by TDX module. */
static void __init tdmr_info_setup_pamt(struct tdx_tdmr *tdmr,
		int pamt_entry_sz_array[TDX_PG_MAX],
		struct tdmr_info *tdmr_info)
{
	unsigned long pamt_base_pgsz = tdmr->pamt_pfn << PAGE_SHIFT;
	unsigned long pamt_base[TDX_PG_MAX];
	unsigned long pamt_sz[TDX_PG_MAX];
	enum tdx_page_sz pgsz;

	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++) {
		unsigned long sz = tdmr_range_to_pamt_sz(tdmr->start_1g,
				tdmr->end_1g, pgsz, pamt_entry_sz_array[pgsz]);

		pamt_base[pgsz] = pamt_base_pgsz;
		pamt_sz[pgsz] = sz;

		pamt_base_pgsz += sz;
	}

	tdmr_info->pamt_4k_base = pamt_base[TDX_PG_4K];
	tdmr_info->pamt_4k_size = pamt_sz[TDX_PG_4K];
	tdmr_info->pamt_2m_base = pamt_base[TDX_PG_2M];
	tdmr_info->pamt_2m_size = pamt_sz[TDX_PG_2M];
	tdmr_info->pamt_1g_base = pamt_base[TDX_PG_1G];
	tdmr_info->pamt_1g_size = pamt_sz[TDX_PG_1G];
}

/*
 * Final step of allocating PAMTs for TDMRs:
 *
 * Set up PAMT info for all TDMR_INFO structures.
 */
static void __init tmem_setup_tdmr_info_pamts(struct tdx_memory *tmem,
		int pamt_entry_sz_array[TDX_PG_MAX],
		struct tdmr_info *tdmr_info_array)
{
	int i;

	for (i = 0; i < tmem->tdmr_num; i++)
		tdmr_info_setup_pamt(&tmem->tdmr_array[i],
				pamt_entry_sz_array,
				&tdmr_info_array[i]);
}

/*
 * Third step of constructing final TDMRs:
 *
 * Allocate PAMTs for distributed TDMRs in previous step, and set up PAMT info
 * to TDMR_INFO array, which is used by TDX module.  Allocating PAMTs must be
 * done after distributing all TDMRs on final TDX memory, since PAMT size
 * depends on this.
 */
static int __init setup_pamts_across_tdmrs(struct tdx_memory *tmem,
		int pamt_entry_sz_array[TDX_PG_MAX],
		struct tdmr_info *tdmr_info_array)
{
	int ret;

	tmem_setup_pamt_candidates(tmem);

	ret = tmem_alloc_pamt_pools(tmem, pamt_entry_sz_array);
	if (ret)
		return ret;

	tmem_setup_pamts(tmem, pamt_entry_sz_array);

	tmem_setup_tdmr_info_pamts(tmem, pamt_entry_sz_array,
			tdmr_info_array);

	return 0;
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
 * Prepare all PAMT ranges that need to be put into the TDMR.  Walk through all
 * PAMTs in TDX memory's pamt list, and find those PAMT ranges that fall into
 * TDMR's range.  Note the list of overlapping part of PAMTs found here are not
 * related to the PAMT allocated for this TDMR, but may PAMTs for other TDMRs.
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
		 * PAMT overlaps with TDMR range.  The overlapping part
		 * needs to be include into TDMR's reserved area.
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
 * for other errors, otherwise set up the reserved area, and increase @p_idx
 * by 1.
 */
static int __init fillup_tdmr_reserved_area(struct tdmr_info *tdmr_info,
		int *p_idx, u64 addr, u64 size, int max_rsvd_area_num)
{
	struct tdmr_reserved_area *rsvd_areas = tdmr_info->reserved_areas;
	int idx = *p_idx;

	/* Reserved area must be 4K aligned in offset and size */
	if (WARN_ON_ONCE(addr & ~PAGE_MASK || size & ~PAGE_MASK))
		return -EFAULT;

	/* Cannot exceed maximum reserved areas supported by TDX */
	if (idx >= max_rsvd_area_num)
		return -E2BIG;

	rsvd_areas[idx].offset = addr - tdmr_info->base;	/* offset */
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
static int __init fillup_tdmr_reserved_area_with_pamt(
		struct tdmr_info *tdmr_info, int *p_idx, u64 addr, u64 size,
		struct rsvd_pamt_ctx *pamt_ctx, int max_rsvd_area_num)
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
			 * if possible, otherwise just fill up PAMT first.
			 */
			if (pamt->base + pamt->sz == addr) {
				addr = pamt->base;
				size += pamt->sz;
			} else {
				if (fillup_tdmr_reserved_area(tdmr_info, p_idx,
							pamt->base, pamt->sz,
							max_rsvd_area_num))
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
		 * to fill up target range.
		 */
		if (addr + size == pamt->base) {
			size += pamt->sz;
			pamt->inserted = true;
		}
		/* Break to fillup target range */
		break;
	}

	return fillup_tdmr_reserved_area(tdmr_info, p_idx, addr, size,
			max_rsvd_area_num);
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
		struct tdmr_info *tdmr_info, int max_rsvd_area_num)
{
	struct tdx_memblock *tmb, *prev_tmb;
	struct rsvd_pamt_ctx pamt_ctx;
	struct rsvd_pamt *pamt;
	unsigned long tdmr_start_pfn, tdmr_end_pfn;
	u64 tdmr_start, tdmr_end;
	u64 addr, size;
	int rsvd_idx = 0;
	int ret = 0;

	tdmr_start = tdmr_info->base;
	tdmr_end = tdmr_info->base + tdmr_info->size;
	tdmr_start_pfn = tdmr_start >> PAGE_SHIFT;
	tdmr_end_pfn = tdmr_end >> PAGE_SHIFT;

	/*
	 * Prepare all the PAMT ranges that fall into TDMR's range.  Those
	 * PAMT ranges need to be put into TDMR's reserved areas.
	 */
	ret = prepare_rsvd_pamt_ctx(tmem, tdmr_start_pfn, tdmr_end_pfn,
			&pamt_ctx);
	if (ret)
		goto out;

	/* Find the first memory block that has overlap with TDMR */
	list_for_each_entry(tmb, &tmem->tmb_list, list)
		if (tmb->end_pfn > tdmr_start_pfn)
			break;

	/* Unable to find? Something is wrong here. */
	if (WARN_ON_ONCE(list_entry_is_head(tmb, &tmem->tmb_list, list))) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * If memory block's start is beyond TDMR start, put [tdmr_start,
	 * tmb_start] into reserved area.
	 */
	if (tmb->start_pfn > tdmr_start_pfn) {
		addr = tdmr_start;
		size = tmb->start_pfn > tdmr_end_pfn ? (tdmr_end - tdmr_start) :
			((tmb->start_pfn << PAGE_SHIFT) - tdmr_start);
		if (fillup_tdmr_reserved_area_with_pamt(tdmr_info, &rsvd_idx,
					addr, size, &pamt_ctx,
					max_rsvd_area_num)) {
			ret = -E2BIG;
			goto out;
		}
	}

	/* If this memory block has already covered entire TDMR, it's done. */
	if (tmb->end_pfn >= tdmr_end_pfn)
		goto done;

	/*
	 * Keep current block as previous block, and continue to walk through
	 * all blocks to check whether there's any holes between them within
	 * TDMR, and if there's any, put to reserved areas.
	 */
	prev_tmb = tmb;
	list_for_each_entry_continue(tmb, &tmem->tmb_list, list) {
		/*
		 * If next block's start is beyond TDMR range, then the loop is
		 * done, and only need to put [prev_tr->end, tdmr_end] to
		 * reserved area. Just break out to handle.
		 */
		if (tmb->start_pfn >= tdmr_end_pfn)
			break;

		/*
		 * Otherwise put hole between previous block and current one
		 * into reserved area.
		 */
		addr = prev_tmb->end_pfn << PAGE_SHIFT;
		size = (tmb->start_pfn << PAGE_SHIFT) - addr;
		if (fillup_tdmr_reserved_area_with_pamt(tdmr_info, &rsvd_idx,
					addr, size, &pamt_ctx,
					max_rsvd_area_num)) {
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
	if (prev_tmb->end_pfn >= tdmr_end_pfn)
		goto done;

	addr = prev_tmb->end_pfn << PAGE_SHIFT;
	size = tdmr_end - addr;
	if (fillup_tdmr_reserved_area_with_pamt(tdmr_info, &rsvd_idx, addr,
				size, &pamt_ctx, max_rsvd_area_num)) {
		ret = -E2BIG;
		goto out;
	}

done:
	/* PAMTs may not have been handled, handle them here */
	list_for_each_entry(pamt, &pamt_ctx.pamt_list, list) {
		if (pamt->inserted)
			continue;
		if (fillup_tdmr_reserved_area(tdmr_info, &rsvd_idx, pamt->base,
					pamt->sz, max_rsvd_area_num)) {
			ret = -E2BIG;
			goto out;
		}
	}
out:
	return ret;
}

/*
 * Last step of constructing final TDMRs:
 *
 * Put TDX memory block holes and PAMTs into reserved areas of TDMRs.
 */
static int __init fillup_reserved_areas_across_tdmrs(struct tdx_memory *tmem,
		struct tdmr_info *tdmr_info_array, int max_rsvd_area_num)
{
	int i, ret;

	for (i = 0; i < tmem->tdmr_num; i++) {
		ret = fillup_tdmr_reserved_areas(tmem, &tdmr_info_array[i],
				max_rsvd_area_num);
		if (ret)
			return ret;
	}

	return 0;
}

/******************************* External APIs *****************************/

/**
 * tdx_memblock_create:	Create one TDX memory block
 *
 * @start_pfn:	Start PFN of the TDX memory block
 * @end_pfn:	End PFN of the TDX memory block
 * @nid:	Node the TDX memory block belongs to
 * @data:	Type-specific TDX memory block opaque data
 * @ops:	Type-specific TDX memory block ops
 *
 * Create one TDX memory block with type-specific data.
 */
struct tdx_memblock * __init tdx_memblock_create(unsigned long start_pfn,
		unsigned long end_pfn, int nid, void *data,
		struct tdx_memblock_ops *ops)
{
	struct tdx_memblock *tmb;

	tmb = kzalloc(sizeof(*tmb), GFP_KERNEL);
	if (!tmb)
		return NULL;

	INIT_LIST_HEAD(&tmb->list);
	tmb->start_pfn = start_pfn;
	tmb->end_pfn = end_pfn;
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
 * tdx_memory_init:	Initialize one TDX memory instance
 *
 * @tmem:	The TDX memory to initialize.
 */
void __init tdx_memory_init(struct tdx_memory *tmem)
{
	INIT_LIST_HEAD(&tmem->tmb_list);
	INIT_LIST_HEAD(&tmem->pamt_list);
}

/**
 * tdx_memory_destroy:	Destroy one TDX memory instance
 *
 * @tmem:	The TDX memory to destroy
 */
void __init tdx_memory_destroy(struct tdx_memory *tmem)
{
	construct_tdmrs_cleanup(tmem);

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

/**
 * tdx_memory_construct_tdmrs:	Construct final TDMRs to cover all TDX memory
 *				blocks in final TDX memory
 *
 * @tmem:		The final TDX memory
 * @cmr_array:		Array of CMR entries
 * @cmr_num:		Number of CMR entries
 * @desc:		TDX module descriptor for constructing final TMDRs
 * @tdmr_info_array:	Array of constructed final TDMRs
 * @tdmr_num:		Number of final TDMRs
 *
 * Construct final TDMRs to cover all TDX memory blocks in final TDX memory,
 * based on CMR info and TDX module descriptor.  Caller is responsible for
 * allocating enough space for array of final TDMRs @tdmr_info_array (i.e. by
 * allocating enough space based on @desc.max_tdmr_num).
 *
 * Upon success, all final TDMRs will be stored in @tdmr_info_array, and
 * @tdmr_num will have the actual number of TDMRs.  On failure, @tmem internal
 * state is cleared, and caller is responsible for destroying it.
 */
int __init tdx_memory_construct_tdmrs(struct tdx_memory *tmem,
		struct cmr_info *cmr_array, int cmr_num,
		struct tdx_module_descriptor *desc,
		struct tdmr_info *tdmr_info_array, int *tdmr_num)
{
	struct tdmr_range_ctx tr_ctx;
	int ret;

	BUILD_BUG_ON(sizeof(struct tdmr_info) != 512);

	/*
	 * Sanity check TDX module descriptor.  TDX module should have the
	 * architectural values in TDX spec.
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

	ret = sanity_check_cmrs(tmem, cmr_array, cmr_num);
	if (ret)
		return ret;

	/* Generate a list of TDMR ranges to cover all TDX memory blocks */
	tdmr_range_ctx_init(&tr_ctx, tmem);
	ret = generate_tdmr_ranges(&tr_ctx);
	if (ret)
		goto tr_ctx_err;

	/*
	 * Shrink number of TDMR ranges in case it exceeds maximum
	 * number of TDMRs that TDX can support.
	 */
	ret = shrink_tdmr_ranges(&tr_ctx, desc->max_tdmr_num);
	if (ret)
		goto tr_ctx_err;

	/* TDMR ranges are ready.  Prepare to construct TDMRs. */
	ret = construct_tdmrs_prepare(tmem, desc->max_tdmr_num);
	if (ret)
		goto construct_tdmrs_err;

	/* Distribute TDMRs across all TDMR ranges */
	ret = distribute_tdmrs_across_tdmr_ranges(&tr_ctx, desc->max_tdmr_num,
			tdmr_info_array);
	if (ret)
		goto construct_tdmrs_err;

	/*
	 * Allocate PAMTs for all TDMRs, and set up PAMT info in
	 * all TDMR_INFO entries.
	 */
	ret = setup_pamts_across_tdmrs(tmem, desc->pamt_entry_size,
			tdmr_info_array);
	if (ret)
		goto construct_tdmrs_err;

	/* Set up reserved areas for all TDMRs */
	ret = fillup_reserved_areas_across_tdmrs(tmem, tdmr_info_array,
			desc->max_tdmr_rsvd_area_num);
	if (ret)
		goto construct_tdmrs_err;

	/* Constructing TDMRs done.  Set up the actual TDMR number */
	*tdmr_num = tmem->tdmr_num;

	/*
	 * Discard TDMR ranges.  They are useless after
	 * constructing TDMRs is done.
	 */
	tdmr_range_ctx_destroy(&tr_ctx);

	return 0;

construct_tdmrs_err:
	construct_tdmrs_cleanup(tmem);
tr_ctx_err:
	tdmr_range_ctx_destroy(&tr_ctx);
	return ret;
}
