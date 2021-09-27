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

/* Merge non-contiguous TDMR ranges */
#define TR_MERGE_NON_CONTIG	BIT(0)

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

/******************************* External APIs *****************************/

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

	return 0;

construct_tdmrs_err:
	construct_tdmrs_cleanup(tmem);
tr_ctx_err:
	tdmr_range_ctx_destroy(&tr_ctx);
	return ret;
}
