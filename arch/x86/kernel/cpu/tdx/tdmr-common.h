/* SPDX-License-Identifier: GPL-2.0 */
#ifndef	_X86_TDMR_COMMON_H
#define	_X86_TDMR_COMMON_H

#include <linux/types.h>
#include <linux/list.h>
#include <asm/tdx_arch.h>

/* TDMRs must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

struct tdx_memblock;
struct tdx_tdmr_range;
struct tdx_memory;

struct tdx_memtype_ops {
	void (*tmb_free)(struct tdx_memblock *tmb);
	/*
	 * Allocate @npages TDX memory as PAMT.  @tmb can be where PAMT is
	 * allocated from, or just a hit.
	 */
	unsigned long (*pamt_alloc)(struct tdx_memblock *tmb,
			unsigned long npages);
	/* Free PAMT allocated by pamt_alloc. */
	void (*pamt_free)(struct tdx_memblock *tmb, unsigned long pamt_pfn,
			unsigned long npages);
};

/*
 * Structure to describe common TDX memory block which can be covered by TDMRs.
 * To support specific type of TDX memory block, a type-specific data structure
 * should be defined, and pass as opaque data, along with type-specific ops.
 */
struct tdx_memblock {
	struct list_head list;
	phys_addr_t start;
	phys_addr_t end;
	int nid;
	void *data;	/* Type specific data */
	struct tdx_memtype_ops *ops;
	bool duplicated;
};

/*
 * TDX PAMT.
 *
 * PAMT is physical contiguous memory used by TDX module to track each page in
 * TDMR and crypto-protected by TDX module, and it (or part) needs to be put
 * into TDMR's reserved area when it (or part) falls into TDMR.
 */
struct tdx_pamt {
	struct list_head list;
	unsigned long pamt_pfn;
	unsigned long total_pages;
	unsigned long free_pages;
	struct tdx_memblock *tmb;	/* @tmb used in pamt_alloc */
};

/*
 * Structure to describe address range to cover one or more TDMRs.  Final TDMRs
 * used to configure TDX module are generated on basis of this structure,
 * meaning one TDMR won't cross two 'struct tdx_tdmr_range's.
 *
 * @start_pfn and @end_pfn must be TDMR_PFN_ALIGNMENT aligned, due to TDMR's
 * requirement. @tmb_list is a list of 'struct tdx_memblock's that the TDMR
 * range covers.
 *
 * One large PAMT is allocated to cover the entire TDMR range.  PAMT for each
 * TDMR within this range is divided frorm the large one.
 */
struct tdx_tdmr_range {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
	struct tdx_pamt *pamt;
	struct list_head tmb_list;
};

/*
 * Structure to describe a set of TDX memory blocks.  Basically it represents
 * memory which will be used by TDX.  Final TDMRs used to configure TDX module
 * is generated based on this.
 */
struct tdx_memory {
	struct list_head tr_list;
	struct list_head pamt_list;
};

/*
 * TDX memory block iterator.
 */
struct tdx_memblock_iter {
	struct tdx_memory *tmem;
	struct tdx_tdmr_range *tr;
	struct tdx_memblock *tmb;
};

static inline bool tdx_memblock_iter_valid(struct tdx_memblock_iter *iter)
{
	if (!iter->tmem)
		return false;
	if (list_entry_is_head(iter->tr, &iter->tmem->tr_list, list))
		return false;
	if (list_entry_is_head(iter->tmb, &iter->tr->tmb_list, list))
		return false;
	return true;
}

static inline void tdx_memblock_iter_start(struct tdx_memory *tmem,
		struct tdx_memblock_iter *iter)
{
	iter->tmem = tmem;

	if (!iter->tmem)
		return;

	iter->tr = list_first_entry(&iter->tmem->tr_list,
			struct tdx_tdmr_range, list);
	if (list_entry_is_head(iter->tr, &iter->tmem->tr_list, list))
		return;

	iter->tmb = list_first_entry(&iter->tr->tmb_list,
			struct tdx_memblock, list);
}

static inline void tdx_memblock_iter_next(struct tdx_memblock_iter *iter)
{
	if (!tdx_memblock_iter_valid(iter))
		return;

	iter->tmb = list_next_entry(iter->tmb, list);
	if (!list_entry_is_head(iter->tmb, &iter->tr->tmb_list, list))
		return;

	iter->tr = list_next_entry(iter->tr, list);
	if (list_entry_is_head(iter->tr, &iter->tmem->tr_list, list))
		return;

	iter->tmb = list_first_entry(&iter->tr->tmb_list,
			struct tdx_memblock, list);
}

#define for_each_tdx_memblock(_iter, _tmem)				\
	for (tdx_memblock_iter_start((_tmem), (_iter));			\
		tdx_memblock_iter_valid((_iter));			\
		tdx_memblock_iter_next((_iter)))

#define for_each_tdx_memblock_continue(_iter, _tmem)			\
	for (tdx_memblock_iter_next(_iter);				\
		tdx_memblock_iter_valid((_iter));			\
		tdx_memblock_iter_next((_iter)))

struct tdx_memblock * __init tdx_memblock_create(phys_addr_t start,
		phys_addr_t end, int nid, void *data,
		struct tdx_memtype_ops *ops);
void __init tdx_memblock_free(struct tdx_memblock *tmb);

void __init tdx_memory_init(struct tdx_memory *tmem);
void __init tdx_memory_destroy(struct tdx_memory *tmem);

/* Add new TDX memory block to TDX memory. */
int __init tdx_memory_add_block(struct tdx_memory *tmem,
		struct tdx_memblock *tmb);

/* Merge TDMR ranges within TDX memory. */
void __init tdx_memory_merge_tdmr_ranges(struct tdx_memory *tmem,
		bool merge_non_contig, bool merge_all);

/* Return minimal number of TDMRs that TDX memory can generate in best way */
int __init tdx_memory_minimal_tdmrs(struct tdx_memory *tmem);

/*
 * Merge TDX memory @tmem_src to @tmem_dst.  This allows caller to build
 * multiple intermediate TDX memory instances, for instance, based on memory
 * type and/or NUMA locality, and merge them together as final TDX memory to
 * generate final TDMRs.
 */
int __init tdx_memory_merge(struct tdx_memory *tmem_dst,
		struct tdx_memory *tmem_src);

/* Sanity check whether all TDX memory blocks are fully covered by CMRs. */
int __init tdx_memory_sanity_check_cmrs(struct tdx_memory *tmem,
		struct cmr_info *cmr_array, int cmr_num);

#endif
