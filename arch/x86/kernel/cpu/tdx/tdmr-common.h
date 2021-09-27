/* SPDX-License-Identifier: GPL-2.0 */
#ifndef	_X86_TDMR_COMMON_H
#define	_X86_TDMR_COMMON_H

#include <linux/types.h>
#include <linux/list.h>
#include <asm/tdx_arch.h>

/* Page sizes supported by TDX */
enum tdx_page_sz {
	TDX_PG_4K = 0,
	TDX_PG_2M,
	TDX_PG_1G,
	TDX_PG_MAX,
};

/*
 * TDX module descriptor.  Those are TDX module's TDMR related global
 * characteristics, which impact constructing TDMRs.
 */
struct tdx_module_descriptor {
	int max_tdmr_num;
	int pamt_entry_size[TDX_PG_MAX];
	int max_tdmr_rsvd_area_num;
};

struct tdx_memblock;
struct tdx_memory;

/*
 * Structure to describe TDX PAMT.
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
	struct tdx_memblock *tmb;
};

struct tdx_memblock_ops {
	void (*tmb_free)(struct tdx_memblock *tmb);
	/*
	 * Allocate @npages TDX memory as PAMT.  @tmb can be where PAMT is
	 * allocated from, or just a hit.
	 */
	unsigned long (*pamt_alloc)(struct tdx_memblock *tmb,
			unsigned long npages);
	/* Free PAMT allocated by pamt_alloc(). */
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
	unsigned long start_pfn;
	unsigned long end_pfn;
	int nid;
	void *data;	/* TDX memory block type specific data */
	struct tdx_memblock_ops *ops;
	struct tdx_pamt *pamt;
};

/* Structure to describe one TDX TDMR. */
struct tdx_tdmr {
	phys_addr_t start_1g;
	phys_addr_t end_1g;
	unsigned long pamt_pfn;
	struct tdx_memblock *tmb;	/* For PAMT allocation */
};

/*
 * Structure to describe a set of TDX memory blocks.  Basically it represents
 * memory which will be used by TDX.  Final TDMRs used to configure TDX module
 * is generated based on this.
 */
struct tdx_memory {
	struct list_head tmb_list;
	struct tdx_tdmr *tdmr_array;
	int tdmr_num;
	struct list_head pamt_list;
};

struct tdx_memblock * __init tdx_memblock_create(unsigned long start_pfn,
		unsigned long end_pfn, int nid, void *data,
		struct tdx_memblock_ops *ops);
void __init tdx_memblock_free(struct tdx_memblock *tmb);

void __init tdx_memory_init(struct tdx_memory *tmem);
void __init tdx_memory_destroy(struct tdx_memory *tmem);

int __init tdx_memory_add_block(struct tdx_memory *tmem,
		struct tdx_memblock *tmb);

int __init tdx_memory_merge(struct tdx_memory *tmem_dst,
		struct tdx_memory *tmem_src);

int __init tdx_memory_construct_tdmrs(struct tdx_memory *tmem,
		struct cmr_info *cmr_array, int cmr_num,
		struct tdx_module_descriptor *desc,
		struct tdmr_info *tdmr_info_array, int *tdmr_num);

#endif
