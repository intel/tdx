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
 * Structure to describe common TDX memory block which can be covered by TDMRs.
 */
struct tdx_memblock {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
	int nid;
	void *data;	/* TDX memory block type specific data */
};

/*
 * Structure to describe a set of TDX memory blocks.  Basically it represents
 * memory which will be used by TDX.  Final TDMRs used to configure TDX module
 * is generated based on this.
 */
struct tdx_memory {
	struct list_head tmb_list;
};

struct tdx_memblock * __init tdx_memblock_create(unsigned long start_pfn,
		unsigned long end_pfn, int nid, void *data);
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
