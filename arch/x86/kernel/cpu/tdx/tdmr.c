// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) memory initialization
 */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/slab.h>
#include <asm/string.h>
#include <linux/sizes.h>
#include <asm/e820/api.h>
#include <asm/pgtable.h>
#include "tdmr.h"

/*
 * Only E820_TYPE_RAM and E820_TYPE_PRAM are considered as candidate for
 * TDX usable memory.  The latter is treated as RAM because it is created
 * on top of real RAM via kernel command line and may be allocated for TD
 * guests.
 */
static bool e820_entry_is_ram(struct e820_entry *entry)
{
	return (entry->type == E820_TYPE_RAM) ||
		(entry->type == E820_TYPE_PRAM);
}

/*
 * Skip the memory below 1MB in e820 RAM entry.  In practice, the memory
 * below 1MB may not be included by CMRs thus cannot be used as TDX
 * memory.  And skipping low 1MB is fine, since those pages are not
 * managed by page allocator anyway due to boot-time reservation.
 *
 * Return true if the e820 entry is completely skipped, in which case
 * caller should ignore this entry.  Otherwise the actual memory range
 * after skipping the low 1MB is returned via @start and @end.
 */
static bool e820_entry_skip_lowmem(struct e820_entry *entry, u64 *start,
				   u64 *end)
{
	u64 _start = entry->addr;
	u64 _end = entry->addr + entry->size;

	if (_start < SZ_1M)
		_start = SZ_1M;

	*start = _start;
	*end = _end;

	return _start >= _end;
}

/* Helper to loop all e820 RAM entries with low 1MB excluded  */
#define e820_for_each_ram_entry(_table, _i, _entry, _start, _end)	\
	for ((_i) = 0, (_entry) = &(_table)->entries[0];		\
			(_i) < (_table)->nr_entries;			\
			(_i)++, (_entry) = &(_table)->entries[(_i)])	\
		if (!e820_entry_is_ram((_entry)) ||			\
			e820_entry_skip_lowmem((_entry),		\
				&(_start), &(_end))) { }		\
		else

/* Check whether first range is the subrange of the second */
static bool is_subrange(u64 r1_start, u64 r1_end, u64 r2_start, u64 r2_end)
{
	return (r1_start >= r2_start && r1_end <= r2_end) ? true : false;
}

/* Check whether address range is covered by any CMR or not. */
static bool range_covered_by_cmrs(struct cmr_info *cmr_array,
				  int cmr_num, u64 start, u64 end)
{
	int i;

	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		if (is_subrange(start, end, cmr->base, cmr->base + cmr->size))
			return true;
	}

	return false;
}

/* Sanity check whether all e820 RAM entries are fully covered by CMRs. */
static int check_e820_against_cmrs(void)
{
	struct e820_entry *entry;
	u64 start, end;
	int i;

	/*
	 * Loop over e820_table to find all RAM entries and check
	 * whether they are all fully covered by any CMR.  Use e820_table
	 * instead of e820_table_firmware or e820_table_kexec to honor
	 * possible 'mem' and 'memmap' kernel command lines.
	 */
	e820_for_each_ram_entry(e820_table, i, entry, start, end) {
		if (!range_covered_by_cmrs(tdx_cmr_array, tdx_cmr_num,
					start, end)) {
			pr_err("[0x%llx, 0x%llx) not fully convertible memory\n",
					start, end);
			return -EFAULT;
		}
	}

	return 0;
}

/* TDMR must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT_ULL(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

/* Align up and down the address to TDMR boundary */
#define TDMR_ALIGN_DOWN(_addr)	ALIGN_DOWN((_addr), TDMR_ALIGNMENT)
#define TDMR_ALIGN_UP(_addr)	ALIGN((_addr), TDMR_ALIGNMENT)

/* TDMR's start and end address */
#define TDMR_START(_tdmr)	((_tdmr)->base)
#define TDMR_END(_tdmr)		((_tdmr)->base + (_tdmr)->size)

static struct tdmr_info *alloc_tdmr(void)
{
	int tdmr_sz;

	/*
	 * TDMR_INFO's actual size depends on maximum number of reserved
	 * areas that one TDMR supports.
	 */
	tdmr_sz = 64 + tdx_sysinfo.max_reserved_per_tdmr *
		sizeof(struct tdmr_reserved_area);

	/*
	 * TDX requires TDMR_INFO to be TDMR_INFO_ALIGNMENT (512, power
	 * of two) aligned.  Always align up TDMR_INFO size to
	 * TDMR_INFO_ALIGNMENT so the memory allocated via kzalloc() can
	 * meet the alignment requirement.
	 */
	tdmr_sz = ALIGN(tdmr_sz, TDMR_INFO_ALIGNMENT);

	return kzalloc(tdmr_sz, GFP_KERNEL);
}

/* Create a new TDMR at given index in the TDMR array */
static struct tdmr_info *create_tdmr(struct tdmr_info **tdmr_array, int idx)
{
	struct tdmr_info *tdmr;

	tdmr = alloc_tdmr();

	WARN_ON(tdmr_array[idx]);
	tdmr_array[idx] = tdmr;

	return tdmr;
}

/*
 * Create TDMRs to cover all RAM entries in e820_table.  The created
 * TDMRs are saved to @tdmr_array, and @tdmr_num is set to the actual
 * number of TDMRs.  All entries in @tdmr_array must be initially NULL.
 */
static int create_tdmrs(struct tdmr_info **tdmr_array, int *tdmr_num)
{
	struct e820_entry *entry;
	struct tdmr_info *tdmr;
	u64 start, end;
	int i, tdmr_idx;

	tdmr_idx = 0;
	tdmr = create_tdmr(tdmr_array, 0);
	if (!tdmr)
		return -ENOMEM;
	/*
	 * Loop over all RAM entries in e820 and create TDMRs to cover
	 * them.  To keep it simple, always try to use one TDMR to cover
	 * one RAM entry.
	 *
	 * TDMR is 1GB aligned, so the current e820 entry may have been
	 * fully or partially covered by the TDMR for the previous e820
	 * entry.  For the latter case, create a new TDMR to cover the
	 * remaining part of this entry.
	 */
	e820_for_each_ram_entry(e820_table, i, entry, start, end) {
		start = TDMR_ALIGN_DOWN(start);
		end = TDMR_ALIGN_UP(end);

		/* Check overlap with current TDMR */
		if (tdmr->size) {
			/* Continue if already fully covered */
			if (end <= TDMR_END(tdmr))
				continue;

			/* Skip the already-covered part */
			if (start < TDMR_END(tdmr))
				start = TDMR_END(tdmr);

			/*
			 * Create a new TDMR when RAM entry is not
			 * covered or partially covered by the current
			 * TDMR.
			 */
			tdmr_idx++;
			if (tdmr_idx >= tdx_sysinfo.max_tdmrs)
				return -E2BIG;
			tdmr = create_tdmr(tdmr_array, tdmr_idx);
			if (!tdmr)
				return -ENOMEM;
		}

		tdmr->base = start;
		tdmr->size = end - start;
	}

	/* @tdmr_idx is always the index of last valid TDMR. */
	*tdmr_num = tdmr_idx + 1;

	return 0;
}

/* Calculate PAMT size given a TDMR and a page size */
static unsigned long __tdmr_get_pamt_sz(struct tdmr_info *tdmr,
					enum tdx_page_sz pgsz)
{
	unsigned long pamt_sz;

	pamt_sz = (tdmr->size >> ((9 * pgsz) + PAGE_SHIFT)) *
		tdx_sysinfo.pamt_entry_size;
	/* PAMT size must be 4K aligned */
	pamt_sz = ALIGN(pamt_sz, PAGE_SIZE);

	return pamt_sz;
}

/* Calculate the size of all PAMTs for a TDMR */
static unsigned long tdmr_get_pamt_sz(struct tdmr_info *tdmr)
{
	enum tdx_page_sz pgsz;
	unsigned long pamt_sz;

	pamt_sz = 0;
	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++)
		pamt_sz += __tdmr_get_pamt_sz(tdmr, pgsz);

	return pamt_sz;
}

/*
 * Locate the NUMA containing the start of the given TDMR's first RAM
 * entry.  The given TDMR may also cover memory in other NUMA nodes.
 */
static int tdmr_get_nid(struct tdmr_info *tdmr)
{
	struct e820_entry *entry;
	u64 start, end;
	int i;

	/* Find the first RAM entry covered by the TDMR */
	e820_for_each_ram_entry(e820_table, i, entry, start, end)
		if (end > TDMR_START(tdmr))
			break;

	/*
	 * One TDMR must cover at least one (or partial) RAM entry,
	 * otherwise it is kernel bug.  WARN_ON() in this case.
	 */
	if (WARN_ON(i == e820_table->nr_entries || start >= TDMR_END(tdmr)))
		return 0;

	/*
	 * The first RAM entry may be partially covered by the previous
	 * TDMR.  In this case, use TDMR's start to find the NUMA node.
	 */
	if (start < TDMR_START(tdmr))
		start = TDMR_START(tdmr);

	return phys_to_target_node(start);
}

static int tdmr_setup_pamt(struct tdmr_info *tdmr)
{
	unsigned long tdmr_pamt_base, pamt_base[TDX_PG_MAX];
	unsigned long pamt_sz[TDX_PG_MAX];
	unsigned long pamt_npages;
	struct page *pamt;
	enum tdx_page_sz pgsz;
	int nid;

	/*
	 * Allocate one chunk of physically contiguous memory for all
	 * PAMTs.  This helps minimize the PAMT's use of reserved areas
	 * in overlapped TDMRs.
	 */
	nid = tdmr_get_nid(tdmr);
	pamt_npages = tdmr_get_pamt_sz(tdmr) >> PAGE_SHIFT;
	pamt = alloc_contig_pages(pamt_npages, GFP_KERNEL, nid,
			&node_online_map);
	if (!pamt)
		return -ENOMEM;

	/* Calculate PAMT base and size for all supported page sizes. */
	tdmr_pamt_base = page_to_pfn(pamt) << PAGE_SHIFT;
	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++) {
		unsigned long sz = __tdmr_get_pamt_sz(tdmr, pgsz);

		pamt_base[pgsz] = tdmr_pamt_base;
		pamt_sz[pgsz] = sz;

		tdmr_pamt_base += sz;
	}

	tdmr->pamt_4k_base = pamt_base[TDX_PG_4K];
	tdmr->pamt_4k_size = pamt_sz[TDX_PG_4K];
	tdmr->pamt_2m_base = pamt_base[TDX_PG_2M];
	tdmr->pamt_2m_size = pamt_sz[TDX_PG_2M];
	tdmr->pamt_1g_base = pamt_base[TDX_PG_1G];
	tdmr->pamt_1g_size = pamt_sz[TDX_PG_1G];

	return 0;
}

static void tdmr_free_pamt(struct tdmr_info *tdmr)
{
	unsigned long pamt_pfn, pamt_sz;

	pamt_pfn = tdmr->pamt_4k_base >> PAGE_SHIFT;
	pamt_sz = tdmr->pamt_4k_size + tdmr->pamt_2m_size + tdmr->pamt_1g_size;

	/* Do nothing if PAMT hasn't been allocated for this TDMR */
	if (!pamt_sz)
		return;

	WARN_ON(!pamt_pfn);
	free_contig_range(pamt_pfn, pamt_sz >> PAGE_SHIFT);
}

static void tdmrs_free_pamt_all(struct tdmr_info **tdmr_array, int tdmr_num)
{
	int i;

	for (i = 0; i < tdmr_num; i++)
		tdmr_free_pamt(tdmr_array[i]);
}

/* Allocate and set up PAMTs for all TDMRs */
static int tdmrs_setup_pamt_all(struct tdmr_info **tdmr_array, int tdmr_num)
{
	int i, ret;

	for (i = 0; i < tdmr_num; i++) {
		ret = tdmr_setup_pamt(tdmr_array[i]);
		if (ret)
			goto err;
	}

	return 0;
err:
	tdmrs_free_pamt_all(tdmr_array, tdmr_num);
	return -ENOMEM;
}

static void destroy_tdmr(struct tdmr_info *tdmr)
{
	WARN_ON(!tdmr);
	tdmr_free_pamt(tdmr);
	kfree(tdmr);
}

/**
 * construct_tdmrs - Construct TDMRs to cover all system RAM in e820
 *
 * @tdmr_array:	Array of pointer to TDMR_INFO
 * @tdmr_num:	Actual number of TDMRs
 *
 * Construct TDMRs to cover all RAM entries in e820_table to convert
 * all system RAM to TDX memory.  The constructed TDMRs are stored in
 * @tdmr_array, with @tdmr_num reflects the actual TDMR number.
 *
 * Caller is responsible for allocating the space for @tdmr_array with
 * at least tdx_sysinfo.max_tdmrs entries.
 *
 * Return: 0 for success, or error.
 */
int construct_tdmrs(struct tdmr_info **tdmr_array, int *tdmr_num)
{
	int ret;

	/* Make sure all entries in the TDMR array are initially NULL */
	memset(tdmr_array, 0,
			sizeof(struct tdmr_info *) * tdx_sysinfo.max_tdmrs);

	*tdmr_num = 0;

	ret = check_e820_against_cmrs();
	if (ret)
		goto err;

	ret = create_tdmrs(tdmr_array, tdmr_num);
	if (ret)
		goto err;

	ret = tdmrs_setup_pamt_all(tdmr_array, *tdmr_num);
	if (ret)
		goto err;

	return -EFAULT;
err:
	destroy_tdmrs(tdmr_array, *tdmr_num);
	return ret;
}

/**
 * destroy_tdmrs - Destroy TDMRs
 *
 * @tdmr_array: Array of pointer to TDMR_INFO
 * @tdmr_num:	Actual number of TDMRs
 *
 * Destroy all TDMRs that are constructed by construct_tdmrs().
 * @tdmr_array is not freed.  It's caller's responsibility to free it.
 */
void destroy_tdmrs(struct tdmr_info **tdmr_array, int tdmr_num)
{
	int i;

	for (i = 0; i < tdmr_num; i++)
		destroy_tdmr(tdmr_array[i]);
}
