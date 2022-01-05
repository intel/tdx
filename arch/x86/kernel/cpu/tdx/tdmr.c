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

static void destroy_tdmr(struct tdmr_info *tdmr)
{
	WARN_ON(!tdmr);
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
