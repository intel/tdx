// SPDX-License-Identifier: GPL-2.0-only

#include "error.h"
#include "misc.h"

static inline void __accept_memory(phys_addr_t start, phys_addr_t end)
{
	/* Platform-specific memory-acceptance call goes here */
	error("Cannot accept memory");
}

void mark_unaccepted(struct boot_params *params, u64 start, u64 end)
{
	/*
	 * The accepted memory bitmap only works at PMD_SIZE granularity.
	 * If a request comes in to mark memory as unaccepted which is not
	 * PMD_SIZE-aligned, simply accept the memory now since it can not be
	 * *marked* as unaccepted.
	 */

	/* Immediately accept whole range if it is within a PMD_SIZE block: */
	if ((start & PMD_MASK) == (end & PMD_MASK)) {
		npages = (end - start) / PAGE_SIZE;
		__accept_memory(start, start + npages * PAGE_SIZE);
		return;
	}

	/* Immediately accept a <PMD_SIZE piece at the start: */
	if (start & ~PMD_MASK) {
		__accept_memory(start, round_up(start, PMD_SIZE));
		start = round_up(start, PMD_SIZE);
	}

	/* Immediately accept a <PMD_SIZE piece at the end: */
	if (end & ~PMD_MASK) {
		__accept_memory(round_down(end, PMD_SIZE), end);
		end = round_down(end, PMD_SIZE);
	}

	if (start == end)
		return;

	bitmap_set((unsigned long *)params->unaccepted_memory,
		   start / PMD_SIZE, (end - start) / PMD_SIZE);
}

void accept_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long *unaccepted_memory;
	unsigned int rs, re;

	unaccepted_memory = (unsigned long *)boot_params->unaccepted_memory;
	bitmap_for_each_set_region(unaccepted_memory, rs, re,
				   start / PMD_SIZE, end / PMD_SIZE) {
		__accept_memory(rs * PMD_SIZE, re * PMD_SIZE);
		bitmap_clear(unaccepted_memory, rs, re - rs);
	}
}
