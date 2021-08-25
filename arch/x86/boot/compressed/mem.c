// SPDX-License-Identifier: GPL-2.0-only

#include "../cpuflags.h"
#include "bitmap.h"
#include "error.h"
#include "math.h"

#define PMD_SHIFT	21
#define PMD_SIZE	(_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))

static inline void __accept_memory(phys_addr_t start, phys_addr_t end)
{
	/* Platform-specific memory-acceptance call goes here */
	error("Cannot accept memory");
}

/*
 * The accepted memory bitmap only works at PMD_SIZE granularity. If a request
 * comes in to mark memory as unaccepted which is not PMD_SIZE-aligned, simply
 * accept the memory now since it can not be *marked* as unaccepted.
 */
void process_unaccepted_memory(struct boot_params *params, u64 start, u64 end)
{
	/*
	 * Accept small regions that might not be able to be represented
	 * in the bitmap.  This is a bit imprecise and may accept some
	 * areas that could have been represented in the bitmap instead.
	 *
	 * Consider case like this:
	 *
	 * | 4k | 2044k |    2048k   |
	 * ^ 0x0        ^ 2MB        ^ 4MB
	 *
	 * all memory in the range is unaccepted, except for the first 4k.
	 * The second 2M can be represented in the bitmap, but kernel accept it
	 * right away. The imprecision makes the code simpler by ensuring that
	 * at least one bit will be set int the bitmap below.
	 */
	if (end - start < 2 * PMD_SIZE) {
		__accept_memory(start, end);
		return;
	}

	/*
	 * No matter how the start and end are aligned, at least one unaccepted
	 * PMD_SIZE area will remain.
	 */

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

	/*
	 * 'start' and 'end' are now both PMD-aligned.
	 * Record the range as being unaccepted:
	 */
	bitmap_set((unsigned long *)params->unaccepted_memory,
		   start / PMD_SIZE, (end - start) / PMD_SIZE);
}
