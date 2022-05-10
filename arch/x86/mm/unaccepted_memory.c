// SPDX-License-Identifier: GPL-2.0-only
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/spinlock.h>

#include <asm/io.h>
#include <asm/setup.h>
#include <asm/unaccepted_memory.h>

/* Protects unaccepted memory bitmap */
static DEFINE_SPINLOCK(unaccepted_memory_lock);

void accept_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long range_start, range_end;
	unsigned long *bitmap;
	unsigned long flags;

	if (!boot_params.unaccepted_memory)
		return;

	bitmap = __va(boot_params.unaccepted_memory);
	range_start = start / PMD_SIZE;

	/*
	 * load_unaligned_zeropad() can lead to unwanted loads across page
	 * boundaries. The unwanted loads are typically harmless. But, they
	 * might be made to totally unrelated or even unmapped memory.
	 * load_unaligned_zeropad() relies on exception fixup (#PF, #GP and now
	 * #VE) to recover from these unwanted loads.
	 *
	 * But, this approach does not work for unaccepted memory. For TDX, a
	 * load from unaccepted memory will not lead to a recoverable exception
	 * within the guest. The guest will exit to the VMM where the only
	 * recourse is to terminate the guest.
	 *
	 * There are two parts to fix this issue and comprehensively avoid
	 * access to unaccepted memory. Together these ensure that an extra
	 * "guard" page is accepted in addition to the memory that needs to be
	 * used:
	 *
	 * 1. Implicitly extend the range_contains_unaccepted_memory(start, end)
	 *    checks up to end+2M if 'end' is aligned on a 2M boundary.
	 *
	 * 2. Implicitly extend accept_memory(start, end) to end+2M if 'end' is
	 *    aligned on a 2M boundary. (immediately following this comment)
	 */
	if (!(end % PMD_SIZE))
		end += PMD_SIZE;

	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	for_each_set_bitrange_from(range_start, range_end, bitmap,
				   DIV_ROUND_UP(end, PMD_SIZE)) {
		unsigned long len = range_end - range_start;

		/* Platform-specific memory-acceptance call goes here */
		panic("Cannot accept memory: unknown platform\n");
		bitmap_clear(bitmap, range_start, len);
	}
	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);
}

bool range_contains_unaccepted_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long *bitmap;
	unsigned long flags;
	bool ret = false;

	if (!boot_params.unaccepted_memory)
		return 0;

	bitmap = __va(boot_params.unaccepted_memory);

	/*
	 * Also consider the unaccepted state of the *next* page. See fix #1 in
	 * the comment on load_unaligned_zeropad() in accept_memory().
	 */
	if (!(end % PMD_SIZE))
		end += PMD_SIZE;

	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	while (start < end) {
		if (test_bit(start / PMD_SIZE, bitmap)) {
			ret = true;
			break;
		}

		start += PMD_SIZE;
	}
	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);

	return ret;
}
