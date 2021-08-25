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
