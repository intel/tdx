#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/spinlock.h>

#include <asm/io.h>
#include <asm/setup.h>
#include <asm/shared/tdx.h>
#include <asm/unaccepted_memory.h>

static DEFINE_SPINLOCK(unaccepted_memory_lock);

#define PMD_ORDER (PMD_SHIFT - PAGE_SHIFT)

static void __accept_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long *unaccepted_memory;
	unsigned int rs, re;

	unaccepted_memory = __va(boot_params.unaccepted_memory);
	rs = start / PMD_SIZE;

	for_each_set_bitrange_from(rs, re, unaccepted_memory,
				   DIV_ROUND_UP(end, PMD_SIZE)) {
		/* Platform-specific memory-acceptance call goes here */
		if (cc_platform_has(CC_ATTR_GUEST_TDX))
			tdx_accept_memory(rs * PMD_SIZE, re * PMD_SIZE);
		else
			panic("Cannot accept memory");
		bitmap_clear(unaccepted_memory, rs, re - rs);
		count_vm_events(ACCEPT_MEMORY, PMD_SIZE / PAGE_SIZE);
	}
}

void accept_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long flags;
	if (!boot_params.unaccepted_memory)
		return;

	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	__accept_memory(start, end);
	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);
}

void maybe_mark_page_unaccepted(struct page *page, unsigned int order)
{
	unsigned long *unaccepted_memory;
	phys_addr_t addr = page_to_phys(page);
	unsigned long flags;
	bool unaccepted = false;
	unsigned int i;

	if (!boot_params.unaccepted_memory)
		return;

	unaccepted_memory = __va(boot_params.unaccepted_memory);
	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	if (order < PMD_ORDER) {
		BUG_ON(test_bit(addr / PMD_SIZE, unaccepted_memory));
		goto out;
	}

	for (i = 0; i < (1 << (order - PMD_ORDER)); i++) {
		if (test_bit(addr / PMD_SIZE + i, unaccepted_memory)) {
			unaccepted = true;
			break;
		}
	}

	/* At least part of page is uneccepted */
	if (unaccepted)
		__SetPageUnaccepted(page);
out:
	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);
}

void accept_page(struct page *page, unsigned int order)
{
	phys_addr_t addr = round_down(page_to_phys(page), PMD_SIZE);
	int i;

	WARN_ON_ONCE(!boot_params.unaccepted_memory);

	page = pfn_to_page(addr >> PAGE_SHIFT);
	if (order < PMD_ORDER)
		order = PMD_ORDER;

	accept_memory(addr, addr + (PAGE_SIZE << order));

	for (i = 0; i < (1 << order); i++) {
		if (PageUnaccepted(page + i))
			__ClearPageUnaccepted(page + i);
	}
}
