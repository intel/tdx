// SPDX-License-Identifier: GPL-2.0
/*
 * Convert x86 legacy PMEM to TDX memory.
 */
#define pr_fmt(fmt) "tdx: " fmt

#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/memremap.h>
#include "tdmr-legacy-pmem.h"

/* TDX memory instance which contains all x86 legacy PMEMs */
struct tdx_memory tmem_legacy_pmem __initdata;

struct tdx_memblock_legacy_pmem {
	struct resource res;
	phys_addr_t end;
};

static void __init legacy_pmem_tmb_free(struct tdx_memblock *tmb)
{
	struct tdx_memblock_legacy_pmem *legacy_pmem =
		(struct tdx_memblock_legacy_pmem *)tmb->data;

	kfree(legacy_pmem);
}

static struct tdx_memblock_ops legacy_pmem_ops = {
	.tmb_free = legacy_pmem_tmb_free,
};

static bool x86_legacy_pmem_found __initdata;

static int __init add_legacy_pmem_memblock(struct resource *res, void *data)
{
	struct tdx_memory *tmem = (struct tdx_memory *)data;
	struct tdx_memblock_legacy_pmem *legacy_pmem;
	struct tdx_memblock *tmb;
	int nid, ret;

	/*
	 * walk_iomem_res_desc() returns -EINVAL if there's no resource found.
	 * This confuses caller with the actual error when handling the resource
	 * that has been found.  Use static variable x86_legacy_pmem_found to
	 * indicate whether the error was due to no resource being found, or
	 * actual error when handling resource.
	 */
	x86_legacy_pmem_found = true;

	/*
	 * Legacy PMEM has alignment requirement.  Just reject if alignment
	 * does not meet.
	 */
	if (!IS_ALIGNED(res->start | (res->end + 1),
			memremap_compat_align())) {
		pr_err("legacy PMEM resource [0x%llx, 0x%llx] misaligned.\n",
				res->start, res->end);
		return -EFAULT;
	}

	nid = phys_to_target_node(res->start);
	/* Legacy PMEM must belong to some NUMA node, otherwise there's bug. */
	if (WARN_ON_ONCE(nid == NUMA_NO_NODE))
		return -EFAULT;

	legacy_pmem = kzalloc(sizeof(*legacy_pmem), GFP_KERNEL);
	if (!legacy_pmem)
		return -ENOMEM;

	legacy_pmem->res = (struct resource) {
		.name = "TDMR (x86 legacy PMEM)",
		.start = res->start,
		.end = res->end,
		.flags = res->flags,
		.desc = res->desc,
	};

	/*
	 * For simplicity round up end to PAGE_SIZE aligned, unlike resource.
	 * Note memremap_compat_align() alignment check above already guarantees
	 * (res->end + 1) is at least PAGE_SIZE aligned.
	 */
	legacy_pmem->end = res->end + 1;
	WARN_ON_ONCE(!IS_ALIGNED(legacy_pmem->end, PAGE_SIZE));

	tmb = tdx_memblock_create(res->start >> PAGE_SHIFT,
			legacy_pmem->end >> PAGE_SHIFT, nid,
			(void *)legacy_pmem, &legacy_pmem_ops);
	if (!tmb) {
		kfree(legacy_pmem);
		return -ENOMEM;
	}

	ret = tdx_memory_add_block(tmem, tmb);
	if (ret) {
		tdx_memblock_free(tmb);
		return ret;
	}

	return 0;
}

static int __init __tdx_legacy_pmem_build(void)
{
	int ret;

	pr_info("Build all x86 legacy PMEMs as TDX memory.\n");

	tdx_memory_init(&tmem_legacy_pmem);

	/*
	 * Scan all legacy PMEMs, and save the TDMR ranges for them to
	 * xarray.  Note the TDMR ranges in the xarray will be in
	 * ascending order, since walk_iomem_res_desc() guarantees that.
	 */
	ret = walk_iomem_res_desc(IORES_DESC_PERSISTENT_MEMORY_LEGACY,
			IORESOURCE_MEM, 0, -1, &tmem_legacy_pmem,
			add_legacy_pmem_memblock);

	if (!x86_legacy_pmem_found)
		ret = 0;

	if (ret)
		goto err;

	return 0;

err:
	pr_err("Fail to build x86 legacy PMEMs as TDX memory.\n");
	tdx_legacy_pmem_cleanup();
	return ret;
}

/**
 * tdx_legacy_pmem_build:	Build all x86 legacy PMEM as TDX memory
 *
 * Build TDX memory @tmem_legacy_pmem for all x86 legacy PMEMs reserved by
 * 'memmap=nn!ss' kernel parameter.
 */
int __init tdx_legacy_pmem_build(void)
{
	if (!boot_cpu_has(X86_FEATURE_SEAM))
		return 0;

	return __tdx_legacy_pmem_build();
}

/**
 * tdx_legacy_pmem_cleanup:	Clean up legacy PMEM TDX memory
 *
 * Clean up TDX memory instances built from all x86 legacy PMEMs for all NUMA
 * nodes.
 */
void __init tdx_legacy_pmem_cleanup(void)
{
	tdx_memory_destroy(&tmem_legacy_pmem);
}
