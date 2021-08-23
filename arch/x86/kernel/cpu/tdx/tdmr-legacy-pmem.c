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

/* Intermediate TDX memory instances for each node */
static struct tdx_memory tmem_legacy_pmem_nodes[MAX_NUMNODES] __initdata;

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

static unsigned long __init legacy_pmem_pamt_alloc(struct tdx_memblock *tmb,
		unsigned long nr_pages)
{
	struct tdx_memblock_legacy_pmem *legacy_pmem =
		(struct tdx_memblock_legacy_pmem *)tmb->data;
	struct resource *res = &legacy_pmem->res;
	struct resource *real_res;
	phys_addr_t new_end;
	unsigned long start_pfn, end_pfn;
	unsigned long pamt_pfn, pamt_npages;
	int ret;

	/* Sanity check alignment. */
	if (WARN_ON_ONCE(!IS_ALIGNED(legacy_pmem->res.start | legacy_pmem->end,
					memremap_compat_align())))
		return 0;

	/*
	 * For legacy PMEM, just reserve PAMT at its end, so basically the
	 * *owner* driver will see a trimmed resource.
	 */
	/* Round up PAMT size to meet alignment requirement. */
	pamt_npages = ALIGN(nr_pages, memremap_compat_align() >> PAGE_SHIFT);
	start_pfn = legacy_pmem->res.start >> PAGE_SHIFT;
	end_pfn = legacy_pmem->end >> PAGE_SHIFT;
	pamt_pfn = end_pfn - pamt_npages;

	/*
	 * FIXME: should we define some *minimal* remaining pages?
	 */
	if (pamt_pfn <= start_pfn)
		return 0;

	new_end = pamt_pfn << PAGE_SHIFT;

	/*
	 * The @res kept in 'struct tdx_memblock_legacy_pmem' is just a copy.  In
	 * order to make driver be able to detect the trimmed size, need to
	 * update the original one in &legacy_pmem_resource.
	 */
	real_res = lookup_resource(&iomem_resource, res->start);
	/*
	 * Since constructing TDMRs happens during kernel boot, we are not
	 * expecting resource being disappeared.
	 */
	if (WARN_ON_ONCE(!real_res))
		return 0;

	ret = adjust_resource(real_res, res->start, new_end - res->start);
	if (ret)
		return 0;

	/* Update the end by taking out PAMT. */
	legacy_pmem->end = new_end;

	return pamt_pfn;
}

static void __init legacy_pmem_pamt_free(struct tdx_memblock *tmb,
		unsigned long pamt_pfn, unsigned long nr_pages)
{
	struct tdx_memblock_legacy_pmem *legacy_pmem =
		(struct tdx_memblock_legacy_pmem *)tmb->data;
	struct resource *res = &legacy_pmem->res;
	struct resource *real_res;
	unsigned long pamt_npages;
	phys_addr_t new_end;
	int ret;

	/* Round up to meet alignment */
	pamt_npages = ALIGN(nr_pages, memremap_compat_align() >> PAGE_SHIFT);

	new_end = legacy_pmem->end + (pamt_npages << PAGE_SHIFT);

	/* The new end should never exceed resource's end */
	if (WARN_ON_ONCE(new_end > (legacy_pmem->res.end + 1)))
		return;

	/* Recover the real resource */
	real_res = lookup_resource(&iomem_resource, res->start);
	/*
	 * Since constructing TDMRs happens during kernel boot, we are not
	 * expecting resource being disappeared.
	 */
	if (WARN_ON_ONCE(!real_res))
		return;

	ret = adjust_resource(real_res, res->start, new_end - res->start);
	if (ret)
		return;

	legacy_pmem->end = new_end;
}

static struct tdx_memtype_ops legacy_pmem_ops = {
	.tmb_free = legacy_pmem_tmb_free,
	.pamt_alloc = legacy_pmem_pamt_alloc,
	.pamt_free = legacy_pmem_pamt_free,
};

static bool x86_legacy_pmem_found __initdata;

static int __init add_legacy_pmem_memblock(struct resource *res, void *data)
{
	struct tdx_memory *tmem_nid;
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
	 * memremap_pages() has alignment requirement.  Just reject if alignment
	 * is not met.
	 */
	if (!IS_ALIGNED(res->start | (res->end + 1),
			memremap_compat_align())) {
		pr_err("legacy PMEM resource [0x%llx, 0x%llx] misaligned.\n",
				res->start, res->end);
		return -EFAULT;
	}

	nid = phys_to_target_node(res->start);
	tmem_nid = &tmem_legacy_pmem_nodes[nid];

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

	/* For simplicity round up end to PAGE_SIZE aligned, unlike resource. */
	legacy_pmem->end = legacy_pmem->res.end + 1;

	tmb = tdx_memblock_create(legacy_pmem->res.start, legacy_pmem->end, nid,
			(void *)legacy_pmem, &legacy_pmem_ops);
	if (!tmb) {
		kfree(legacy_pmem);
		return -ENOMEM;
	}

	ret = tdx_memory_add_block(tmem_nid, tmb);
	if (ret) {
		tdx_memblock_free(tmb);
		return ret;
	}

	return 0;
}

static void __init tdx_legacy_pmem_init(void)
{
	int nid;

	tdx_memory_init(&tmem_legacy_pmem);
	for_each_online_node(nid)
		tdx_memory_init(&tmem_legacy_pmem_nodes[nid]);
}

static int __init tdx_legacy_pmem_finalize(void)
{
	int nid, ret;

	for_each_online_node(nid) {
		tdx_memory_merge_tdmr_ranges(&tmem_legacy_pmem_nodes[nid],
				false, true);
	}

	for_each_online_node(nid) {
		ret = tdx_memory_merge(&tmem_legacy_pmem,
				&tmem_legacy_pmem_nodes[nid]);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * tdx_legacy_pmem_build:	Build all x86 legacy PMEM as TDX memory
 *
 * Build TDX memory blocks for x86 legacy PMEM reserved by 'memmap=nn!ss', and
 * add them to @tmem_legacy_pmem.
 */
int __init tdx_legacy_pmem_build(void)
{
	int ret = 0;

	if (!boot_cpu_has(X86_FEATURE_SEAM))
		return 0;

	pr_info("Build all x86 legacy PMEMs as TDX memory.\n");

	tdx_legacy_pmem_init();

	/*
	 * Scan all legacy PMEMs, and save the TDMR ranges for them to
	 * xarray.  Note the TDMR ranges in the xarray will be in
	 * ascending order, since walk_iomem_res_desc() guarantees that.
	 */
	ret = walk_iomem_res_desc(IORES_DESC_PERSISTENT_MEMORY_LEGACY,
			IORESOURCE_MEM, 0, -1, NULL, add_legacy_pmem_memblock);

	if (!x86_legacy_pmem_found)
		ret = 0;

	if (ret)
		goto err;

	ret = tdx_legacy_pmem_finalize();
	if (ret)
		goto err;

	return 0;
err:
	pr_err("Fail to build x86 legacy PMEMs as TDX memory.\n");
	tdx_legacy_pmem_cleanup();
	return ret;
}

/**
 * tdx_legacy_pmem_cleanup:	Cleanup legacy PMEM TDX memory
 *
 * Cleanup TDX memory instances built from all x86 legacy PMEMs for all NUMA
 * nodes.
 */
void __init tdx_legacy_pmem_cleanup(void)
{
	int nid;

	for_each_online_node(nid)
		tdx_memory_destroy(&tmem_legacy_pmem_nodes[nid]);
	tdx_memory_destroy(&tmem_legacy_pmem);
}
