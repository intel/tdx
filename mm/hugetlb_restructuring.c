// SPDX-License-Identifier: GPL-2.0-only
/*
 * Code to support runtime HugeTLB folio restructuring.
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/hugetlb_restructuring.h>
#include <linux/xarray.h>

static DEFINE_XARRAY(hugetlb_restructuring_metadata);

static void hugetlb_restructuring_metadata_initialize(
	struct hugetlb_restructuring_metadata *metadata, struct folio *folio)
{
	metadata->page_order = folio_order(folio);
	metadata->spool = hugetlb_folio_subpool(folio);
	metadata->h_cg = hugetlb_cgroup_from_folio(folio);
	metadata->h_cg_rsvd = hugetlb_cgroup_from_folio_rsvd(folio);
	metadata->hugetlb_cma = folio_test_hugetlb_cma(folio);
}

static void __hugetlb_restructuring_metadata_restore(
	struct folio *folio, struct hugetlb_restructuring_metadata *metadata)
{
	WARN_ON(!folio_test_hugetlb(folio));
	WARN_ON(folio_order(folio) != metadata->page_order);

	hugetlb_set_folio_subpool(folio, metadata->spool);
	set_hugetlb_cgroup(folio, metadata->h_cg);
	set_hugetlb_cgroup_rsvd(folio, metadata->h_cg_rsvd);
	if (metadata->hugetlb_cma)
		folio_set_hugetlb_cma(folio);
	else
		folio_clear_hugetlb_cma(folio);
}

static int hugetlb_restructuring_metadata_register(
	unsigned long pfn, struct hugetlb_restructuring_metadata *metadata)
{
	u8 order = metadata->page_order;
	void *entry;

	entry = xa_store_order(&hugetlb_restructuring_metadata, pfn, order,
			       metadata, GFP_KERNEL);

	WARN(entry, "Unexpected duplicate metadata registered");
	if (xa_is_err(entry))
		return xa_err(entry);

	return 0;
}

int hugetlb_restructuring_metadata_store(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;

	metadata = kmalloc(sizeof(*metadata), GFP_KERNEL);
	if (!metadata)
		return -ENOMEM;

	hugetlb_restructuring_metadata_initialize(metadata, folio);
	return hugetlb_restructuring_metadata_register(folio_pfn(folio), metadata);
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_metadata_store, "kvm");

void hugetlb_restructuring_metadata_restore(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;
	unsigned long pfn = folio_pfn(folio);

	metadata = xa_erase(&hugetlb_restructuring_metadata, pfn);
	__hugetlb_restructuring_metadata_restore(folio, metadata);

	kfree(metadata);
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_metadata_restore, "kvm");

struct hugetlb_restructuring_metadata *
hugetlb_restructuring_metadata_get(unsigned long pfn)
{
	return xa_load(&hugetlb_restructuring_metadata, pfn);
}
EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_metadata_get, "kvm");
