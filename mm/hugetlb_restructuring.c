// SPDX-License-Identifier: GPL-2.0-only
/*
 * Code to support runtime HugeTLB folio restructuring.
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/hugetlb_restructuring.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>

#include "hugetlb_vmemmap.h"

static DEFINE_XARRAY(hugetlb_restructuring_metadata);

static void hugetlb_restructuring_metadata_initialize(
	struct hugetlb_restructuring_metadata *metadata, struct folio *folio)
{
	metadata->page_order = folio_order(folio);
	metadata->spool = hugetlb_folio_subpool(folio);
	metadata->h_cg = hugetlb_cgroup_from_folio(folio);
	metadata->h_cg_rsvd = hugetlb_cgroup_from_folio_rsvd(folio);
	metadata->hugetlb_cma = folio_test_hugetlb_cma(folio);
	atomic_set(&metadata->nr_pages_waiting_to_be_merged, 0);
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

static void hugetlb_restructuring_freeze_folio(struct folio *folio)
{
	const int filemap_refcount = folio_nr_pages(folio);

	while (!folio_ref_freeze(folio, filemap_refcount)) {
		WARN_ONCE(1, "Spinning on folio=%p refcount=%d", folio,
			  folio_ref_count(folio));
		cond_resched();
	}
}

static void hugetlb_restructuring_unfreeze_folio(struct folio *folio)
{
	const int filemap_refcount = folio_nr_pages(folio);

	folio_ref_unfreeze(folio, filemap_refcount);
}

static int split_entries(struct address_space *mapping, pgoff_t index,
			 u8 current_order, u8 to_order)
{
	XA_STATE(xas, &mapping->i_pages, 0);
	void *entry;
	int ret;

	xas_set_order(&xas, index, current_order);

	rcu_read_lock();
	entry = xas_load(&xas);
	rcu_read_unlock();

	xas_set_order(&xas, index, to_order);

	xas_split_alloc(&xas, entry, current_order, GFP_KERNEL);
	ret = xas_error(&xas);
	if (ret) {
		xas_destroy(&xas);
	} else {
		xas_lock_irq(&xas);
		xas_split(&xas, entry, current_order);
		xas_unlock_irq(&xas);
	}

	return ret;
}

static void merge_entries(struct address_space *mapping, pgoff_t index,
			  u8 current_order, u8 to_order)
{
	XA_STATE(xas, &mapping->i_pages, 0);
	void *entry;

	WARN_ON(to_order <= current_order);

	xas_set_order(&xas, index, current_order);

	rcu_read_lock();
	entry = xas_load(&xas);
	rcu_read_unlock();

	xas_set_order(&xas, index, to_order);

	xas_lock_irq(&xas);
	xas_store(&xas, entry);
	xas_unlock_irq(&xas);
}

static int hugetlb_restructuring_split_folio(struct folio *folio, u8 to_order)
{
	struct address_space *mapping = folio->mapping;
	u8 current_order = folio_order(folio);
	struct hstate *current_h;
	struct folio *end_folio;
	struct folio *f;
	pgoff_t index;
	int ret;

	/* For now, only support to_order == 0. */
	WARN_ON(to_order != 0);

	/* TODO: handle poisoned folios. */
	WARN_ON(folio_test_hwpoison(folio));

	index = folio->index;
	current_h = hugetlb_order_to_hstate(current_order);
	end_folio = folio_next(folio);

	ret = split_entries(mapping, index, current_order, to_order);
	if (ret)
		goto err;

	hugetlb_restructuring_freeze_folio(folio);

	/*
	 * hugetlb_vmemmap_restore_folio() has to be called ahead of the rest
	 * because it checks page type. This doesn't actually split the folio,
	 * so the first few struct pages are still intact.
	 */
	ret = hugetlb_vmemmap_restore_folio(current_h, folio);
	if (ret)
		goto err_unfreeze;

	/*
	 * Can clear without lock because this will not race with the folio
	 * being mapped. folio's page type is overlaid with mapcount and so in
	 * other cases it's necessary to take hugetlb_lock to prevent races with
	 * mapcount increasing.
	 */
	__folio_clear_hugetlb(folio);

	__split_folio_to_order(folio, current_order, to_order);

	xa_lock_irq(&mapping->i_pages);
	for (f = folio; f != end_folio; f = folio_next(f))
		__xa_store(&mapping->i_pages, f->index, f, 0);
	xa_unlock_irq(&mapping->i_pages);

	for (f = folio; f != end_folio; f = folio_next(f))
		hugetlb_restructuring_unfreeze_folio(f);

	return 0;

err_unfreeze:
	hugetlb_restructuring_unfreeze_folio(folio);
err:
	merge_entries(mapping, index, to_order, current_order);
	return ret;
}

static void __merge_folio_to_order(struct folio *folio, unsigned int to_order)
{
	struct address_space *mapping = folio->mapping;

	prep_compound_page(folio_page(folio, 0), to_order);

	folio->mapping = mapping;
}

static int merge_unreferenced_folio(struct folio *first_folio, u8 to_order)
{
	struct hstate *h;

	WARN_ON_ONCE(!IS_ALIGNED(first_folio->index, 1 << to_order));

	__merge_folio_to_order(first_folio, to_order);

	__folio_set_hugetlb(first_folio);
	h = hugetlb_order_to_hstate(folio_order(first_folio));
	hugetlb_vmemmap_optimize_folio(h, first_folio);

	return 0;
}

static int hugetlb_restructuring_merge_folio(struct folio *first_folio, u8 to_order)
{
	struct folio *f, *end_folio;
	int ret;

	end_folio = (struct folio *)folio_page(first_folio, 1 << to_order);
	for (f = first_folio; f != end_folio; f = folio_next(f))
		hugetlb_restructuring_freeze_folio(f);

	merge_entries(first_folio->mapping, first_folio->index,
		      folio_order(first_folio), to_order);

	ret = merge_unreferenced_folio(first_folio, to_order);
	WARN_ON_ONCE(ret);

	hugetlb_restructuring_unfreeze_folio(first_folio);

	return ret;
}

int hugetlb_restructuring_restructure_folio(struct folio *folio, u8 to_order)
{
	u8 order = folio_order(folio);

	if (order > to_order)
		return hugetlb_restructuring_split_folio(folio, to_order);
	else if (order < to_order)
		return hugetlb_restructuring_merge_folio(folio, to_order);
	else
		return 0;
}

EXPORT_SYMBOL_FOR_MODULES(hugetlb_restructuring_restructure_folio, "kvm");

static struct folio *maybe_merge_unreferenced_folio(struct folio *folio)
{
	struct hugetlb_restructuring_metadata *metadata;
	size_t nr_pages_waiting_to_be_merged;
	unsigned long first_folio_pfn;
	struct folio *first_folio;
	size_t original_nr_pages;
	u8 original_order;
	int ret;

	unsigned long pfn = folio_pfn(folio);
	metadata = hugetlb_restructuring_metadata_get(pfn);
	original_order = metadata->page_order;
	original_nr_pages = 1 << original_order;

	nr_pages_waiting_to_be_merged = atomic_add_return(
		folio_nr_pages(folio), &metadata->nr_pages_waiting_to_be_merged);
	if (nr_pages_waiting_to_be_merged < original_nr_pages)
		return NULL;

	first_folio_pfn = round_down(pfn, original_nr_pages);
	first_folio = pfn_folio(first_folio_pfn);

	ret = merge_unreferenced_folio(first_folio, original_order);
	if (ret) {
		WARN_ONCE(ret, "Error merging unreferenced folio.");
		return ERR_PTR(ret);
	}

	return first_folio;
}

static void hugetlb_restructuring_cleanup_folio(struct folio *folio)
{
	struct folio *merged_folio = maybe_merge_unreferenced_folio(folio);

	if (!IS_ERR_OR_NULL(merged_folio)) {
		hugetlb_restructuring_metadata_restore(merged_folio);
		__folio_put(merged_folio);
	}
}

struct workqueue_struct *hugetlb_restructuring_wq __ro_after_init;
static struct work_struct hugetlb_restructuring_cleanup_work;
static LLIST_HEAD(hugetlb_restructuring_cleanup_list);

static void hugetlb_restructuring_cleanup_workfn(struct work_struct *work)
{
	struct llist_node *node = llist_del_all(&hugetlb_restructuring_cleanup_list);

	while (node) {
		struct folio *folio;

		folio = container_of((struct address_space **)node,
				     struct folio, mapping);

		node = node->next;
		folio->mapping = NULL;

		hugetlb_restructuring_cleanup_folio(folio);
	}
}

static int __init hugetlb_restructuring_init(void)
{
	INIT_WORK(&hugetlb_restructuring_cleanup_work, hugetlb_restructuring_cleanup_workfn);

	hugetlb_restructuring_wq = alloc_workqueue("hugetlb_restructuring",
						   WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	if (!hugetlb_restructuring_wq)
		return -ENOMEM;

	return 0;
}
subsys_initcall(hugetlb_restructuring_init);
