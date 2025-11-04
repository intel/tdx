// SPDX-License-Identifier: GPL-2.0-only
/*
 * Wrapper for HugeTLB to provide pages for guest_memfd.
 */

#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/hugetlb_restructuring.h>
#include <linux/kvm.h>
#include <linux/mempolicy.h>

#include "guest_memfd_hugetlb.h"

struct gmem_hugetlb {
	struct hstate *h;
	struct hugepage_subpool *spool;
	struct hugetlb_cgroup *h_cg_rsvd;
};

bool gmem_hugetlb_valid_order(u8 order)
{
	if (order == 0)
		return false;

	return (bool)hugetlb_order_to_hstate(order);
}

static void *gmem_hugetlb_setup(size_t size, u8 page_order)
{
	struct hugetlb_cgroup *h_cg_rsvd = NULL;
	struct hugepage_subpool *spool;
	struct gmem_hugetlb *private;
	unsigned long nr_pages;
	struct hstate *h;
	long hpages;
	int ret;

	private = kzalloc(sizeof(*private), GFP_KERNEL);
	if (!private)
		return ERR_PTR(-ENOMEM);

	/* Creating a subpool makes reservations, hence charge for them now. */
	nr_pages = size >> PAGE_SHIFT;
	ret = hugetlb_cgroup_charge_cgroup_rsvd_for_order(page_order, nr_pages,
							  &h_cg_rsvd);
	if (ret)
		goto err_free;

	h = hugetlb_order_to_hstate(page_order);
	hpages = size >> (page_order + PAGE_SHIFT);
	spool = hugepage_new_subpool(h, hpages, hpages, false);
	if (!spool)
		goto err_uncharge;

	private->h = h;
	private->spool = spool;
	private->h_cg_rsvd = h_cg_rsvd;

	return private;

err_uncharge:
	ret = -ENOMEM;
	hugetlb_cgroup_uncharge_cgroup_rsvd_for_order(page_order, nr_pages,
						      h_cg_rsvd);
err_free:
	kfree(private);
	return ERR_PTR(ret);
}

int gmem_hugetlb_init(struct inode *inode, u64 flags, size_t size,
		      u8 page_order)
{
	void *private;

	if (!(flags & GUEST_MEMFD_FLAG_HUGETLB))
		return 0;

	private = gmem_hugetlb_setup(size, page_order);
	if (IS_ERR(private))
		return PTR_ERR(private);

	inode->i_private = private;
	inode->i_blkbits = page_order + PAGE_SHIFT;

	return 0;
}

void gmem_hugetlb_teardown(struct inode *inode, u8 page_order, u64 flags)
{
	unsigned long nr_pages = inode->i_size >> PAGE_SHIFT;
	struct gmem_hugetlb *private = inode->i_private;

	if (!(flags & GUEST_MEMFD_FLAG_HUGETLB))
		return;

	/* private may be NULL if inode creation process had some error. */
	if (!private)
		return;

	hugepage_put_subpool(private->spool);

	hugetlb_cgroup_uncharge_cgroup_rsvd_for_order(page_order, nr_pages,
						      private->h_cg_rsvd);

	kfree(private);
}

struct folio *gmem_hugetlb_alloc_folio(void *priv, u8 page_order, struct mempolicy *mpol)
{
	struct gmem_hugetlb *private = priv;
	struct folio *folio;
	struct hstate *h;
	pgoff_t ilx;
	int ret;

	ret = hugepage_subpool_get_pages(private->spool, 1);
	if (ret == -ENOMEM) {
		return ERR_PTR(-ENOMEM);
	} else if (ret > 0) {
		/* guest_memfd will not use surplus pages. */
		goto err_put_pages;
	}

	/* TODO: ignore interleaving for now. */
	ilx = NO_INTERLEAVE_INDEX;

	/*
	 * charge_cgroup_rsvd is false because we already charged reservations
	 * when creating the subpool for this
	 * guest_memfd. use_existing_reservation is true - we're using a
	 * reservation from the guest_memfd's subpool.
	 */
	h = hugetlb_order_to_hstate(page_order);
	folio = hugetlb_alloc_folio(h, mpol, ilx, false, true);
	if (IS_ERR_OR_NULL(folio))
		goto err_put_pages;

	/*
	 * Clear restore_reserve here so that when this folio is freed,
	 * free_huge_folio() will always attempt to return the reservation to
	 * the subpool.  guest_memfd, unlike regular hugetlb, has no resv_map,
	 * and hence when freeing, the folio needs to be returned to the
	 * subpool.  guest_memfd does not use surplus hugetlb pages, so in
	 * free_huge_folio(), returning to subpool will always succeed and the
	 * hstate reservation will then get restored.
	 *
	 * hugetlbfs does this in hugetlb_add_to_page_cache().
	 */
	folio_clear_hugetlb_restore_reserve(folio);

	hugetlb_set_folio_subpool(folio, private->spool);

	ret = hugetlb_restructuring_metadata_store(folio);
	if (ret) {
		folio_put(folio);
		return ERR_PTR(ret);
	}

	return folio;

err_put_pages:
	hugepage_subpool_put_pages(private->spool, 1);
	return ERR_PTR(-ENOMEM);
}

int gmem_hugetlb_restructure_folio(struct address_space *mapping,
				   pgoff_t index, u8 to_order)
{
	struct folio *folio = filemap_get_folio(mapping, index);

	if (IS_ERR(folio))
		return 0;

	/* Leave only filemap refcounts on folio. */
	folio_put(folio);

	return hugetlb_restructuring_restructure_folio(folio, to_order);
}
