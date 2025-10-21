// SPDX-License-Identifier: GPL-2.0-only
/*
 * Wrapper for HugeTLB to provide pages for guest_memfd.
 */

#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/kvm.h>

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
