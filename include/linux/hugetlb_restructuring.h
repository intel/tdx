#ifndef _LINUX_HUGETLB_RESTRUCTURING_H
#define _LINUX_HUGETLB_RESTRUCTURING_H

#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/types.h>

struct hugetlb_restructuring_metadata {
	/* Track subpool, since folio may outlive the inode. */
	struct hugepage_subpool *spool;
	/* The cgroup holding the usage charge for this allocated folio. */
	struct hugetlb_cgroup *h_cg;
	/* The cgroup holding the reservation charge for this allocated folio. */
	struct hugetlb_cgroup *h_cg_rsvd;
	/* Tracks the original size of this folio. */
	u8 page_order;
	/* Whether CMA was used to allocate this HugeTLB folio. */
	bool hugetlb_cma;
	/* Count of split pages, individually freed, waiting to be merged. */
	atomic_t nr_pages_waiting_to_be_merged;
};

int hugetlb_restructuring_metadata_store(struct folio *folio);
void hugetlb_restructuring_metadata_restore(struct folio *folio);
struct hugetlb_restructuring_metadata *hugetlb_restructuring_metadata_get(unsigned long pfn);

int hugetlb_restructuring_restructure_folio(struct folio *folio, u8 to_order);

#endif  /* _LINUX_HUGETLB_RESTRUCTURING_H */
