// SPDX-License-Identifier: GPL-2.0-only
/*
 * Wrapper for HugeTLB to provide pages for guest_memfd.
 */

#include <linux/hugetlb.h>

#include "guest_memfd_hugetlb.h"

bool gmem_hugetlb_valid_order(u8 order)
{
	if (order == 0)
		return false;

	return (bool)hugetlb_order_to_hstate(order);
}
