#ifndef __KVM_GUEST_MEMFD_HUGETLB_H__
#define __KVM_GUEST_MEMFD_HUGETLB_H__

#include <linux/types.h>

#ifdef CONFIG_KVM_GUEST_MEMFD_HUGETLB

bool gmem_hugetlb_valid_order(u8 order);

#else

static bool gmem_hugetlb_valid_order(u8 order)
{
	return order == 0;
}

#endif /* CONFIG_KVM_GUEST_MEMFD_HUGETLB */

#endif
