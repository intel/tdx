// SPDX-License-Identifier: GPL-2.0
/* C-wrapper functions for P-SEAMLDR SEAMCALLs and functions for P-SEAMLDR */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/kvm_types.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <asm/seamcall.h>

#include "seamcall-boot.h"
#include "p-seamldr.h"

int seamldr_info(phys_addr_t seamldr_info)
{
	u64 ret;

	ret = seamcall_boot(SEAMCALL_SEAMLDR_INFO, seamldr_info, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

int seamldr_install(phys_addr_t seamldr_params)
{
	u64 ret;

	ret = seamcall_boot(SEAMCALL_SEAMLDR_INSTALL, seamldr_params, 0, 0, 0,
			    NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

int seamldr_shutdown(void)
{
	u64 ret;

	ret = seamcall_boot(SEAMCALL_SEAMLDR_SHUTDOWN, 0, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}
