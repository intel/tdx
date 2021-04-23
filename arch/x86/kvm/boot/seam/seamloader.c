// SPDX-License-Identifier: GPL-2.0

#include <linux/kvm_types.h>
#include <linux/types.h>

#include "vmx/tdx_arch.h"
#include "seamloader.h"
#include "seamcall_boot.h"

/*
 * P-SEAMLDR API function leaves
 */
#define SEAMCALL_SEAMLDR_BASE          BIT_ULL(63)
#define SEAMCALL_SEAMLDR_INFO          SEAMCALL_SEAMLDR_BASE
#define SEAMCALL_SEAMLDR_INSTALL       (SEAMCALL_SEAMLDR_BASE | 1)
#define SEAMCALL_SEAMLDR_SHUTDOWN      (SEAMCALL_SEAMLDR_BASE | 2)

int seamldr_info(u64 seamldr_info)
{
	u64 ret;

	ret = seamcall_boot(SEAMLDR_INFO, seamldr_info, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

int seamldr_install(u64 seamldr_params)
{
	u64 ret;

	ret = seamcall_boot(SEAMLDR_INSTALL, seamldr_params, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

int seamldr_shutdown(void)
{
	u64 ret;

	ret = seamcall_boot(SEAMLDR_SHUTDOWN, 0, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}
