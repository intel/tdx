/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel TDX module SEAMCALL wrapper functions
 */

#ifndef _X86_TDX_SEAMCALL_H
#define _X86_TDX_SEAMCALL_H

#include <linux/types.h>
#include <asm/seam.h>

/* TDX module SEAMCALL leaf function numbers */
#define TDH_SYS_LP_SHUTDOWN	44

static inline int tdh_sys_lp_shutdown(void)
{
	int ret;

	ret = tdx_seamcall(TDH_SYS_LP_SHUTDOWN, NULL, NULL, NULL);
	/* TDH.SYS.LP.SHUTDOWN should not fail.  WARN_ON() if it does. */
	WARN_ON(ret);
	return ret;
}

#endif /* _X86_TDX_SEAMCALL_H */
