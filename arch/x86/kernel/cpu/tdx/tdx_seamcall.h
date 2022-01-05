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
#include "tdx_arch.h"

/* TDX module SEAMCALL leaf function numbers */
#define TDH_SYS_INFO		32
#define TDH_SYS_INIT		33
#define TDH_SYS_LP_INIT		35
#define TDH_SYS_LP_SHUTDOWN	44

static inline int tdh_sys_info(struct tdsysinfo_struct *tdsysinfo,
			       struct cmr_info *cmr_array,
			       u64 *tdsysinfo_sz, u64 *cmr_num)
{
	struct seamcall_regs_in in;
	struct seamcall_regs_out out;
	int ret;

	in.rcx = __pa(tdsysinfo);
	in.rdx = sizeof(*tdsysinfo);
	in.r8 = __pa(cmr_array);
	in.r9 = MAX_CMRS;

	ret = tdx_seamcall(TDH_SYS_INFO, &in, NULL, &out);
	/* TDH.SYS.INFO should not fail.  WARN_ON() if it does. */
	if (WARN_ON(ret))
		return ret;

	/*
	 * If SEAMCALL succeeds, RDX contains the actual bytes written
	 * to @tdsysinfo and R9 contains the actual written number of
	 * CMR_INFO entries.  Otherwise both fields are 0.
	 */
	*tdsysinfo_sz = out.rdx;
	*cmr_num = out.r9;

	return 0;
}

static inline int tdh_sys_init(void)
{
	struct seamcall_regs_in in;
	int ret;

	/* Must be 0 for the first generation of TDX */
	in.rcx = 0;
	ret = tdx_seamcall(TDH_SYS_INIT, &in, NULL, NULL);
	/* TDH.SYS.INIT should not fail.  WARN_ON() if it does. */
	WARN_ON(ret);
	return ret;
}

static inline int tdh_sys_lp_init(void)
{
	int ret;

	ret = tdx_seamcall(TDH_SYS_LP_INIT, NULL, NULL, NULL);
	/* TDH.SYS.LP.INIT should not fail.  WARN_ON() if it does. */
	WARN_ON(ret);
	return ret;
}

static inline int tdh_sys_lp_shutdown(void)
{
	int ret;

	ret = tdx_seamcall(TDH_SYS_LP_SHUTDOWN, NULL, NULL, NULL);
	/* TDH.SYS.LP.SHUTDOWN should not fail.  WARN_ON() if it does. */
	WARN_ON(ret);
	return ret;
}

#endif /* _X86_TDX_SEAMCALL_H */
