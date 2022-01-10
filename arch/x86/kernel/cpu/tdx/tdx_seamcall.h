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
#define TDH_SYS_KEY_CONFIG	31
#define TDH_SYS_INFO		32
#define TDH_SYS_INIT		33
#define TDH_SYS_LP_INIT		35
#define TDH_SYS_TDMR_INIT	36
#define TDH_SYS_LP_SHUTDOWN	44
#define TDH_SYS_CONFIG		45

static inline int tdh_sys_key_config(u64 *seamcall_ret)
{
	int ret;

	ret = tdx_seamcall(TDH_SYS_KEY_CONFIG, NULL, seamcall_ret, NULL);
	/*
	 * TDH.SYS.KEY.CONFIG may fail with recoverable errors (i.e. due
	 * to entropy error), and tdx_seamcall() returns -EFAULT in this
	 * case.  It should not return any other errors.  WARN_ON() if
	 * it does.
	 */
	WARN_ON(ret && ret != -EFAULT);
	return ret;
}

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

static inline int tdh_sys_tdmr_init(struct tdmr_info *tdmr, u64 *next)
{
	struct seamcall_regs_in in;
	struct seamcall_regs_out out;
	int ret;

	in.rcx = tdmr->base;
	ret = tdx_seamcall(TDH_SYS_TDMR_INIT, &in, NULL, &out);
	/* TDH.SYS.TDMR.INIT should not fail.  WARN_ON() if it does. */
	if (WARN_ON(ret))
		return ret;

	/*
	 * RDX contains 'next-to-initialize' address if
	 * TDH.SYS.TDMR.INIT succeeds.
	 */
	*next = out.rdx;

	return 0;
}

static inline int tdh_sys_lp_shutdown(void)
{
	int ret;

	ret = tdx_seamcall(TDH_SYS_LP_SHUTDOWN, NULL, NULL, NULL);
	/* TDH.SYS.LP.SHUTDOWN should not fail.  WARN_ON() if it does. */
	WARN_ON(ret);
	return ret;
}

static inline int tdh_sys_config(u64 *tdmr_pa_array, u64 tdmr_num,
				 u64 global_keyid)
{
	struct seamcall_regs_in in;
	int ret;

	in.rcx = __pa(tdmr_pa_array);
	in.rdx = tdmr_num;
	in.r8 = global_keyid;

	ret = tdx_seamcall(TDH_SYS_CONFIG, &in, NULL, NULL);
	/* TDH.SYS.CONFIG should not fail.  WARN_ON() if it does. */
	WARN_ON(ret);
	return ret;
}

#endif /* _X86_TDX_SEAMCALL_H */
