/* SPDX-License-Identifier: GPL-2.0-only */
/* C-wrapper function for TDX SEAMCALL */
#ifndef __TDX_OPS_H
#define __TDX_OPS_H

#include <asm/cpu.h>

static inline u64 tdh_sys_info(u64 tdsysinfo, int nr_bytes, u64 cmr_info,
			       int nr_cmr_entries, struct tdx_ex_ret *ex)
{
	return seamcall(SEAMCALL_TDH_SYS_INFO, tdsysinfo, nr_bytes,
			cmr_info, nr_cmr_entries, ex);
}

static inline u64 tdh_sys_init(u64 attributes, struct tdx_ex_ret *ex)
{
	return seamcall(SEAMCALL_TDH_SYS_INIT, attributes, 0, 0, 0, ex);
}

static inline u64 tdh_sys_lp_init(struct tdx_ex_ret *ex)
{
	return seamcall(SEAMCALL_TDH_SYS_LP_INIT, 0, 0, 0, 0, ex);
}

#endif /* __TDX_OPS_H */
