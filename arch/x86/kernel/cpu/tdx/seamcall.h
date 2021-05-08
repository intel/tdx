/* SPDX-License-Identifier: GPL-2.0-only */
/* C function wrapper for SEAMCALL */
#ifndef __SEAM_SEAMCALL_H
#define __SEAM_SEAMCALL_H

#include <linux/linkage.h>

#include <asm/tdx_host.h>

asmlinkage u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			  struct tdx_ex_ret *ex);

static inline u64 seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			   struct tdx_ex_ret *ex)
{
	struct tdx_ex_ret dummy;

	if (!ex)
		/* __seamcall requires non-NULL ex. */
		ex = &dummy;

	return __seamcall(op, rcx, rdx, r8, r9, ex);
}

#endif /* __SEAM_SEAMCALL_H */
