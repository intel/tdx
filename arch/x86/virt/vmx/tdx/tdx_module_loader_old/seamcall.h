/* SPDX-License-Identifier: GPL-2.0-only */
/* C function wrapper for SEAMCALL */
#ifndef __SEAM_SEAMCALL_H
#define __SEAM_SEAMCALL_H

#include <linux/linkage.h>

#include "tdx_host.h"

/*
 * Used to gather the output registers values of the TDCALL and SEAMCALL
 * instructions when requesting services from the TDX module.
 *
 * This is a software only structure and not part of the TDX module/VMM ABI.
 */
struct tdx_module_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
};

extern u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
	       u64 r11, u64 r12, u64 r13, struct tdx_module_output *out);

static inline u64 seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			   struct tdx_ex_ret *ex)
{
	struct tdx_ex_ret dummy;
	struct tdx_module_output out;
	u64 err;

	if (!ex)
		/* __seamcall requires non-NULL ex. */
		ex = &dummy;

	err = __seamcall(op, rcx, rdx, r8, r9, 0, 0, 0, 0, &out);
	ex->regs.rcx = out.rcx;
	ex->regs.rdx = out.rdx;
	ex->regs.r8 = out.r8;
	ex->regs.r9 = out.r9;
	ex->regs.r10 = out.r10;
	ex->regs.r11 = out.r11;

	return err;
}

#endif /* __SEAM_SEAMCALL_H */
