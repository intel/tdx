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
struct tdx_module_args {
        u64 rax_unused;
        u64 rcx;
        u64 rdx;
        u64 rbx;
        u64 rsp_unused;
        u64 rbp_unused;
        u64 rsi;
        u64 rdi;
        u64 r8;
        u64 r9;
        u64 r10;
        u64 r11;
        u64 r12;
        u64 r13;
        u64 r14;
        u64 r15;
};

u64 __seamcall(u64 fn, struct tdx_module_args *args);
u64 __seamcall_ret(u64 fn, struct tdx_module_args *args);

static inline u64 seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			   struct tdx_ex_ret *ex)
{
	struct tdx_module_args args = {
		.rcx = rcx,
		.rdx = rdx,
		.r8 = r8,
		.r9 = r9,
	};
	u64 err;

	if (ex) {
		err = __seamcall_ret(op, &args);
		ex->regs.rcx = args.rcx;
		ex->regs.rdx = args.rdx;
		ex->regs.r8 = args.r8;
		ex->regs.r9 = args.r9;
		ex->regs.r10 = args.r10;
		ex->regs.r11 = args.r11;
	} else {
		err = __seamcall(op, &args);
	}

	return err;
}

#endif /* __SEAM_SEAMCALL_H */
