// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include <linux/bug.h>
#include <linux/trace_events.h>

#include <asm/tdx_errno.h>
#include <asm/tdx_arch.h>
#include <asm/tdx_host.h>

#include "p-seamldr.h"
#include "seamcall.h"

#define CREATE_TRACE_POINTS
#include <asm/trace/seam.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(seamcall_enter);
EXPORT_TRACEPOINT_SYMBOL_GPL(seamcall_exit);

void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
			     const struct tdx_ex_ret *ex_ret)
{
	if (WARN_ON(!ex_ret))
		return;

	switch (error_code & TDX_SEAMCALL_STATUS_MASK) {
	/* TODO: add API specific pretty print. */
	default:
		pr_err("RCX 0x%llx, RDX 0x%llx, R8 0x%llx, R9 0x%llx, "
		       "R10 0x%llx, R11 0x%llx\n",
			ex_ret->regs.rcx, ex_ret->regs.rdx, ex_ret->regs.r8,
			ex_ret->regs.r9, ex_ret->regs.r10, ex_ret->regs.r11);
		break;
	}
}
EXPORT_SYMBOL_GPL(pr_seamcall_ex_ret_info);

void pr_seamcall_error(u64 op, u64 error_code, const struct tdx_ex_ret *ex_ret)
{
	pr_err_ratelimited("SEAMCALL[0x%llx] failed: 0x%llx\n",
			op, error_code);
	if (ex_ret)
		pr_seamcall_ex_ret_info(op, error_code, ex_ret);
}
EXPORT_SYMBOL_GPL(pr_seamcall_error);
