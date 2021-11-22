// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include <linux/kernel.h>
#include <linux/bug.h>

#include "tdx_ops.h"

void pr_tdx_error(u64 op, u64 error_code, const union tdx_ex_ret *ex)
{
	if (!ex) {
		pr_err_ratelimited("SEAMCALL[%lld] failed: 0x%llx\n",
				op, error_code);
		return;
	}

	pr_err_ratelimited(
		"SEAMCALL[%lld] failed: 0x%llx "
		"RCX 0x%llx, RDX 0x%llx, R8 0x%llx, R9 0x%llx, R10 0x%llx, R11 0x%llx\n",
		op, error_code, ex->regs.rcx, ex->regs.rdx, ex->regs.r8,
		ex->regs.r9, ex->regs.r10, ex->regs.r11);
}
