// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include <linux/kernel.h>
#include <linux/bug.h>

#include "tdx_ops.h"

void pr_tdx_error(u64 op, u64 error_code, const struct tdx_module_output *out)
{
	if (!out) {
		pr_err_ratelimited("SEAMCALL[%lld] failed: 0x%llx\n",
				op, error_code);
		return;
	}

	pr_err_ratelimited(
		"SEAMCALL[%lld] failed: 0x%llx "
		"RCX 0x%llx, RDX 0x%llx, R8 0x%llx, R9 0x%llx, R10 0x%llx, R11 0x%llx\n",
		op, error_code,
		out->rcx, out->rdx, out->r8, out->r9, out->r10, out->r11);
}
