// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include <linux/kernel.h>
#include <linux/bug.h>

#include "tdx_ops.h"

void pr_tdx_error(u64 op, u64 error_code, const struct tdx_module_args *out)
{
	if (!out) {
		pr_err_ratelimited("SEAMCALL (0x%016llx) failed: 0x%016llx\n",
				   op, error_code);
		return;
	}

#define MSG	\
	"SEAMCALL (0x%016llx) failed: 0x%016llx RCX 0x%016llx RDX 0x%016llx R8 0x%016llx R9 0x%016llx R10 0x%016llx R11 0x%016llx\n"
	pr_err_ratelimited(MSG, op, error_code, out->rcx, out->rdx, out->r8,
			   out->r9, out->r10, out->r11);
}
