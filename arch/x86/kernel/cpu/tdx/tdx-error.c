// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include <linux/kvm_types.h>
#include <linux/trace_events.h>

#include <asm/tdx_errno.h>
#include <asm/tdx_arch.h>

#include "p-seamldr.h"

#define CREATE_TRACE_POINTS
#include <asm/trace/seam.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(seamcall_enter);
EXPORT_TRACEPOINT_SYMBOL_GPL(seamcall_exit);

struct tdx_seamcall_status {
	u64 err_code;
	const char *err_name;
};

static const struct tdx_seamcall_status p_seamldr_error_codes[] = {
	P_SEAMLDR_ERROR_CODES
};

static const struct tdx_seamcall_status tdx_status_codes[] = {
	TDX_STATUS_CODES
};

const char *tdx_seamcall_error_name(u64 error_code)
{
	struct tdx_seamcall_status status;
	int i;

	if ((error_code & TDX_SEAMCALL_STATUS_MASK) ==
	    P_SEAMLDR_SEAMCALL_ERROR_CODE) {
		for (i = 0; i < ARRAY_SIZE(p_seamldr_error_codes); i++) {
			status = p_seamldr_error_codes[i];
			if (error_code == status.err_code)
				return status.err_name;
		}
		return "Unknown SEAMLDR error code";
	}

	for (i = 0; i < ARRAY_SIZE(tdx_status_codes); i++) {
		status = tdx_status_codes[i];
		if ((error_code & TDX_SEAMCALL_STATUS_MASK) == status.err_code)
			return status.err_name;
	}

	return "Unknown SEAMCALL status code";
}
EXPORT_SYMBOL_GPL(tdx_seamcall_error_name);

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
		       ex_ret->rcx, ex_ret->rdx, ex_ret->r8, ex_ret->r9,
		       ex_ret->r10, ex_ret->r11);
		break;
	}
}
EXPORT_SYMBOL_GPL(pr_seamcall_ex_ret_info);
