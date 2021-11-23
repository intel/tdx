// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include <linux/kernel.h>
#include <linux/bug.h>

#include "tdx_errno.h"
#include "tdx_arch.h"
#include "tdx_ops.h"

#define CREATE_TRACE_POINTS
#include "tdx_trace.h"

EXPORT_TRACEPOINT_SYMBOL_GPL(tdx_seamcall);
EXPORT_TRACEPOINT_SYMBOL_GPL(tdx_seamret);

struct tdx_name {
	u64 value;
	const char *name;
};

static const char *tdx_find_name(u64 value, const struct tdx_name *names,
				int size, const char *not_found)
{
	int i;

	for (i = 0; i < size; i++) {
		if (value == names[i].value)
			return names[i].name;
	}
	return not_found;
}

static const char *tdx_seamcall_name(u64 op)
{
	static const struct tdx_name names[] = {
		TDX_SEAMCALLS
	};

	return tdx_find_name(op, names, ARRAY_SIZE(names),
			"Unknown TDX SEAMCALL op");
}

const char *tdx_error_name(u64 error_code)
{
	static const struct tdx_name names[] = {
		TDX_STATUS_CODES
	};

	return tdx_find_name(error_code & TDX_SEAMCALL_STATUS_MASK,
			names, ARRAY_SIZE(names),
			"Unknown SEAMCALL status code");
}

static const char * const TDX_SEPT_ENTRY_STATES[] = {
	"SEPT_FREE",
	"SEPT_BLOCKED",
	"SEPT_PENDING",
	"SEPT_PENDING_BLOCKED",
	"SEPT_PRESENT"
};

void pr_tdx_ex_ret_info(u64 op, u64 error_code, const struct tdx_ex_ret *ex_ret)
{
	if (WARN_ON(!ex_ret))
		return;

	switch (error_code & TDX_SEAMCALL_STATUS_MASK) {
	case TDX_EPT_WALK_FAILED: {
		const char *state;

		if (ex_ret->sept_walk.state >= ARRAY_SIZE(TDX_SEPT_ENTRY_STATES))
			state = "Invalid";
		else
			state = TDX_SEPT_ENTRY_STATES[ex_ret->sept_walk.state];

		pr_err("Secure EPT walk error: SEPTE 0x%llx, level %d, %s\n",
			ex_ret->sept_walk.septe, ex_ret->sept_walk.level, state);
		break;
	}
	default:
		/* TODO: print only meaningful registers depending on op */
		pr_err("RCX 0x%llx, RDX 0x%llx, R8 0x%llx, R9 0x%llx, "
		       "R10 0x%llx, R11 0x%llx\n",
			ex_ret->regs.rcx, ex_ret->regs.rdx, ex_ret->regs.r8,
			ex_ret->regs.r9, ex_ret->regs.r10, ex_ret->regs.r11);
		break;
	}
}

void pr_tdx_error(u64 op, u64 error_code, const struct tdx_ex_ret *ex_ret)
{
	pr_err_ratelimited("SEAMCALL[%s(0x%llx)] failed: %s (0x%llx)\n",
			tdx_seamcall_name(op), op,
			tdx_error_name(error_code), error_code);
	if (ex_ret)
		pr_tdx_ex_ret_info(op, error_code, ex_ret);
}
