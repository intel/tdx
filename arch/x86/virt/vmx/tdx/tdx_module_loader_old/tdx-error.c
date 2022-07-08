// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include "tdx_errno.h"
#include "tdx_arch.h"
#include "tdx_host.h"

#include "p-seamldr.h"

struct tdx_seamcall_status {
	u64 err_code;
	const char *err_name;
};

static const struct tdx_seamcall_status p_seamldr_error_codes[] = {
	P_SEAMLDR_ERROR_CODES
};

const char *p_seamldr_error_name(u64 error_code)
{
	struct tdx_seamcall_status status;
	int i;

	for (i = 0; i < ARRAY_SIZE(p_seamldr_error_codes); i++) {
		status = p_seamldr_error_codes[i];
		if (error_code == status.err_code)
			return status.err_name;
	}
	return "Unknown SEAMLDR error code";
}
