// SPDX-License-Identifier: GPL-2.0
/* Load and initialize TDX-module. */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/init.h>

#include "p-seamldr.h"

enum TDX_HOST_OPTION {
	TDX_HOST_OFF,
	TDX_HOST_ON,
};

static enum TDX_HOST_OPTION tdx_host __initdata;

static int __init tdx_host_param(char *str)
{
	if (!strcmp(str, "on"))
		tdx_host = TDX_HOST_ON;

	return 0;
}
early_param("tdx_host", tdx_host_param);

static int __init tdx_early_init(void)
{
	int ret;

	/* Avoid TDX overhead when opt-in is not present. */
	if (tdx_host != TDX_HOST_ON)
		return 0;

	ret = load_p_seamldr();
	return ret;
}
early_initcall(tdx_early_init);
