// SPDX-License-Identifier: GPL-2.0
/* Load and initialize TDX-module. */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/init.h>
#include "p-seamldr.h"

static int __init tdx_early_init(void)
{
	int ret;

	ret = load_p_seamldr();

	return ret;
}
early_initcall(tdx_early_init);
