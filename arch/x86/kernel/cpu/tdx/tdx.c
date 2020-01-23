// SPDX-License-Identifier: GPL-2.0
/* Load and initialize TDX-module. */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/init.h>

#include <asm/cmdline.h>

#include "p-seamldr.h"

enum TDX_HOST_OPTION {
	TDX_HOST_OFF,
	TDX_HOST_ON,
};

static enum TDX_HOST_OPTION tdx_host __initdata;

static int __init tdx_host_setup(char *s)
{
	if (!strcmp(s, "on"))
		tdx_host = TDX_HOST_ON;
	return 0;
}
__setup("tdx_host=", tdx_host_setup);


/*
 * Early system wide initialization of the TDX module. Check if the TDX firmware
 * loader and the TDX firmware module are available and log their version.
 */
static int __init tdx_arch_init(void)
{
	/* Avoid TDX overhead when opt-in is not present. */
	if (tdx_host != TDX_HOST_ON)
		return 0;

	/* TODO more TDX arch initialization. */
	return 0;
}

/*
 * arch_initcall() is chosen to satisfy the following conditions.
 * - After SMP initialization.
 */
arch_initcall(tdx_arch_init);
