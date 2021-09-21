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

	/* TDX requires SEAM mode. */
	if (!is_seamrr_enabled())
		return -EOPNOTSUPP;

	/* TDX requires VMX. */
	ret = seam_init_vmx_early();
	if (ret)
		return ret;

	/*
	 * Check if P-SEAMLDR is available and log its version information for
	 * the administrator of the machine.  Although the kernel don't use
	 * P-SEAMLDR at the moment, it's a part of TCB.  It's worthwhile to
	 * tell it to the administrator of the machine.
	 */
	ret = p_seamldr_get_info();
	if (ret) {
		pr_info("No P-SEAMLDR is available.\n");
		return ret;
	}
	setup_force_cpu_cap(X86_FEATURE_SEAM);

	return 0;
}

/*
 * arch_initcall() is chosen to satisfy the following conditions.
 * - After SMP initialization.
 */
arch_initcall(tdx_arch_init);
