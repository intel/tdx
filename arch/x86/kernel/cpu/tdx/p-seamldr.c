// SPDX-License-Identifier: GPL-2.0
/* C-wrapper functions for P-SEAMLDR SEAMCALLs and functions for P-SEAMLDR */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/earlycpio.h>
#include <linux/memblock.h>
#include <linux/slab.h>

#include <asm/cmdline.h>
#include <asm/virtext.h>

#include "p-seamldr.h"
#include "seamcall.h"
#include "seam.h"

static char *np_seamldr_name __initdata = "intel-seam/np-seamldr.acm";
static size_t np_seamldr_len __initdata;

static int __init seamldr_param(char *str)
{
	np_seamldr_len = strlen(str) + 1;

	np_seamldr_name = memblock_alloc(np_seamldr_len, 0);
	if (!np_seamldr_name) {
		np_seamldr_len = 0;
		return -ENOMEM;
	}

	strscpy(np_seamldr_name, str, np_seamldr_len);
	return 0;
}
early_param("np_seamldr", seamldr_param);

/*
 * load_p_seamldr() - load P-SEAMLDR
 *
 * Call this function
 *  - only BSP is running before bringing up all APs by smp_init().
 *  - after MTRR is setup for BSP.
 *  - after mcheck is ready.
 */
int __init load_p_seamldr(void)
{
	struct cpio_data np_seamldr;

	if (!seam_get_firmware(&np_seamldr, np_seamldr_name)) {
		pr_err("no NP-SEAMLDR found %s\n", np_seamldr_name);
		return -ENOENT;
	}

	/* TODO: Launch NP-SEAMLDR */
	if (np_seamldr_len)
		memblock_free_late(__pa(np_seamldr_name), np_seamldr_len);
	return 0;
}
