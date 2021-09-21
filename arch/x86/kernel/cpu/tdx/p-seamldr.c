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
 * is_seamrr_enabled - check if seamrr is supported.
 */
static bool __init is_seamrr_enabled(void)
{
	u64 mtrrcap, seamrr_base, seamrr_mask;

	if (!boot_cpu_has(X86_FEATURE_MTRR))
		return false;

	/* MTRRcap.SEAMRR indicates the support of SEAMRR_PHYS_{BASE, MASK} */
	rdmsrl(MSR_MTRRcap, mtrrcap);
	if (!(mtrrcap & MTRRCAP_SEAMRR))
		return false;

	rdmsrl(MSR_IA32_SEAMRR_PHYS_BASE, seamrr_base);
	if (!(seamrr_base & MSR_IA32_SEAMRR_PHYS_BASE_CONFIGURED)) {
		pr_info("SEAMRR base is not configured by BIOS\n");
		return false;
	}

	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, seamrr_mask);
	if (!(seamrr_mask & MSR_IA32_SEAMRR_PHYS_MASK_ENABLED)) {
		pr_info("SEAMRR is not enabled by BIOS\n");
		return false;
	}

	return true;
}

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
	int err;

	/* TDX requires SEAM mode. */
	if (!is_seamrr_enabled())
		return -EOPNOTSUPP;

	/* TDX requires VMX. */
	err = seam_init_vmx_early();
	if (err)
		return err;

	if (!seam_get_firmware(&np_seamldr, np_seamldr_name)) {
		pr_err("no NP-SEAMLDR found %s\n", np_seamldr_name);
		return -ENOENT;
	}

	/* TODO: Launch NP-SEAMLDR */
	if (np_seamldr_len)
		memblock_free_late(__pa(np_seamldr_name), np_seamldr_len);
	return 0;
}
