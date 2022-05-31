// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2022 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) support
 */

#define pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <asm/cpufeatures.h>
#include <asm/cpufeature.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/tdx.h>
#include <asm/coco.h>
#include "tdx.h"

static u32 tdx_keyid_start __ro_after_init;
static u32 tdx_keyid_num __ro_after_init;

/* Detect whether CPU supports SEAM */
static int detect_seam(void)
{
	u64 mtrrcap, mask;

	/* SEAMRR is reported via MTRRcap */
	if (!boot_cpu_has(X86_FEATURE_MTRR))
		return -ENODEV;

	rdmsrl(MSR_MTRRcap, mtrrcap);
	if (!(mtrrcap & MTRR_CAP_SEAMRR))
		return -ENODEV;

	/* The MASK MSR reports whether SEAMRR is enabled */
	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, mask);
	if ((mask & SEAMRR_ENABLED_BITS) != SEAMRR_ENABLED_BITS)
		return -ENODEV;

	pr_info("SEAMRR enabled.\n");
	return 0;
}

static int detect_tdx_keyids(void)
{
	u64 keyid_part;

	rdmsrl(MSR_IA32_MKTME_KEYID_PARTITIONING, keyid_part);

	tdx_keyid_num = TDX_KEYID_NUM(keyid_part);
	tdx_keyid_start = TDX_KEYID_START(keyid_part);

	pr_info("TDX private KeyID range: [%u, %u).\n",
			tdx_keyid_start, tdx_keyid_start + tdx_keyid_num);

	/*
	 * TDX guarantees at least two TDX KeyIDs are configured by
	 * BIOS, otherwise SEAMRR is disabled.  Invalid TDX private
	 * range means kernel bug (TDX is broken).
	 */
	if (WARN_ON(!tdx_keyid_start || tdx_keyid_num < 2)) {
		tdx_keyid_start = tdx_keyid_num = 0;
		return -EINVAL;
	}

	return 0;
}

/*
 * Detect TDX via detecting SEAMRR during kernel boot.
 *
 * To enable TDX, BIOS must configure SEAMRR consistently across all
 * CPU cores.  TDX doesn't trust BIOS.  Instead, MCHECK verifies all
 * configurations from BIOS are correct, and if not, it disables TDX
 * (SEAMRR is disabled on all cores).  This means detecting SEAMRR on
 * BSP is enough to determine whether TDX has been enabled by BIOS.
 */
static int __init tdx_early_detect(void)
{
	int ret;

	ret = detect_seam();
	if (ret)
		return ret;

	/*
	 * TDX private KeyIDs is only accessible by SEAM software.
	 * Only detect TDX KeyIDs when SEAMRR is enabled.
	 */
	ret = detect_tdx_keyids();
	if (ret)
		return ret;

	/* Set TDX enabled platform as confidential computing platform */
	cc_set_vendor(CC_VENDOR_INTEL);

	pr_info("TDX enabled by BIOS.\n");
	return 0;
}
early_initcall(tdx_early_detect);

/**
 * platform_tdx_enabled() - Return whether BIOS has enabled TDX
 *
 * Return whether BIOS has enabled TDX regardless whether the TDX module
 * has been loaded or not.
 */
bool platform_tdx_enabled(void)
{
	return tdx_keyid_num >= 2;
}
