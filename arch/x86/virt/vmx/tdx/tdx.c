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
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/tdx.h>
#include "tdx.h"

static u32 tdx_keyid_start __ro_after_init;
static u32 tdx_keyid_num __ro_after_init;

/*
 * Detect TDX private KeyIDs to see whether TDX has been enabled by the
 * BIOS.  Both initializing the TDX module and running TDX guest require
 * TDX private KeyID.
 *
 * TDX doesn't trust BIOS.  TDX verifies all configurations from BIOS
 * are correct before enabling TDX on any core.  TDX requires the BIOS
 * to correctly and consistently program TDX private KeyIDs on all CPU
 * packages.  Unless there is a BIOS bug, detecting a valid TDX private
 * KeyID range on BSP indicates TDX has been enabled by the BIOS.  If
 * there's such BIOS bug, it will be caught later when initializing the
 * TDX module.
 */
static int __init detect_tdx(void)
{
	int ret;

	/*
	 * IA32_MKTME_KEYID_PARTIONING:
	 *   Bit [31:0]:	Number of MKTME KeyIDs.
	 *   Bit [63:32]:	Number of TDX private KeyIDs.
	 */
	ret = rdmsr_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &tdx_keyid_start,
			&tdx_keyid_num);
	if (ret)
		return -ENODEV;

	if (!tdx_keyid_num)
		return -ENODEV;

	/*
	 * KeyID 0 is for TME.  MKTME KeyIDs start from 1.  TDX private
	 * KeyIDs start after the last MKTME KeyID.
	 */
	tdx_keyid_start++;

	pr_info("TDX enabled by BIOS. TDX private KeyID range: [%u, %u)\n",
			tdx_keyid_start, tdx_keyid_start + tdx_keyid_num);

	return 0;
}

static void __init clear_tdx(void)
{
	tdx_keyid_start = tdx_keyid_num = 0;
}

static int __init tdx_init(void)
{
	if (detect_tdx())
		return -ENODEV;

	/*
	 * Initializing the TDX module requires one TDX private KeyID.
	 * If there's only one TDX KeyID then after module initialization
	 * KVM won't be able to run any TDX guest, which makes the whole
	 * thing worthless.  Just disable TDX in this case.
	 */
	if (tdx_keyid_num < 2) {
		pr_info("Disable TDX as there's only one TDX private KeyID available.\n");
		goto no_tdx;
	}

	/*
	 * TDX requires X2APIC being enabled to prevent potential data
	 * leak via APIC MMIO registers.  Just disable TDX if not using
	 * X2APIC.
	 */
	if (!x2apic_enabled()) {
		pr_info("Disable TDX as X2APIC is not enabled.\n");
		goto no_tdx;
	}

	return 0;
no_tdx:
	clear_tdx();
	return -ENODEV;
}
early_initcall(tdx_init);

/* Return whether the BIOS has enabled TDX */
bool platform_tdx_enabled(void)
{
	return !!tdx_keyid_num;
}
