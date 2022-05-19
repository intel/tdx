// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2022 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) support
 */

#define pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <asm/msr.h>
#include <asm/tdx.h>
#include "tdx.h"

static u32 tdx_keyid_start __ro_after_init;
static u32 nr_tdx_keyids __ro_after_init;

/*
 * tdx_keyid_start and nr_tdx_keyids indicate that TDX is uninitialized.
 * This is used in TDX initialization error paths to take it from
 * initialized -> uninitialized.
 */
static void __init clear_tdx(void)
{
	tdx_keyid_start = nr_tdx_keyids = 0;
}

static int __init record_keyid_partitioning(void)
{
	u32 nr_mktme_keyids;
	int ret;

	/*
	 * IA32_MKTME_KEYID_PARTIONING:
	 *   Bit [31:0]:	Number of MKTME KeyIDs.
	 *   Bit [63:32]:	Number of TDX private KeyIDs.
	 */
	ret = rdmsr_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &nr_mktme_keyids,
			&nr_tdx_keyids);
	if (ret)
		return -ENODEV;

	if (!nr_tdx_keyids)
		return -ENODEV;

	/* TDX KeyIDs start after the last MKTME KeyID. */
	tdx_keyid_start = nr_mktme_keyids + 1;

	pr_info("BIOS enabled: private KeyID range [%u, %u)\n",
			tdx_keyid_start, tdx_keyid_start + nr_tdx_keyids);

	return 0;
}

static int __init tdx_init(void)
{
	int err;

	err = record_keyid_partitioning();
	if (err)
		return err;

	/*
	 * Initializing the TDX module requires one TDX private KeyID.
	 * If there's only one TDX KeyID then after module initialization
	 * KVM won't be able to run any TDX guest, which makes the whole
	 * thing worthless.  Just disable TDX in this case.
	 */
	if (nr_tdx_keyids < 2) {
		pr_info("initialization failed: too few private KeyIDs available (%d).\n",
				nr_tdx_keyids);
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
	return !!nr_tdx_keyids;
}
