// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) host kernel support
 */

#define	pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <asm/cpufeatures.h>
#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/tdx_host.h>

#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

static u64 keyid_partitioning_info;
static u32 tdx_keyid_start;
static u32 tdx_keyid_num;

static void detect_tdx_keyids_bsp(struct cpuinfo_x86 *c)
{
	u64 keyid_part;

	/* TDX is built on MKTME, which is based on TME */
	if (!boot_cpu_has(X86_FEATURE_TME))
		return;

	if (rdmsrl_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &keyid_part))
		return;

	/*
	 * Intel Trusted Domain CPU Architecture Extension spec:
	 *
	 * IA32_MKTME_KEYID_PART:
	 *
	 *   Bit [31:0]: NUM_MKTME_KIDS.
	 *   Bit [63:32]: NUM_TDX_PRIV_KIDS.  TDX KeyIDs span the range
	 *		  [NUM_MKTME_KIDS+1, NUM_MKTME_KIDS+NUM_TDX_PRIV_KIDS]
	 *
	 * If MSR value is 0, TDX is not enabled by BIOS.
	 */
	if (!keyid_part)
		return;

	tdx_keyid_start = (keyid_part & 0xfffffffful) + 1;
	tdx_keyid_num = (u32)(keyid_part >> 32);
	keyid_partitioning_info = keyid_part;
}

static void detect_tdx_keyids_ap(struct cpuinfo_x86 *c)
{
	u64 keyid_part;

	/*
	 * Don't bother to detect this AP if TDX KeyIDs are
	 * not detected or cleared after earlier detections.
	 */
	if (!keyid_partitioning_info)
		return;
	/*
	 * Check potential BIOS bug that TDX KeyIDs are not
	 * configured consistently among packages by BIOS.
	 */
	rdmsrl(MSR_IA32_MKTME_KEYID_PARTITIONING, keyid_part);

	if (keyid_part != keyid_partitioning_info) {
		pr_err("Inconsistent TDX KeyID configuration among packages by BIOS\n");
		keyid_partitioning_info = 0;
		tdx_keyid_start = 0;
		tdx_keyid_num = 0;
	}
}

void detect_tdx_keyids(struct cpuinfo_x86 *c)
{
	if (c == &boot_cpu_data)
		detect_tdx_keyids_bsp(c);
	else
		detect_tdx_keyids_ap(c);
}
