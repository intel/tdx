// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2022 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) support
 */

#define pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/cpumask.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/cpufeature.h>
#include <asm/cpufeatures.h>
#include <asm/tdx.h>

/* Support Intel Secure Arbitration Mode Range Registers (SEAMRR) */
#define MTRR_CAP_SEAMRR			BIT(15)

/* Core-scope Intel SEAMRR base and mask registers. */
#define MSR_IA32_SEAMRR_PHYS_BASE	0x00001400
#define MSR_IA32_SEAMRR_PHYS_MASK	0x00001401

#define SEAMRR_PHYS_BASE_CONFIGURED	BIT_ULL(3)
#define SEAMRR_PHYS_MASK_ENABLED	BIT_ULL(11)
#define SEAMRR_PHYS_MASK_LOCKED		BIT_ULL(10)

#define SEAMRR_ENABLED_BITS	\
	(SEAMRR_PHYS_MASK_ENABLED | SEAMRR_PHYS_MASK_LOCKED)

/*
 * Intel Trusted Domain CPU Architecture Extension spec:
 *
 * IA32_MKTME_KEYID_PARTIONING:
 *
 *   Bit [31:0]: number of MKTME KeyIDs.
 *   Bit [63:32]: number of TDX private KeyIDs.
 *
 * TDX private KeyIDs start after the last MKTME KeyID.
 */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

#define TDX_KEYID_START(_keyid_part)	\
		((u32)(((_keyid_part) & 0xffffffffull) + 1))
#define TDX_KEYID_NUM(_keyid_part)	((u32)((_keyid_part) >> 32))

/* BIOS must configure SEAMRR registers for all cores consistently */
static u64 seamrr_base, seamrr_mask;

static u32 tdx_keyid_start;
static u32 tdx_keyid_num;

static bool __seamrr_enabled(void)
{
	return (seamrr_mask & SEAMRR_ENABLED_BITS) == SEAMRR_ENABLED_BITS;
}

static void detect_seam_bsp(struct cpuinfo_x86 *c)
{
	u64 mtrrcap, base, mask;

	/* SEAMRR is reported via MTRRcap */
	if (!boot_cpu_has(X86_FEATURE_MTRR))
		return;

	rdmsrl(MSR_MTRRcap, mtrrcap);
	if (!(mtrrcap & MTRR_CAP_SEAMRR))
		return;

	rdmsrl(MSR_IA32_SEAMRR_PHYS_BASE, base);
	if (!(base & SEAMRR_PHYS_BASE_CONFIGURED)) {
		pr_info("SEAMRR base is not configured by BIOS\n");
		return;
	}

	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, mask);
	if ((mask & SEAMRR_ENABLED_BITS) != SEAMRR_ENABLED_BITS) {
		pr_info("SEAMRR is not enabled by BIOS\n");
		return;
	}

	seamrr_base = base;
	seamrr_mask = mask;
}

static void detect_seam_ap(struct cpuinfo_x86 *c)
{
	u64 base, mask;

	/*
	 * Don't bother to detect this AP if SEAMRR is not
	 * enabled after earlier detections.
	 */
	if (!__seamrr_enabled())
		return;

	rdmsrl(MSR_IA32_SEAMRR_PHYS_BASE, base);
	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, mask);

	if (base == seamrr_base && mask == seamrr_mask)
		return;

	pr_err("Inconsistent SEAMRR configuration by BIOS\n");
	/* Mark SEAMRR as disabled. */
	seamrr_base = 0;
	seamrr_mask = 0;
}

static void detect_seam(struct cpuinfo_x86 *c)
{
	if (c == &boot_cpu_data)
		detect_seam_bsp(c);
	else
		detect_seam_ap(c);
}

static void detect_tdx_keyids_bsp(struct cpuinfo_x86 *c)
{
	u64 keyid_part;

	/* TDX is built on MKTME, which is based on TME */
	if (!boot_cpu_has(X86_FEATURE_TME))
		return;

	if (rdmsrl_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &keyid_part))
		return;

	/* If MSR value is 0, TDX is not enabled by BIOS. */
	if (!keyid_part)
		return;

	tdx_keyid_num = TDX_KEYID_NUM(keyid_part);
	if (!tdx_keyid_num)
		return;

	tdx_keyid_start = TDX_KEYID_START(keyid_part);
}

static void detect_tdx_keyids_ap(struct cpuinfo_x86 *c)
{
	u64 keyid_part;

	/*
	 * Don't bother to detect this AP if TDX KeyIDs are
	 * not detected or cleared after earlier detections.
	 */
	if (!tdx_keyid_num)
		return;

	rdmsrl(MSR_IA32_MKTME_KEYID_PARTITIONING, keyid_part);

	if ((tdx_keyid_start == TDX_KEYID_START(keyid_part)) &&
			(tdx_keyid_num == TDX_KEYID_NUM(keyid_part)))
		return;

	pr_err("Inconsistent TDX KeyID configuration among packages by BIOS\n");
	tdx_keyid_start = 0;
	tdx_keyid_num = 0;
}

static void detect_tdx_keyids(struct cpuinfo_x86 *c)
{
	if (c == &boot_cpu_data)
		detect_tdx_keyids_bsp(c);
	else
		detect_tdx_keyids_ap(c);
}

void tdx_detect_cpu(struct cpuinfo_x86 *c)
{
	detect_seam(c);
	detect_tdx_keyids(c);
}
