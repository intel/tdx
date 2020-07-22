// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <linux/cpu.h>
#include <linux/cc_platform.h>

#include <asm/coco.h>
#include <asm/tdx.h>
#include <asm/cmdline.h>

bool tdx_allowed_port(short int port)
{
	if (tdx_debug_enabled() && !cc_filter_enabled())
		return true;

	switch (port) {
	/* MC146818 RTC */
	case 0x70 ... 0x71:
	/* i8237A DMA controller */
	case 0x80 ... 0x8f:
	/* PCI */
	case 0xcd8 ... 0xcdf:
	case 0xcf8 ... 0xcff:
		return true;
	/* PCIE hotplug device state for Q35 machine type */
	case 0xcc4:
	case 0xcc8:
		return true;
	/* ACPI ports list:
	 * 0600-0603 : ACPI PM1a_EVT_BLK
	 * 0604-0605 : ACPI PM1a_CNT_BLK
	 * 0608-060b : ACPI PM_TMR
	 * 0620-062f : ACPI GPE0_BLK
	 */
	case 0x600 ... 0x62f:
		return true;
	/* serial */
	case 0x2e8 ... 0x2ef:
	case 0x2f8 ... 0x2ff:
	case 0x3e8 ... 0x3ef:
	case 0x3f8 ... 0x3ff:
		return tdx_debug_enabled();
	default:
		return false;
	}
}

void __init tdx_filter_init(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return;

	if (!cc_platform_has(CC_ATTR_GUEST_DEVICE_FILTER))
		return;

	if (cmdline_find_option_bool(boot_command_line, "noccfilter"))
		cc_set_filter_status(false);

	if (!cc_filter_enabled()) {
		pr_info("Disabled TDX guest filter support\n");
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		return;
	}

	pr_info("Enabled TDX guest device filter\n");
}
