// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/device/filter.h>
#include <linux/protected_guest.h>

#include <asm/tdx.h>
#include <asm/cmdline.h>

static bool tdg_filter_status = 1;

#define ADD_FILTER_NODE(bname, alist, st)		\
{							\
	.bus_name = #bname,				\
	.allow_list = alist,				\
	.len = ARRAY_SIZE(alist),			\
	.default_status = st				\
}

#define ADD_SIMPLE_FILTER_NODE(bname, st)		\
{							\
	.bus_name = #bname,				\
	.default_status = st				\
}

/* Allow list for Virtio bus */
static char *virtio_allow_list[] = {
	"virtio_net",
	"virtio_console",
	"virtio_blk",
	"virtio_rproc_serial",
};

/* Allow list for PCI bus */
static char *pci_allow_list[] = {
	"virtio-pci",
};

static struct drv_filter_node filter_list[] = {
	/* Enable all devices in "cpu" bus */
	ADD_SIMPLE_FILTER_NODE(cpu, true),
	/* Allow drivers in pci_allow_list in "pci" bus */
	ADD_FILTER_NODE(pci, pci_allow_list, false),
	/* Allow drivers in virtio_allow_list in "virtio" bus */
	ADD_FILTER_NODE(virtio, virtio_allow_list, false),
};

bool tdg_filter_enabled(void)
{
	return tdg_filter_status;
}

bool tdg_allowed_port(short int port)
{
	if (tdg_debug_enabled() && tdg_filter_enabled())
		return true;

	switch (port) {
	/* MC146818 RTC */
	case 0x70 ... 0x71:
	/* PCI */
	case 0xcf8 ... 0xcff:
		return true;
	/* ACPI ports list:
	 * 0600-0603 : ACPI PM1a_EVT_BLK
	 * 0604-0605 : ACPI PM1a_CNT_BLK
	 * 0608-060b : ACPI PM_TMR
	 * 0620-062f : ACPI GPE0_BLK
	 */
	case 0x600 ... 0x62f:
		return true;
	/* COM1 */
	case 0x3f8:
	case 0x3f9:
	case 0x3fa:
	case 0x3fd:
		return tdg_debug_enabled();
	default:
		return false;
	}
}

void __init tdg_filter_init(void)
{
	int i;

	if (!prot_guest_has(PR_GUEST_TDX))
		return;

	if (cmdline_find_option_bool(boot_command_line, "tdx_disable_filter"))
		tdg_filter_status = 0;

	if (!tdg_filter_enabled()) {
		pr_info("Disabled TDX guest filter support\n");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(filter_list); i++)
		register_drv_filter(&filter_list[i]);

	pr_info("Enabled TDX guest device filter\n");
}
