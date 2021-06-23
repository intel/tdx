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

#define ADD_FILTER_NODE(bname, dlist)			\
{							\
	.bus_name = bname,				\
	.drv_list = dlist,				\
}

#define FILTER_CMDLINE_LEN 500

static bool tdg_filter_status = 1;
static char acpi_allowed[FILTER_CMDLINE_LEN];

/* Allow list for Virtio bus */
static const char virtio_allow_list[] = "virtio_net,virtio_console,virtio_blk,"
					"virtio_rproc_serial,9pnet_virtio";

/* Allow list for PCI bus */
static const char pci_allow_list[] = "virtio-pci";

static struct drv_filter_node allow_list[] = {
	/* Enable all drivers in "cpu" bus */
	ADD_FILTER_NODE("cpu", "ALL"),
	/* Allow drivers in pci_allow_list in "pci" bus */
	ADD_FILTER_NODE("pci", pci_allow_list),
	/* Allow drivers in virtio_allow_list in "virtio" bus */
	ADD_FILTER_NODE("virtio", virtio_allow_list),
};

/* Block all drivers by default */
static struct drv_filter_node deny_list[] = {
	ADD_FILTER_NODE("ALL", "ALL")
};

static __init bool is_filter_overridden(void)
{
	char driver_list[FILTER_CMDLINE_LEN];

	if (cmdline_find_option(boot_command_line, "filter_allow_drivers",
				driver_list, sizeof(driver_list)) != -1)
		return true;

	if (cmdline_find_option(boot_command_line, "filter_deny_drivers",
				driver_list, sizeof(driver_list)) != -1)
		return true;

	return false;
}

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
	char *allowed;
	char a_allowed[60];

	if (!prot_guest_has(PATTR_GUEST_DRIVER_FILTER))
		return;

	if (cmdline_find_option_bool(boot_command_line, "tdx_disable_filter"))
		tdg_filter_status = 0;

	if (!tdg_filter_enabled()) {
		pr_info("Disabled TDX guest filter support\n");
		ioremap_force_shared = true;
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		return;
	}

	pci_disable_early();

	if (is_filter_overridden()) {
		/*
		 * Since the default allow/deny list is overridden
		 * to make sure new drivers use ioremap_shared,
		 * force it on all drivers.
		 */
		ioremap_force_shared = true;
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
	}

	for (i = 0; i < ARRAY_SIZE(allow_list); i++) {
		if (register_filter_allow_node(&allow_list[i]))
			pr_err("Filter allow list registration failed\n");
	}

	for (i = 0; i < ARRAY_SIZE(deny_list); i++) {
		if (register_filter_deny_node(&deny_list[i]))
			pr_err("Filter deny list registration failed\n");
	}

	allowed = "RDSP,XSDT,FACP,DSDT,FACS,APIC,SVKL";
	if (cmdline_find_option(boot_command_line, "tdx_allow_acpi",
				a_allowed, sizeof(a_allowed)) >= 0) {
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		snprintf(acpi_allowed, sizeof(acpi_allowed), "%s,%s", allowed,
			 a_allowed);
		allowed = acpi_allowed;
		/*
		 * Similar to previous overrides, ACPI table override also
		 * requires ioremap as shared. So force enable it.
		 */
		ioremap_force_shared = true;
	}
	acpi_tbl_allow_setup(allowed);

	pr_info("Enabled TDX guest device filter\n");
}
