// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/protected_guest.h>

#include <asm/tdx.h>
#include <asm/cmdline.h>

#define CMDLINE_MAX_NODES		100
#define CMDLINE_MAX_LEN			1000

#define ADD_FILTER_NODE(bname, dlist)			\
{							\
	.bus = bname,					\
	.dev_str = dlist,				\
}

struct authorize_node {
	const char *bus;
	const char *dev_str;
};

/*
 * Memory to store data passed via command line options
 * authorize_allow_devs/authorize_deny_devs.
 */
static char cmd_authorized_devices[CMDLINE_MAX_LEN];
static char cmd_denied_devices[CMDLINE_MAX_LEN];
static struct authorize_node cmd_allowed_nodes[CMDLINE_MAX_NODES];
static struct authorize_node cmd_denied_nodes[CMDLINE_MAX_NODES];
static int cmd_allowed_nodes_len;
static int cmd_denied_nodes_len;
static bool tdx_filter_status = 1;

/* Set true if authorize_allow_devs/authorize_deny_devs is used */
static bool filter_overridden;

/* Allow list for PCI bus */
static const char pci_allow_list[] =
"0x1af4:0x1000," /* Virtio NET */
"0x1af4:0x1001," /* Virtio block */
"0x1af4:0x1003," /* Virtio console */
"0x1af4:0x1009," /* Virtio FS */
"0x1af4:0x1041," /* Virtio 1.0 NET */
"0x1af4:0x1042," /* Virtio 1.0 block */
"0x1af4:0x1043," /* Virtio 1.0 console */
"0x1af4:0x1049"; /* Virtio 1.0 FS */

static struct authorize_node allow_list[] = {
	/* Enable all devices in "virtio" bus */
	ADD_FILTER_NODE("virtio", "ALL"),
	/* Allow devices in pci_allow_list in "pci" bus */
	ADD_FILTER_NODE("pci", pci_allow_list),
};

/* Block all devices by default */
static struct authorize_node deny_list[] = {
	ADD_FILTER_NODE("ALL", "ALL")
};

static bool authorized_node_match(struct authorize_node *node,
				  const char *bus_name, const char *dev_str)
{
	const char *n;
	int len;

	/* If bus and dev_str matches "ALL", return true */
	if (!strcmp(node->bus, "ALL") && !strcmp(node->dev_str, "ALL"))
		return true;

	/*
	 * Since next step involves bus specific comparison, make
	 * sure the bus name matches with filter node. If not
	 * return false.
	 */
	if (strcmp(node->bus, bus_name))
		return false;

	/* If device name is "ALL", allow all */
	if (!strcmp(node->dev_str, "ALL"))
		return true;

	for (n = node->dev_str; *n; n += len) {
		if (*n == ',')
			n++;
		len = strcspn(n, ",");
		if (!strncmp(dev_str, n, len))
			return true;
	}

	return false;
}

static __init void add_authorize_nodes(char *p, bool allow)
{
	struct authorize_node *n;
	int j = 0;
	char *k;

	while ((k = strsep(&p, ";")) != NULL) {
		if (j >= CMDLINE_MAX_NODES) {
			pr_err("Authorize nodes exceeds MAX allowed\n");
			break;
		}
		if (allow)
			n = &cmd_allowed_nodes[j++];
		else
			n = &cmd_denied_nodes[j++];

		n->bus = strsep(&k, ":");
		n->dev_str = k;
	}

	if (j) {
		if (allow)
			cmd_allowed_nodes_len = j;
		else
			cmd_denied_nodes_len = j;
	}
}

static __init int allowed_cmdline_setup(char *buf)
{
	if (strlen(buf) >= CMDLINE_MAX_LEN)
		pr_warn("Authorized allowed devices list exceed %d chars\n",
			CMDLINE_MAX_LEN);

	strscpy(cmd_authorized_devices, buf, CMDLINE_MAX_LEN);

	add_authorize_nodes(cmd_authorized_devices, 1);

	filter_overridden = true;

	return 0;
}
__setup("authorize_allow_devs=", allowed_cmdline_setup);

static __init int denied_cmdline_setup(char *buf)
{
	if (strlen(buf) >= CMDLINE_MAX_LEN)
		pr_warn("Authorized denied devices list exceed %d chars\n",
			CMDLINE_MAX_LEN);

	strscpy(cmd_denied_devices, buf, CMDLINE_MAX_LEN);

	add_authorize_nodes(cmd_denied_devices, 0);

	filter_overridden = true;

	return 0;
}
__setup("authorize_deny_devs=", denied_cmdline_setup);

bool tdx_guest_authorized(struct device *dev, char *dev_str)
{
	int i;

	if (!dev->bus)
		return dev->authorized;

	/* Lookup arch allow list */
	for (i = 0;  i < ARRAY_SIZE(allow_list); i++) {
		if (authorized_node_match(&allow_list[i], dev->bus->name,
					  dev_str))
			return true;
	}

	/* Lookup command line allow list */
	for (i = 0; i < cmd_allowed_nodes_len; i++) {
		if (authorized_node_match(&cmd_allowed_nodes[i], dev->bus->name,
					  dev_str))
			return true;
	}

	/* Lookup arch deny list */
	for (i = 0;  i < ARRAY_SIZE(deny_list); i++) {
		if (authorized_node_match(&deny_list[i], dev->bus->name,
					  dev_str))
			return false;
	}

	/* Lookup command line deny list */
	for (i = 0; i < cmd_denied_nodes_len; i++) {
		if (authorized_node_match(&cmd_denied_nodes[i], dev->bus->name,
					  dev_str))
			return false;
	}

	return dev->authorized;
}

bool tdx_filter_enabled(void)
{
	return tdx_filter_status;
}

bool tdx_allowed_port(short int port)
{
	if (tdx_debug_enabled() && tdx_filter_enabled())
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
		return tdx_debug_enabled();
	default:
		return false;
	}
}

void __init tdg_filter_init(void)
{
	if (!prot_guest_has(PATTR_GUEST_DEVICE_FILTER))
		return;

	if (cmdline_find_option_bool(boot_command_line, "tdx_disable_filter"))
		tdx_filter_status = 0;

	if (!tdx_filter_enabled()) {
		pr_info("Disabled TDX guest filter support\n");
		ioremap_force_shared = true;
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		return;
	}

	/* Set default authorization as disabled */
	dev_default_authorization = false;

	pci_disable_early();

	if (filter_overridden) {
		/*
		 * Since the default allow/deny list is overridden
		 * to make sure new drivers use ioremap_shared,
		 * force it on all drivers.
		 */
		ioremap_force_shared = true;
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
	}

	acpi_tbl_allow_setup("XSDT,FACP,DSDT,FACS,APIC");

	pr_info("Enabled TDX guest device filter\n");
}
