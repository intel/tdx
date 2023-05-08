// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/cc_platform.h>
#include <linux/export.h>
#include <uapi/linux/virtio_ids.h>

#include <asm/tdx.h>
#include <asm/cmdline.h>

#define CMDLINE_MAX_NODES		100
#define CMDLINE_MAX_LEN			1000

/*
 * struct authorize_node - Device authorization node
 *
 * @bus: Name of the bus
 * @dev_list: device allow list per bus device type (eg:
 *            struct pci_device_id). If NULL, allow all
 *            devices.
 */
struct authorize_node {
	const char *bus;
	void *dev_list;
};

/*
 * Memory to store data passed via command line options
 * authorize_allow_devs.
 */
static char cmd_authorized_devices[CMDLINE_MAX_LEN];
static struct authorize_node cmd_allowed_nodes[CMDLINE_MAX_NODES];
static struct pci_device_id cmd_pci_ids[CMDLINE_MAX_NODES];
static int cmd_pci_nodes_len;
static int cmd_allowed_nodes_len;

/* Set true if authorize_allow_devs is used */
static bool filter_overridden;

/*
 * Allow list for PCI bus
 *
 * NOTE: Device ID is duplicated here. But for small list
 * of devices, it is easier to maintain the duplicated list
 * here verses exporting the device ID table from the driver
 * and use it.
 */
struct pci_device_id pci_allow_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_NET) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_BLOCK) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_CONSOLE) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_9P) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_NET) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_BLOCK) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_CONSOLE) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_9P) },
	{ 0, },
};

static struct authorize_node allow_list[] = {
	/* Allow devices in pci_allow_list in "pci" bus */
	{ "pci", pci_allow_ids },
};

static bool authorized_node_match(struct device *dev,
				  struct authorize_node *node)
{
	/* If bus matches "ALL" and dev_list is NULL, return true */
	if (!strcmp(node->bus, "ALL") && !node->dev_list)
		return true;

	/*
	 * Since next step involves bus specific comparison, make
	 * sure the bus name matches with filter node. If not
	 * return false.
	 */
	if (strcmp(node->bus, dev->bus->name))
		return false;

	/* If dev_list is NULL, allow all and return true */
	if (!node->dev_list)
		return true;

	/*
	 * Do bus specific device ID match. Currently only PCI
	 * bus is supported.
	 */
	if (dev_is_pci(dev)) {
		if (pci_match_id((struct pci_device_id *)node->dev_list,
				 to_pci_dev(dev)))
			return true;
	}

	return false;
}

static struct pci_device_id *parse_pci_id(char *ids)
{
	unsigned int subdevice = PCI_ANY_ID, class = 0, class_mask = 0;
	unsigned int vendor, device, subvendor = PCI_ANY_ID;
	char *p, *id;
	int fields;

	p = ids;
	while ((id = strsep(&p, ","))) {
		if (!strlen(id))
			continue;
		fields = sscanf(id, "%x:%x:%x:%x:%x:%x", &vendor, &device,
				&subvendor, &subdevice, &class, &class_mask);
		if (fields < 2)
			continue;
		cmd_pci_ids[cmd_pci_nodes_len].vendor = vendor;
		cmd_pci_ids[cmd_pci_nodes_len++].device = device;
	}

	return cmd_pci_ids;
}

static void *parse_device_id(const char *bus, char *ids)
{
	if (!strcmp(ids, "ALL"))
		return NULL;

	if (!strcmp(bus, "pci"))
		return parse_pci_id(ids);
	else
		return ids;
}

static __init void add_authorize_nodes(char *p)
{
	struct authorize_node *n;
	int j = 0;
	char *k;

	while ((k = strsep(&p, ";")) != NULL) {
		if (j >= CMDLINE_MAX_NODES) {
			pr_err("Authorize nodes exceeds MAX allowed\n");
			break;
		}
		n = &cmd_allowed_nodes[j++];
		n->bus = strsep(&k, ":");
		n->dev_list = parse_device_id(n->bus, k);
	}

	if (j)
		cmd_allowed_nodes_len = j;
}

static __init int allowed_cmdline_setup(char *buf)
{
	if (strlen(buf) >= CMDLINE_MAX_LEN)
		pr_warn("Authorized allowed devices list exceed %d chars\n",
			CMDLINE_MAX_LEN);

	strscpy(cmd_authorized_devices, buf, CMDLINE_MAX_LEN);

	add_authorize_nodes(cmd_authorized_devices);

	filter_overridden = true;

	return 0;
}
__setup("authorize_allow_devs=", allowed_cmdline_setup);

bool dev_authorized_init(void)
{
	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return false;

	return true;
}

bool arch_dev_authorized(struct device *dev)
{
	int i;

	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return true;

	if (!dev->bus)
		return dev->authorized;

	/* Lookup arch allow list */
	for (i = 0;  i < ARRAY_SIZE(allow_list); i++) {
		if (authorized_node_match(dev, &allow_list[i]))
			return true;
	}

	/* Lookup command line allow list */
	for (i = 0; i < cmd_allowed_nodes_len; i++) {
		if (authorized_node_match(dev, &cmd_allowed_nodes[i]))
			return true;
	}

	return false;
}

void __init tdx_filter_init(void)
{
	if (!cc_platform_has(CC_ATTR_GUEST_DEVICE_FILTER))
		return;

	if (filter_overridden) {
		add_taint(TAINT_CONF_NO_LOCKDOWN, LOCKDEP_STILL_OK);
		pr_debug("Device filter is overridden\n");
	}

	pr_info("Enabled TDX guest device filter\n");
}
