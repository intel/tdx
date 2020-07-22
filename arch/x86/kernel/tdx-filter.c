// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <asm/tdx.h>
#include <linux/device/filter.h>
#include <linux/acpi.h>
#include <linux/pci.h>

#define CMDLINE_FILTER_LIMIT 100

static bool pci_bus_filter_cb(struct device *dev);
static bool tdx_device_filter(struct device *dev);

struct filter_node {
	const char *bus;
	bool (*bus_filter_cb)(struct device *dev); /* bus specific callback */
};

struct pci_filter_node {
	unsigned short vendor;
	unsigned short device;
};

static struct device_filter_node dnode = { .filter = tdx_device_filter };
static bool tdx_disable_filter;

static struct filter_node fnodes[] = {
	{
		.bus = "pci",
		.bus_filter_cb = pci_bus_filter_cb
	},
};

/* PCI bus allow-list devices */
static struct pci_filter_node pci_fnodes[] = {
	{ PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1000 }, /* Virtio NET */
	{ PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1001 }, /* Virtio block */
	{ PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1003 }, /* Virtio console */
	{ PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1009 }, /* Virtio FS */

	{ PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1041 }, /* Virtio 1.0 NET */
	{ PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1042 }, /* Virtio 1.0 block */
	{ PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1043 }, /* Virtio 1.0 console */
	{ PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1049 }, /* Virtio 1.0 FS */
};

static struct pci_filter_node cmdline_pci_fnodes[CMDLINE_FILTER_LIMIT];
static int cmdline_pci_len;

/* List of ACPI HID allow-list */
static const char *const acpi_flist[] = {
	"PNP0A06",
	"PNP0A08",
	"QEMU0002",
	"PNP0103",
	"PNP0B00",
	"PNP0303",
	"PNP0F13",
	"PNP0501",
	"device"
};

static char *cmdline_acpi_fnodes[CMDLINE_FILTER_LIMIT];
static int cmdline_acpi_len;

static bool pci_fnode_decode(char *str,  struct pci_filter_node *node)
{
	char *fentry;
	int ret;

	/* get bus name */
	fentry = strsep(&str, ":");
	if (!strlen(fentry))
		goto decode_failed;

	/* get PCI vendor ID */
	fentry = strsep(&str, ":");
	if (!strlen(fentry))
		goto decode_failed;

	ret = kstrtou16(fentry, 16, &node->vendor);
	if (ret < 0)
		goto decode_failed;

	/* get PCI device ID */
	fentry = strsep(&str, ":");
	if (!strlen(fentry))
		goto decode_failed;

	ret = kstrtou16(fentry, 16, &node->device);
	if (ret < 0)
		goto decode_failed;

	return true;

decode_failed:
	node->vendor = 0;
	node->device = 0;
	return false;
}

static bool acpi_fnode_decode(char *str,  char **node)
{
	char *fentry;

	/* get bus name */
	fentry = strsep(&str, ":");
	if (!strlen(fentry))
		goto decode_failed;

	/* get ACPI ID */
	fentry = strsep(&str, ":");
	if (!strlen(fentry))
		goto decode_failed;

	*node = fentry;
	return true;

decode_failed:
	*node = NULL;
	return false;
}

/*
 * Command line parameter setup to update PCI and ACPI
 * device filter allow-list.
 */
static int __init setup_tdx_filter_devids(char *str)
{
	char *p, *fentry;

	/* check for empty string*/
	if (!str || str[0] == '\0')
		return 1;

	p = str;
	while ((fentry = strsep(&p, ","))) {
		/* do nothing for empty entry */
		if (!strlen(fentry))
			continue;

		if (!strncmp(fentry, "pci", 3)) {
			if (cmdline_pci_len >= CMDLINE_FILTER_LIMIT) {
				pr_err("PCI allowlist entries crosses limit\n");
				continue;
			}
			if (!pci_fnode_decode(fentry,
				&cmdline_pci_fnodes[cmdline_pci_len])) {
				pr_err("Invalid PCI IDs: %s\n", fentry);
				continue;
			}
			cmdline_pci_len++;
		} else if (!strncmp(fentry, "acpi", 4)) {
			if (cmdline_acpi_len >= CMDLINE_FILTER_LIMIT) {
				pr_err("ACPI filter entries crosses limit\n");
				continue;
			}
			if (!acpi_fnode_decode(fentry,
				&cmdline_acpi_fnodes[cmdline_acpi_len])) {
				pr_err("Invalid ACPI IDs: %s\n", fentry);
				continue;
			}
			cmdline_acpi_len++;
		}
	}

	return 0;
}
early_param("tdx_filter_devids", setup_tdx_filter_devids);

/* Command line parameter setup to disable TDX device filter. */
static int __init setup_tdx_disable_filter(char *arg)
{
	tdx_disable_filter = 1;
	return 0;
}
early_param("tdx_disable_filter", setup_tdx_disable_filter);

/* get the filter node for the give bus name */
struct filter_node *get_bus_fnode(const char *bus)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fnodes); i++)
		if (!strncmp(fnodes[i].bus, bus, strlen(fnodes[i].bus)))
			return &fnodes[i];

	return NULL;
}

static bool pci_bus_filter_cb(struct device *dev)
{
	int i;
	bool status = false;
	struct pci_dev *pdev =  to_pci_dev(dev);

	for (i = 0; i < ARRAY_SIZE(pci_fnodes); i++) {
		if ((pci_fnodes[i].vendor == pdev->vendor ||
		     pci_fnodes[i].vendor == PCI_ANY_ID) &&
		    (pci_fnodes[i].device == pdev->device ||
		     pci_fnodes[i].device == PCI_ANY_ID)) {
			status = true;
			break;
		}
	}

	for (i = 0; i < cmdline_pci_len; i++) {
		if ((cmdline_pci_fnodes[i].vendor == pdev->vendor ||
		     cmdline_pci_fnodes[i].vendor == PCI_ANY_ID) &&
		    (cmdline_pci_fnodes[i].device == pdev->device ||
		     cmdline_pci_fnodes[i].device == PCI_ANY_ID)) {
			status = true;
			break;
		}
	}

	pr_info("PCI vendor:%x device:%x %s\n", pdev->vendor,
		pdev->device, status ? "allowed" : "blocked");

	return status;
}

static bool acpi_hid_verify(struct device *dev)
{
	int i;
	struct acpi_device *adev = ACPI_COMPANION(dev);

	if (!adev)
		return true;

	for (i = 0; i < ARRAY_SIZE(acpi_flist); i++) {
		if (!strncmp(acpi_flist[i], acpi_device_hid(adev),
			    strlen(acpi_flist[i]))) {
			pr_debug("ACPI HID:%s allowed\n",
				 acpi_device_hid(adev));
			return true;
		}
	}

	for (i = 0; i < cmdline_acpi_len; i++) {
		if (!strncmp(cmdline_acpi_fnodes[i], acpi_device_hid(adev),
			     strlen(cmdline_acpi_fnodes[i]))) {
			pr_debug("ACPI HID:%s allowed\n",
				 acpi_device_hid(adev));
			return true;
		}
	}

	pr_info("ACPI HID:%s blocked\n",  acpi_device_hid(adev));

	return false;
}

static bool tdx_device_filter(struct device *dev)
{
	struct filter_node *fnode;

	/* Allow all non bus devicess */
	if (!dev->bus) {
		pr_debug("standalone device:%s allowed\n", dev_name(dev));
		return true;
	}

	/* If its a valid ACPI device, then check for HID match */
	if (!acpi_hid_verify(dev))
		return false;

	fnode = get_bus_fnode(dev->bus->name);
	if (!fnode) {
		pr_debug("%s bus missing filterlist, device:%s allowed",
			 dev->bus->name, dev_name(dev));
		return true;
	}

	return fnode->bus_filter_cb(dev);
}

void __init tdx_filter_init(void)
{
	/* Consider tdx_disable_filter only in TDX debug mode */
	if (!is_tdx_guest() ||
	    (tdx_debug_enabled() && tdx_disable_filter))
		return;

	add_device_filter(&dnode);

	pr_info("Enabled device filter\n");
}
early_initcall(tdx_filter_init);
