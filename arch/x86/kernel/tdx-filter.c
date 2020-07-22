// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <asm/tdx.h>
#include <linux/device/filter.h>
#include <linux/acpi.h>
#include <linux/pci.h>

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
	if (!is_tdx_guest())
		return;

	add_device_filter(&dnode);

	pr_info("Enabled device filter\n");
}
early_initcall(tdx_filter_init);
