// SPDX-License-Identifier: GPL-2.0
/*
 * Device ID Filter Table (DIFT)
 *
 * Copyright (C) 2023 Intel Corporation
 */

#define pr_fmt(fmt) "ACPI DIFT: " fmt

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/pci-acpi.h>
#include <linux/list.h>

static LIST_HEAD(dift_pci_ids);

/* Whether a DIFT table has been successfully processed */
static bool dift_setup_done;

int acpi_pci_device_filter(struct pci_dev *dev)
{
	struct dift_pci_id *id;

	if (!dift_setup_done)
		return 0;

	list_for_each_entry(id, &dift_pci_ids, node) {
		if (pci_acpi_dift_match(id, dev))
			return 0;
	}

	return -EPERM;
}

static u32 __init dift_to_pci(u16 val)
{
	return val == (u16)PCI_ANY_ID ? PCI_ANY_ID : val;
}

static int __init parse_dift_pci_id(union acpi_subtable_headers *header, const unsigned long end)
{
	struct acpi_dift_device *d = (struct acpi_dift_device *)header;
	struct dift_pci_id *id;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id)
		return -ENOMEM;

	id->domain		= d->segment_group;
	id->bus			= d->bus;
	id->slot		= d->slot;
	id->function		= d->function;
	id->id.vendor		= dift_to_pci(d->vendor);
	id->id.device		= dift_to_pci(d->device);
	id->id.subvendor	= dift_to_pci(d->subvendor);
	id->id.subdevice	= dift_to_pci(d->subdevice);
	id->id.class		= d->class_code;
	id->id.class_mask	= d->class_mask;

	list_add(&id->node, &dift_pci_ids);

	pr_debug("PCI device %04x:%02x:%02x.%x %04x:%04x subsys %04x:%04x class %x mask %x\n",
		 id->domain, id->bus, id->slot, id->function, id->id.vendor,
		 id->id.device, id->id.subvendor, id->id.subdevice,
		 id->id.class, id->id.class_mask);

	return 0;
}

static void __init free_dift_pci_ids(void)
{
	struct dift_pci_id *id, *next;

	list_for_each_entry_safe(id, next, &dift_pci_ids, node) {
		list_del(&id->node);
		kfree(id);
	}
}

void __init acpi_dift_init(void)
{
	int cnt = acpi_table_parse_entries(ACPI_SIG_DIFT,
					   sizeof(struct acpi_table_dift),
					   ACPI_DIFT_TYPE_PCI,
					   parse_dift_pci_id, 0);

	if (cnt < 0) {
		free_dift_pci_ids();
		return;
	}

	dift_setup_done = true;

	pr_info("Detected table with %u device IDs\n", cnt);
}
