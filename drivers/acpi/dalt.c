// SPDX-License-Identifier: GPL-2.0
/*
 * dalt.c - Device Authorize List Table (DALT)
 *
 * Copyright (C) 2023 Intel Corporation
 */

#define pr_fmt(fmt) "ACPI DALT: " fmt

#include <linux/module.h>
#include <linux/acpi.h>

/**
 * struct da_bus_node - DA table bus device node struct.
 * @type: Type of the bus.
 * @devid: Device id struct.
 */
struct da_bus_node {
	u8 type;
	void *devid;
	struct list_head list;
};

/* List of parsed DA bus device nodes */
static LIST_HEAD(da_bus_list);

static void print_da_bus_list(void)
{
	struct pci_device_id *pci_id;
	char *id;
	struct da_bus_node *node;

	list_for_each_entry(node, &da_bus_list, list) {
		if (node->type == ACPI_DALT_PCI_DEV) {
			pci_id = (struct pci_device_id *)node->devid;
			pr_debug("PCI device vendor:%x device:%x\n",
				 pci_id->vendor, pci_id->device);
		} else if (node->type == ACPI_DALT_ACPI_DEV) {
			id = (char *)node->devid;
			pr_debug("ACPI device %s\n", id);
		} else if (node->type == ACPI_DALT_PLATFORM_DEV) {
			id = (char *)node->devid;
			pr_debug("Platform device %s\n", id);
		}
	}
}

static void free_da_bus_list(void)
{
	struct da_bus_node *node, *tmp_node;

	list_for_each_entry_safe(node, tmp_node, &da_bus_list, list) {
		kfree(node->devid);
		list_del(&node->list);
		kfree(node);
	}
}

static int add_da_bus_node(u8 type, void *devid)
{
	struct da_bus_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->type = type;
	node->devid = devid;

	list_add_tail(&node->list, &da_bus_list);

	return 0;
}

static int parse_dalt_table(struct acpi_table_dalt *dalt)
{
	struct acpi_dalt_device *ddev = (struct acpi_dalt_device *)dalt->devices;
	u32 max_size = dalt->header.length - sizeof(*dalt) - sizeof(*ddev);
	struct pci_device_id *pci_id = NULL;
	unsigned int vendor, device;
	int fields, ret = 0;
	u32 curr_size = 0;
	char *id = NULL;
	void *devid;

	while (curr_size <= max_size ) {
		pr_debug("Device type:%d len:%d name:%s\n", ddev->type,
			 ddev->len, ddev->name);

		id = NULL;
		pci_id = NULL;

		if (ddev->type == ACPI_DALT_PCI_DEV) {
			fields = sscanf(ddev->name, "%x:%x", &vendor, &device);
			if (fields == 2) {
				pci_id = kzalloc(sizeof(*pci_id), GFP_KERNEL);
				if (!pci_id) {
					ret = -ENOMEM;
					goto parse_failed;
				}
				pci_id->vendor = vendor;
				pci_id->device = device;
				pci_id->subdevice = PCI_ANY_ID;
				pci_id->subvendor = PCI_ANY_ID;
				devid = pci_id;
			} else {
				pr_warn("Invalid PCI device %s\n", ddev->name);
			}
		} else if ((ddev->type == ACPI_DALT_ACPI_DEV) ||
			   (ddev->type == ACPI_DALT_PLATFORM_DEV)) {
			id = (char *)kzalloc(ddev->len, GFP_KERNEL);
			if (!id) {
				ret = -ENOMEM;
				goto parse_failed;
			}
			strcpy(id, ddev->name);
			devid = id;
		}

		ret = add_da_bus_node(ddev->type, devid);
		if (ret)
			goto parse_failed;

		curr_size = curr_size + sizeof(*ddev) + ddev->len;
		ddev = (struct acpi_dalt_device *)(dalt->devices + curr_size);
	}

	return 0;

parse_failed:
	kfree(id);
	kfree(pci_id);
	free_da_bus_list();
	return ret;
}

/* Parse DALT ACPI table */
static int __init acpi_dalt_init(void)
{
	struct acpi_table_dalt *dalt;
	acpi_status status;
	int ret;

	status = acpi_get_table(ACPI_SIG_DALT, 0, (struct acpi_table_header **)&dalt);
	if (ACPI_FAILURE(status))
		return -EIO;

	ret = parse_dalt_table(dalt);
	if (ret) {
		pr_err("Parse table failed %d\n", ret);
		return ret;
	}

	print_da_bus_list();

	acpi_put_table((struct acpi_table_header *)dalt);

	pr_info("Parsed successfully\n");

	return 0;
}
arch_initcall(acpi_dalt_init);
