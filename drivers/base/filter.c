// SPDX-License-Identifier: GPL-2.0
/*
 * filter.c - Add driver filter framework.
 *
 * Implements APIs required for registering platform specific
 * driver filter.
 *
 * Copyright (c) 2020 Intel Corporation
 *
 * Author: Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */
#include <linux/init.h>
#include <linux/device/filter.h>
#include <linux/acpi.h>
#include <linux/protected_guest.h>

#include "base.h"

/* List of filter allow list */
static LIST_HEAD(driver_filter_list);

/* Protects driver_filter_list add/read operations*/
static DEFINE_SPINLOCK(driver_filter_lock);

/*
 * Compares the driver name with given filter node allow list.
 *
 * Return true if driver name matches with allow list.
 */
static bool is_driver_allowed(struct device_driver *drv,
			      struct drv_filter_node *node)
{
	char *n;
	int len;

	if (!drv || !node)
		return false;

	/*
	 * Make sure driver bus name matches with filter node.
	 */
	if (!drv->bus || strcmp(drv->bus->name, node->bus_name))
		return false;

	/* If allow list is not given, return default filter status */
	if (!node->allow_list)
		return node->default_status;

	for (n = node->allow_list; *n; n += len) {
		if (*n == ',')
			n++;
		len = strcspn(n, ",");
		if (!strncmp(drv->name, n, len) && drv->name[len] == 0)
			return true;
	}

	return false;
}

/*
 * is_driver_pg_trusted() - Check whether given driver is trusted
 *			    or not based on platform specific driver
 *			    filter list.
 *
 * This filter is currently only enabled for protected guests.
 *
 */
bool is_driver_pg_trusted(struct device_driver *drv)
{
	bool status = false;
	struct drv_filter_node *node;

	/* If platform does not support driver filter, allow all */
	if (!prot_guest_has(PR_GUEST_DRIVER_FILTER))
		return true;

	spin_lock(&driver_filter_lock);

	/*
	 * Check whether the driver is allowed using platform
	 * registered filter lists.
	 */
	list_for_each_entry(node, &driver_filter_list, list) {
		if (is_driver_allowed(drv, node)) {
			status = true;
			break;
		}
	}

	pr_filter_dbg("bus:%s driver:%s %s\n",
		      drv->bus ? drv->bus->name : "null",
		      drv->name,
		      status ? "allowed" : "blocked");

	spin_unlock(&driver_filter_lock);

	return status;
}

void register_drv_filter(struct drv_filter_node *node)
{
	spin_lock(&driver_filter_lock);
	list_add_tail(&node->list, &driver_filter_list);
	spin_unlock(&driver_filter_lock);
}
