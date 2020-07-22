// SPDX-License-Identifier: GPL-2.0
/*
 * filter.c - Add driver filter framework.
 *
 * Implements APIs required for registering platform specific
 * driver filter.
 *
 * Copyright (c) 2021 Intel Corporation
 */

#define pr_fmt(fmt) "filter: " fmt

#include <linux/init.h>
#include <linux/device/filter.h>
#include <linux/acpi.h>
#include <linux/protected_guest.h>

#include "base.h"

#define MAX_FILTER_NODES 10
#define MAX_CMDLINE_LEN  500

/* Buffer used by command line parser */
static char allowed_drivers[MAX_CMDLINE_LEN];
static char denied_drivers[MAX_CMDLINE_LEN];

/* List of filter nodes for command line parser */
static struct drv_filter_node allowed_nodes[MAX_FILTER_NODES];
static struct drv_filter_node denied_nodes[MAX_FILTER_NODES];

/* Driver allow list */
static LIST_HEAD(driver_allow_list);
/* Driver deny list */
static LIST_HEAD(driver_deny_list);

/* Protects driver_filter_list add/read operations*/
static DEFINE_SPINLOCK(driver_filter_lock);

/*
 * Compares the driver name with given filter node.
 *
 * Return true if driver name matches with filter node.
 */
static bool match_driver(struct device_driver *drv,
			 struct drv_filter_node *node)
{
	const char *n;
	int len;

	/* Make sure input entries are valid */
	if (!drv || !node || !drv->bus)
		return false;

	/* If bus_name and drv_list matches "ALL", return true */
	if (!strcmp(node->bus_name, "ALL") && !strcmp(node->drv_list, "ALL"))
		return true;

	/*
	 * Since next step involves bus specific comparison, make
	 * sure the bus name matches with filter node. If not
	 * return false.
	 */
	if (strcmp(node->bus_name, drv->bus->name))
		return false;

	/* If allow list is "ALL", allow all */
	if (!strcmp(node->drv_list, "ALL"))
		return true;

	for (n = node->drv_list; *n; n += len) {
		if (*n == ',')
			n++;
		len = strcspn(n, ",");
		if (!strncmp(drv->name, n, len) && drv->name[len] == 0)
			return true;
	}

	return false;
}

/*
 * driver_allowed() - Check whether given driver is allowed or not
 *		      based on platform specific driver filter list.
 */
bool driver_allowed(struct device_driver *drv)
{
	bool status = true;
	struct drv_filter_node *node;

	spin_lock(&driver_filter_lock);

	/*
	 * Check whether the driver is allowed using platform
	 * registered allow list.
	 */
	list_for_each_entry(node, &driver_allow_list, list) {
		if (match_driver(drv, node)) {
			status = true;
			goto done;
		}
	}

	/*
	 * Check whether the driver is denied using platform
	 * registered deny list.
	 */
	list_for_each_entry(node, &driver_deny_list, list) {
		if (match_driver(drv, node)) {
			status = false;
			break;
		}
	}

done:
	pr_debug("bus:%s driver:%s %s\n", drv->bus ? drv->bus->name : "null",
		 drv->name, status ? "allowed" : "denied");

	spin_unlock(&driver_filter_lock);

	return status;
}

bool driver_filter_enabled(void)
{
	return !list_empty(&driver_allow_list) ||
		!list_empty(&driver_deny_list);
}

/*
 * Helper function for filter node validity checks and
 * adding filter node to allow or deny list.
 */
static int add_node_to_list(struct drv_filter_node *node,
			    struct list_head *flist)
{
	/* If filter node is NULL, return error */
	if (!node)
		return -EINVAL;

	/* Make sure node input is valid */
	if (!node->bus_name || !node->drv_list)
		return -EINVAL;

	spin_lock(&driver_filter_lock);

	list_add_tail(&node->list, flist);

	spin_unlock(&driver_filter_lock);

	return 0;
}

int register_filter_allow_node(struct drv_filter_node *node)
{
	return add_node_to_list(node, &driver_allow_list);
}

int register_filter_deny_node(struct drv_filter_node *node)
{
	return add_node_to_list(node, &driver_deny_list);
}

static __init void add_custom_driver_filter(char *p, bool allow)
{
	struct drv_filter_node *n;
	int j = 0;
	char *k;

	while ((k = strsep(&p, ";")) != NULL) {
		if (j >= MAX_FILTER_NODES) {
			pr_err("Driver filter nodes exceed MAX_FILTER_NODES\n");
			break;
		}

		if (allow)
			n = &allowed_nodes[j++];
		else
			n = &denied_nodes[j++];

		n->bus_name = strsep(&k, ":");

		n->drv_list = p;

		if (allow)
			register_filter_allow_node(n);
		else
			register_filter_deny_node(n);
	}
}

/* Command line option to update driver allow list */
static int __init setup_allowed_drivers(char *buf)
{
	if (strlen(buf) >= MAX_CMDLINE_LEN)
		pr_warn("Allowed list exceeds %d chars\n", MAX_CMDLINE_LEN);

	strscpy(allowed_drivers, buf, MAX_CMDLINE_LEN);

	add_custom_driver_filter(allowed_drivers, 1);

	return 0;
}
__setup("filter_allow_drivers=", setup_allowed_drivers);

/* Command line option to update driver deny list */
static int __init setup_denied_drivers(char *buf)
{
	if (strlen(buf) >= MAX_CMDLINE_LEN)
		pr_warn("Allowed list exceeds %d chars\n", MAX_CMDLINE_LEN);

	strscpy(denied_drivers, buf, MAX_CMDLINE_LEN);

	add_custom_driver_filter(denied_drivers, 0);

	return 0;
}
__setup("filter_deny_drivers=", setup_denied_drivers);
