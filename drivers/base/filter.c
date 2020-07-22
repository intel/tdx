// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#include <linux/init.h>
#include <linux/device/filter.h>

#include "base.h"

static LIST_HEAD(device_filter_list);

static DEFINE_SPINLOCK(device_filter_lock);

void add_device_filter(struct device_filter_node *node)
{
	spin_lock(&device_filter_lock);
	list_add_tail(&node->list, &device_filter_list);
	spin_unlock(&device_filter_lock);
}
EXPORT_SYMBOL_GPL(add_device_filter);

bool device_filter_check(struct device *dev)
{
	struct device_filter_node *node;
	bool status = true;

	spin_lock(&device_filter_lock);
	list_for_each_entry(node, &device_filter_list, list)
		if (!node->filter(dev)) {
			status = false;
			break;
		}
	spin_unlock(&device_filter_lock);

	pr_debug("bus:%s device:%s %s\n", dev->bus ? dev->bus->name : "null",
		 dev_name(dev), status ? "allowed" : "not allowed");

	return status;
}
