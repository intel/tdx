/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 Intel Corporation
 */

#ifndef _DEVICE_FILTER_H_
#define _DEVICE_FILTER_H_

#include <linux/device/bus.h>
#include <linux/device/driver.h>
#include <linux/device.h>

typedef bool (*device_filter)(struct device *dev);

struct device_filter_node {
	device_filter filter;
	struct list_head list;
};

void add_device_filter(struct device_filter_node *node);
#endif
