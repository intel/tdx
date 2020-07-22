/* SPDX-License-Identifier: GPL-2.0 */
/*
 * filter.h - Device filter specific header
 *
 * Copyright (c) 2020 Intel Corporation
 *
 * Author: Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */

#ifndef _DEVICE_FILTER_H_
#define _DEVICE_FILTER_H_

#include <linux/device/bus.h>
#include <linux/device/driver.h>
#include <linux/device.h>

struct device_filter_node {
	bool (*filter)(struct device *dev);
	struct list_head list;
};

void add_device_filter(struct device_filter_node *node);
#endif
