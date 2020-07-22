/* SPDX-License-Identifier: GPL-2.0 */
/*
 * filter.h - Driver filter specific header
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

#define FILTER_TAG	"filter: "

#define pr_filter_dbg(fmt, ...) \
	pr_debug(FILTER_TAG fmt, ##__VA_ARGS__)
#define pr_filter_info(fmt, ...) \
	pr_info(FILTER_TAG fmt, ##__VA_ARGS__)
#define pr_filter_crit(fmt, ...) \
	pr_crit(FILTER_TAG fmt, ##__VA_ARGS__)

enum filter_policy {
	BLOCK_ALL = 0, /* Block all drivers */
	ALLOW_ALL = 1  /* Allow all drivers */
};

/**
 * struct drv_filter_node - driver filter node
 *
 * @bus_name		: Name of the bus.
 * @allow_list		: Driver name based allow list.
 * @len:		: Length of the allow list.
 * @default_status	: Default status if allow list is empty.
 */
struct drv_filter_node {
	char *bus_name;
	char **allow_list;
	unsigned int len;
	bool default_status;
	struct list_head list;
};

/* Register platform specific filter allow list */
void register_drv_filter(struct drv_filter_node *node);
#endif
