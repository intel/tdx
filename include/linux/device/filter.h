/* SPDX-License-Identifier: GPL-2.0 */
/*
 * filter.h - Driver filter specific header
 *
 * Copyright (c) 2021 Intel Corporation
 *
 */

#ifndef _DEVICE_FILTER_H_
#define _DEVICE_FILTER_H_

#include <linux/device/bus.h>
#include <linux/device/driver.h>
#include <linux/device.h>

/**
 * struct drv_filter_node - driver filter node
 *
 * @bus_name		: Name of the bus.
 * @drv_list		: Driver names for allow or deny list.
 *
 * Passing ALL in bus_name and drv_list will allow or
 * deny all drivers.
 */
struct drv_filter_node {
	const char *bus_name;
	const char *drv_list;
	struct list_head list;
};

/* Register platform specific allow list */
int register_filter_allow_node(struct drv_filter_node *node);
/* Register platform specific deny list */
int register_filter_deny_node(struct drv_filter_node *node);
#endif
