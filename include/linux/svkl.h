/* SPDX-License-Identifier: GPL-2.0 */
/*
 * svkl.h - Linux ACPI SVKL Interface
 */

#ifndef ACPI_SVKL_H
#define ACPI_SVKL_H

#include <linux/types.h>
#include <linux/ioctl.h>

struct acpi_svkl_key_info {
	__u16 type;
	__u16 format;
	__u32 size;
} __packed;

#define ACPI_SVKL_GET_KEY_COUNT	_IOW('E', 0x01, __u32)
#define ACPI_SVKL_GET_KEY_INFO	_IOWR('E', 0x02, struct acpi_svkl_key_info)
#define ACPI_SVKL_GET_KEY_DATA	_IOR('E', 0x03, __u64)
#define ACPI_SVKL_CLEAR_KEY	_IOR('E', 0x04, __u32)

#endif
