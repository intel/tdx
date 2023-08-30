/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TSM_H
#define __TSM_H

#include <linux/sizes.h>
#include <linux/types.h>
#include <linux/device.h>

#define TSM_INBLOB_MAX 64
#define TSM_OUTBLOB_MAX SZ_32K

/*
 * Privilege level is a nested permission concept to allow confidential
 * guests to partition address space, 4-levels are supported.
 */
#define TSM_PRIVLEVEL_MAX 3

enum tsm_format {
	TSM_FORMAT_DEFAULT,
	TSM_FORMAT_EXTENDED,
};

/**
 * struct tsm_desc - option descriptor for generating tsm report blobs
 * @privlevel: optional privilege level to associate with @outblob
 * @inblob_len: sizeof @inblob
 * @inblob: arbitrary input data
 * @outblob_format: for TSMs with an "extended" format
 */
struct tsm_desc {
	unsigned int privlevel;
	size_t inblob_len;
	u8 inblob[TSM_INBLOB_MAX];
	enum tsm_format outblob_format;
};

/*
 * arch specific ops, only one is expected to be registered at a time
 * i.e. only one of SEV, TDX, COVE, etc.
 */
struct tsm_ops {
	const char *name;
	const int privlevel_floor;
	u8 *(*report_new)(const struct tsm_desc *desc, void *data,
			  size_t *outblob_len);
};

extern const struct config_item_type tsm_report_ext_type;
extern const struct config_item_type tsm_report_default_type;

int register_tsm(const struct tsm_ops *ops, void *priv,
		 const struct config_item_type *type);
int unregister_tsm(const struct tsm_ops *ops);
#endif /* __TSM_H */
