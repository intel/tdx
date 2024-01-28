/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TSM_H
#define __TSM_H

#include <crypto/hash_info.h>
#include <linux/sizes.h>
#include <linux/types.h>

#define TSM_INBLOB_MAX 64
#define TSM_OUTBLOB_MAX SZ_32K
#define TSM_DIGEST_MAX SHA512_DIGEST_SIZE

/*
 * Privilege level is a nested permission concept to allow confidential
 * guests to partition address space, 4-levels are supported.
 */
#define TSM_PRIVLEVEL_MAX 3

/**
 * struct tsm_desc - option descriptor for generating tsm report blobs
 * @privlevel: optional privilege level to associate with @outblob
 * @inblob_len: sizeof @inblob
 * @inblob: arbitrary input data
 */
struct tsm_desc {
	unsigned int privlevel;
	size_t inblob_len;
	u8 inblob[TSM_INBLOB_MAX];
};

/**
 * struct tsm_report - track state of report generation relative to options
 * @desc: input parameters to @report_new()
 * @outblob_len: sizeof(@outblob)
 * @outblob: generated evidence to provider to the attestation agent
 * @auxblob_len: sizeof(@auxblob)
 * @auxblob: (optional) auxiliary data to the report (e.g. certificate data)
 */
struct tsm_report {
	struct tsm_desc desc;
	size_t outblob_len;
	u8 *outblob;
	size_t auxblob_len;
	u8 *auxblob;
};

#define TSM_MAX_RTMR 32

/**
 * struct tsm_rtmr_desc - Describes a TSM Runtime Measurement Register (RTMR).
 * @hash_alg: The hash algorithm used to extend this runtime measurement
 *            register.
 * @tcg_pcr_mask: A bit mask of all TCG PCRs mapped to this RTMR.
 */
struct tsm_rtmr_desc {
	enum hash_algo hash_alg;
	unsigned long tcg_pcr_mask;
};

/**
 * struct tsm_capabilities - Describes a TSM capabilities.
 * @num_rtmrs: The number of Runtime Measurement Registers (RTMR) available from
 *             a TSM.
 * @rtmr_hash_alg: The hash algorithm used to extend a runtime measurement
 *                 register.
 */
struct tsm_capabilities {
	size_t num_rtmrs;
	const struct tsm_rtmr_desc *rtmrs;
};

/**
 * struct tsm_ops - attributes and operations for tsm instances
 * @name: tsm id reflected in /sys/kernel/config/tsm/report/$report/provider
 * @privlevel_floor: convey base privlevel for nested scenarios
 * @capabilities: Describe the TSM capabilities, e.g. the number of available
 *                runtime measurement registers (see `struct tsm_capabilities`).
 * @report_new: Populate @report with the report blob and auxblob
 *              (optional), return 0 on successful population, or -errno
 *              otherwise
 * @rtmr_extend: Extend an RTMR with the provided digest.
 *               Return 0 on successful extension, or -errno otherwise.
 * @rtmr_read: Reads the value of an RTMR.
 *             Return the number of bytes read or -errno for errors.
 *
 * Implementation specific ops, only one is expected to be registered at
 * a time i.e. only one of "sev-guest", "tdx-guest", etc.
 */
struct tsm_ops {
	const char *name;
	const unsigned int privlevel_floor;
	const struct tsm_capabilities capabilities;
	int (*report_new)(struct tsm_report *report, void *data);
	int (*rtmr_extend)(u32 idx, const u8 *digest, size_t digest_size);
	ssize_t (*rtmr_read)(u32 idx, u8 *digest, size_t digest_size);
};

extern const struct config_item_type tsm_report_default_type;

/* publish @privlevel, @privlevel_floor, and @auxblob attributes */
extern const struct config_item_type tsm_report_extra_type;

int tsm_register(const struct tsm_ops *ops, void *priv,
		 const struct config_item_type *type);
int tsm_unregister(const struct tsm_ops *ops);
#endif /* __TSM_H */
