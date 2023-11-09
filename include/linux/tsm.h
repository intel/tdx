/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TSM_H
#define __TSM_H

#include <linux/sizes.h>
#include <linux/types.h>
#include <linux/uuid.h>

#define TSM_INBLOB_MAX 64
#define TSM_RTMR_DATA_MAX 48
#define TSM_REPORT_DATA_MAX 256
#define TSM_OUTBLOB_MAX SZ_32K

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
 * @remote_guid: GUID of the report generation server
 */
struct tsm_desc {
	unsigned int privlevel;
	size_t inblob_len;
	u8 inblob[TSM_INBLOB_MAX];
	guid_t remote_guid;
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

/**
 * struct tsm_rtmr - track state of RTMR extend operation
 * @index: Index of RTMR register to extend
 * @data_len: sizeof @data
 * @data: Measurement extension data.
 * @status: Status of RTMR extend operation.
 */
struct tsm_rtmr {
	unsigned int index;
	size_t data_len;
	u8 data[TSM_RTMR_DATA_MAX];
	int status;
};

/**
 * struct tsm_misc - track state of misc TSM operations
 * @report_data: Report data to be validated.
 * @report_data_len: sizeof @report_data
 * @report_status: Validation status of the report data.
 */
struct tsm_misc {
	u8 report_data[TSM_REPORT_DATA_MAX];
	size_t report_data_len;
	int report_status;
};

/**
 * struct tsm_ops - attributes and operations for tsm instances
 * @name: tsm id reflected in /sys/kernel/config/tsm/report/$report/provider
 * @privlevel_floor: convey base privlevel for nested scenarios
 * @max_rtmr_index: Maximum RTMR register index allowed to extend.
 * @min_rtmr_index: Minimum RTMR register index allowed to extend.
 * @report_new: Populate @report with the report blob and auxblob
 * @update_rtmr: Update RTMR register with RTMR data and index.
 * @verify_report: Verify the integerity of the report and return status.
 * (optional), return 0 on successful population, or -errno otherwise
 *
 * Implementation specific ops, only one is expected to be registered at
 * a time i.e. only one of "sev-guest", "tdx-guest", etc.
 */
struct tsm_ops {
	const char *name;
	const unsigned int privlevel_floor;
	const unsigned int min_rtmr_index;
	const unsigned int max_rtmr_index;
	int (*report_new)(struct tsm_report *report, void *data);
	int (*update_rtmr)(struct tsm_rtmr *rtmr, void *data);
	int (*verify_report)(struct tsm_misc *misc, void *data);
};

extern const struct config_item_type tsm_report_default_type;

/* publish @privlevel, @privlevel_floor, and @auxblob attributes */
extern const struct config_item_type tsm_report_extra_type;

int tsm_register(const struct tsm_ops *ops, void *priv,
		 const struct config_item_type *type);
int tsm_unregister(const struct tsm_ops *ops);
#endif /* __TSM_H */
