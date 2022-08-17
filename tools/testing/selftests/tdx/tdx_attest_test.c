// SPDX-License-Identifier: GPL-2.0
/*
 * Test TDX attestation
 *
 * Copyright (C) 2022 Intel Corporation. All rights reserved.
 *
 * Author: Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <uapi/asm/tdx.h>

#include "../kselftest_harness.h"

#define TDX_GUEST_DEVNAME	"/dev/" TDX_GUEST_DEVICE
#define HEX_DUMP_SIZE		8
#define __packed		__attribute__((packed))
#define DEBUG			0
#define QUOTE_SIZE		8192

/*
 * struct tdreport_type - Type header of TDREPORT_STRUCT.
 * More details can be found in TDX v1.0 module specification, sec
 * titled "REPORTTYPE".
 */
struct tdreport_type {
	/* 0 - SGX, 81 -TDX, rest are reserved */
	__u8 type;
	/* Default value is 0 */
	__u8 sub_type;
	/* Default value is 0 */
	__u8 version;
	__u8 reserved;
}  __packed;

/*
 * struct reportmac - It is MAC-protected and contains hashes of the
 * remainder of the report structure along with user provided report
 * data. More details can be found in TDX v1.0 Module specification,
 * sec titled "REPORTMACSTRUCT"
 */
struct reportmac {
	struct tdreport_type type;
	__u8 reserved1[12];
	/* CPU security version */
	__u8 cpu_svn[16];
	/* SHA384 hash of TEE TCB INFO */
	__u8 tee_tcb_info_hash[48];
	/* SHA384 hash of TDINFO_STRUCT */
	__u8 tee_td_info_hash[48];
	/* User defined unique data passed in TDG.MR.REPORT request */
	__u8 reportdata[64];
	__u8 reserved2[32];
	__u8 mac[32];
}  __packed;

/*
 * struct td_info - It contains the measurements and initial
 * configuration of the TDX guest that was locked at initialization and
 * a set of measurement registers that are run-time extendable. More
 * details can be found in TDX v1.0 Module specification, sec titled
 * "TDINFO_STRUCT".
 */
struct td_info {
	/* TDX Guest attributes (like debug, spet_disable, etc) */
	__u8 attr[8];
	__u64 xfam;
	/* Measurement registers */
	__u64 mrtd[6];
	__u64 mrconfigid[6];
	__u64 mrowner[6];
	__u64 mrownerconfig[6];
	/* Runtime measurement registers */
	__u64 rtmr[24];
	__u64 reserved[14];
} __packed;

/*
 * struct tdreport - Output of TDCALL[TDG.MR.REPORT].
 * More details can be found in TDX v1.0 Module specification, sec
 * titled "TDREPORT_STRUCT".
 */
struct tdreport {
	/* Common to TDX/SGX of size 256 bytes */
	struct reportmac reportmac;
	__u8 tee_tcb_info[239];
	__u8 reserved[17];
	/* Measurements and configuration data of size 512 byes */
	struct td_info tdinfo;
}  __packed;

static void print_array_hex(const char *title, const char *prefix_str,
			    const void *buf, int len)
{
	int i, rowsize = HEX_DUMP_SIZE;
	const __u8 *ptr = buf;

	if (!len || !buf)
		return;

	printf("\t\t%s", title);

	for (i = 0; i < len; i++) {
		if (!(i % rowsize))
			printf("\n%s%.8x:", prefix_str, i);
		printf(" %.2x", ptr[i]);
	}

	printf("\n");
}

/* Helper function to get TDREPORT */
long get_tdreport(int devfd, __u8 *reportdata, struct tdreport *tdreport)
{
	struct tdx_report_req req;
	int i;

	/* Generate sample report data */
	for (i = 0; i < TDX_REPORTDATA_LEN; i++)
		reportdata[i] = i;

	/* Initialize IOCTL request */
	req.subtype     = 0;
	req.reportdata  = (__u64)reportdata;
	req.rpd_len     = TDX_REPORTDATA_LEN;
	req.tdreport    = (__u64)tdreport;
	req.tdr_len     = sizeof(*tdreport);

	memset(req.reserved, 0, sizeof(req.reserved));

	return ioctl(devfd, TDX_CMD_GET_REPORT, &req);
}

TEST(verify_report)
{
	__u8 reportdata[TDX_REPORTDATA_LEN];
	struct tdreport tdreport;
	int devfd;

	devfd = open(TDX_GUEST_DEVNAME, O_RDWR | O_SYNC);

	ASSERT_LT(0, devfd);

	/* Get TDREPORT */
	ASSERT_EQ(0, get_tdreport(devfd, reportdata, &tdreport));

	if (DEBUG) {
		print_array_hex("\n\t\tTDX report data\n", "",
				reportdata, sizeof(reportdata));

		print_array_hex("\n\t\tTDX tdreport data\n", "",
				&tdreport, sizeof(tdreport));
	}

	/* Make sure TDREPORT data includes the REPORTDATA passed */
	ASSERT_EQ(0, memcmp(&tdreport.reportmac.reportdata[0],
			    reportdata, sizeof(reportdata)));

	ASSERT_EQ(0, close(devfd));
}

TEST(verify_quote)
{
	__u8 reportdata[TDX_REPORTDATA_LEN];
	struct tdx_quote_hdr *quote_hdr;
	struct tdx_quote_req req;
	__u8 *quote_buf = NULL;
	__u64 quote_buf_size;
	int devfd;

	/* Open attestation device */
	devfd = open(TDX_GUEST_DEVNAME, O_RDWR | O_SYNC);

	ASSERT_LT(0, devfd);

	/* Add size for quote header */
	quote_buf_size = sizeof(*quote_hdr) + QUOTE_SIZE;

	/* Allocate quote buffer */
	quote_buf = malloc(quote_buf_size);
	ASSERT_NE(NULL, quote_buf);

	quote_hdr = (struct tdx_quote_hdr *)quote_buf;

	/* Initialize GetQuote header */
	quote_hdr->version = 1;
	quote_hdr->status  = GET_QUOTE_SUCCESS;
	quote_hdr->in_len  = TDX_REPORT_LEN;
	quote_hdr->out_len = 0;

	/* Get TDREPORT data */
	ASSERT_EQ(0, get_tdreport(devfd, reportdata,
				(struct tdreport *)&quote_hdr->data));

	/* Fill GetQuote request */
	req.buf	  = (__u64)quote_buf;
	req.len	  = quote_buf_size;

	ASSERT_EQ(0, ioctl(devfd, TDX_CMD_GET_QUOTE, &req));

	/* Check whether GetQuote request is successful */
	EXPECT_EQ(0, quote_hdr->status);

	free(quote_buf);
}

TEST(verify_reportmac)
{
	__u8 reportdata[TDX_REPORTDATA_LEN];
	struct tdx_verifyreport_req req;
	struct tdreport tdreport;
	int devfd;

	devfd = open(TDX_GUEST_DEVNAME, O_RDWR | O_SYNC);

	ASSERT_LT(0, devfd);

	/* Get TDREPORT */
	ASSERT_EQ(0, get_tdreport(devfd, reportdata, &tdreport));

	/* Fill VERIFYREPORT request */
	req.reportmac	  = (__u64)&tdreport.reportmac;
	req.rpm_len	  = sizeof(tdreport.reportmac);

	/* Verify reportmac and make sure it is valid */
	ASSERT_EQ(0, ioctl(devfd, TDX_CMD_VERIFYREPORT, &req));

	ASSERT_EQ(0, close(devfd));
}


TEST_HARNESS_MAIN
