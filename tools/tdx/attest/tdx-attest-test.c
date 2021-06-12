// SPDX-License-Identifier: GPL-2.0-only
/*
 * tdx-attest-test.c - utility to test TDX attestation feature.
 *
 * Copyright (C) 2020 - 2021 Intel Corporation. All rights reserved.
 *
 * Author: Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 *
 */

#include <linux/types.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdint.h> /* uintmax_t */
#include <sys/mman.h>
#include <unistd.h> /* sysconf */
#include <time.h>

#include "../../../include/uapi/misc/tdx.h"

#define devname		"/dev/tdx-attest"

#define HEX_DUMP_SIZE	16
#define MAX_ROW_SIZE	70

#define ATTESTATION_TEST_BIN_VERSION "0.1"

struct tdx_attest_args {
	bool is_dump_data;
	bool is_get_tdreport;
	bool is_get_quote_size;
	bool is_gen_quote;
	bool debug_mode;
	char *out_file;
};

static void print_hex_dump(const char *title, const char *prefix_str,
			   const void *buf, int len)
{
	const __u8 *ptr = buf;
	int i, rowsize = HEX_DUMP_SIZE;

	if (!len || !buf)
		return;

	printf("\t\t%s", title);

	for (i = 0; i < len; i++) {
		if (!(i % rowsize))
			printf("\n%s%.8x:", prefix_str, i);
		printf(" %.2x", ptr[i])
	}

	printf("\n");
}

static void gen_report_data(__u8 *report_data, bool dump_data)
{
	int i;

	srand(time(NULL));

	for (i = 0; i < TDX_REPORT_DATA_LEN; i++)
		report_data[i] = rand();

	if (dump_data)
		print_hex_dump("\n\t\tTDX report data\n", " ",
			       report_data, TDX_REPORT_DATA_LEN);
}

static int get_tdreport(int devfd, bool dump_data, __u8 *report_data)
{
	__u8 tdrdata[TDX_TDREPORT_LEN] = {0};
	int ret;

	if (!report_data)
		report_data = tdrdata;

	gen_report_data(report_data, dump_data);

	ret = ioctl(devfd, TDX_CMD_GET_TDREPORT, report_data);
	if (ret) {
		printf("TDX_CMD_GET_TDREPORT ioctl() %d failed\n", ret);
		return -EIO;
	}

	if (dump_data)
		print_hex_dump("\n\t\tTDX tdreport data\n", " ", report_data,
			       TDX_TDREPORT_LEN);

	return 0;
}

static __u64 get_quote_size(int devfd)
{
	int ret;
	__u64 quote_size;

	ret = ioctl(devfd, TDX_CMD_GET_QUOTE_SIZE, &quote_size);
	if (ret) {
		printf("TDX_CMD_GET_QUOTE_SIZE ioctl() %d failed\n", ret);
		return -EIO;
	}

	printf("Quote size: %lld\n", quote_size);

	return quote_size;
}

static int gen_quote(int devfd, bool dump_data)
{
	__u8 *quote_data;
	__u64 quote_size;
	int ret;

	quote_size = get_quote_size(devfd);

	quote_data = malloc(sizeof(char) * quote_size);
	if (!quote_data) {
		printf("%s queue data alloc failed\n", devname);
		return -ENOMEM;
	}

	ret = get_tdreport(devfd, dump_data, quote_data);
	if (ret) {
		printf("TDX_CMD_GET_TDREPORT ioctl() %d failed\n", ret);
		goto done;
	}

	ret = ioctl(devfd, TDX_CMD_GEN_QUOTE, quote_data);
	if (ret) {
		printf("TDX_CMD_GEN_QUOTE ioctl() %d failed\n", ret);
		goto done;
	}

	print_hex_dump("\n\t\tTDX Quote MMIO data\n", " ", quote_data,
		       quote_size);

done:
	free(quote_data);

	return ret;
}

static void usage(void)
{
	puts("\nUsage:\n");
	puts("tdx_attest [options] \n");

	puts("Attestation device test utility.");

	puts("\nOptions:\n");
	puts(" -d, --dump                Dump tdreport/tdquote data");
	puts(" -r, --get-tdreport        Get TDREPORT data");
	puts(" -g, --gen-quote           Generate TDQUOTE");
	puts(" -s, --get-quote-size      Get TDQUOTE size");
}

int main(int argc, char **argv)
{
	int ret, devfd;
	struct tdx_attest_args args = {0};

	static const struct option longopts[] = {
		{ "dump",           no_argument,       NULL, 'd' },
		{ "get-tdreport",   required_argument, NULL, 'r' },
		{ "gen-quote",      required_argument, NULL, 'g' },
		{ "gen-quote-size", required_argument, NULL, 's' },
		{ "version",        no_argument,       NULL, 'V' },
		{ NULL,             0, NULL, 0 }
	};

	while ((ret = getopt_long(argc, argv, "hdrgsV", longopts,
				  NULL)) != -1) {
		switch (ret) {
		case 'd':
			args.is_dump_data = true;
			break;
		case 'r':
			args.is_get_tdreport = true;
			break;
		case 'g':
			args.is_gen_quote = true;
			break;
		case 's':
			args.is_get_quote_size = true;
			break;
		case 'h':
			usage();
			return 0;
		case 'V':
			printf("Version: %s\n", ATTESTATION_TEST_BIN_VERSION);
			return 0;
		default:
			printf("Invalid options\n");
			usage();
			return -EINVAL;
		}
	}

	devfd = open(devname, O_RDWR | O_SYNC);
	if (devfd < 0) {
		printf("%s open() failed\n", devname);
		return -ENODEV;
	}

	if (args.is_get_quote_size)
		get_quote_size(devfd);

	if (args.is_get_tdreport)
		get_tdreport(devfd, args.is_dump_data, NULL);

	if (args.is_gen_quote)
		gen_quote(devfd, args.is_dump_data);

	close(devfd);

	return 0;
}
