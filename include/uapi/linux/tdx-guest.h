/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace interface for TDX guest driver
 *
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef _UAPI_LINUX_TDX_GUEST_H_
#define _UAPI_LINUX_TDX_GUEST_H_

#include <linux/ioctl.h>
#include <linux/types.h>

/* Length of the REPORTDATA used in TDG.MR.REPORT TDCALL */
#define TDX_REPORTDATA_LEN              64

/* Length of TDREPORT used in TDG.MR.REPORT TDCALL */
#define TDX_REPORT_LEN                  1024

/* TD Quote status codes */
#define GET_QUOTE_SUCCESS               0
#define GET_QUOTE_IN_FLIGHT             0xffffffffffffffff
#define GET_QUOTE_ERROR                 0x8000000000000000
#define GET_QUOTE_SERVICE_UNAVAILABLE   0x8000000000000001

/**
 * struct tdx_report_req - Request struct for TDX_CMD_GET_REPORT0 IOCTL.
 *
 * @reportdata: User buffer with REPORTDATA to be included into TDREPORT.
 *              Typically it can be some nonce provided by attestation
 *              service, so the generated TDREPORT can be uniquely verified.
 * @tdreport: User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT].
 */
struct tdx_report_req {
	__u8 reportdata[TDX_REPORTDATA_LEN];
	__u8 tdreport[TDX_REPORT_LEN];
};

/* struct tdx_quote_hdr: Format of Quote request buffer header.
 * @version: Quote format version, filled by TD.
 * @status: Status code of Quote request, filled by VMM.
 * @in_len: Length of TDREPORT, filled by TD.
 * @out_len: Length of Quote data, filled by VMM.
 * @data: Quote data on output or TDREPORT on input.
 *
 * More details of Quote data header can be found in TDX
 * Guest-Host Communication Interface (GHCI) for Intel TDX 1.0,
 * section titled "TDG.VP.VMCALL<GetQuote>"
 */
struct tdx_quote_hdr {
	__u64 version;
	__u64 status;
	__u32 in_len;
	__u32 out_len;
	__u64 data[];
};

/* struct tdx_quote_req: Request struct for TDX_CMD_GET_QUOTE IOCTL.
 * @buf: Address of user buffer that includes TDREPORT. Upon successful
 *	 completion of IOCTL, output is copied back to the same buffer.
 * @len: Length of the Quote buffer.
 */
struct tdx_quote_req {
	__u64 buf;
	__u64 len;
};

/*
 * TDX_CMD_GET_REPORT0 - Get TDREPORT0 (a.k.a. TDREPORT subtype 0) using
 *                       TDCALL[TDG.MR.REPORT]
 *
 * Return 0 on success, -EIO on TDCALL execution failure, and
 * standard errno on other general error cases.
 */
#define TDX_CMD_GET_REPORT0              _IOWR('T', 1, struct tdx_report_req)

/*
 * TDX_CMD_GET_QUOTE - Get TD Guest Quote from QE/QGS using GetQuote
 *		       TDVMCALL.
 *
 * Returns 0 on success or standard errno on other failures.
 */
#define TDX_CMD_GET_QUOTE		_IOR('T', 2, struct tdx_quote_req)

#endif /* _UAPI_LINUX_TDX_GUEST_H_ */
