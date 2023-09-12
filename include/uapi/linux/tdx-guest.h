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

/* Length of the REPORTMACSTRUCT */
#define TDX_REPORTMACSTRUCT_LEN         256

/* Length of RTMR extend data */
#define TDX_EXTEND_RTMR_DATA_LEN        48

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

/* struct tdx_verify_report_req: Request struct for TDX_CMD_VERIFY_REPORT IOCTL.
 * @reportmac: User buffer with REPORTMACSTRUCT. REPORTMACSTRUCT data is part of
 * TDREPORT output generated via TDCALL[TDG.MR.REPORT].
 * @err_code: TDG.MR.VERIFYREPORT TDCALL return error code.
 *
 * It is used to verify whether the given REPORTMACSTRUCT was created on
 * the current Trusted Execution Environment (TEE).
 */
struct tdx_verify_report_req {
	__u8 reportmac[TDX_REPORTMACSTRUCT_LEN];
	__u64 err_code;
};

/**
 * struct tdx_extend_rtmr_req - Request struct for TDX_CMD_EXTEND_RTMR IOCTL.
 *
 * @data: User buffer with RTMR extend data.
 * @index: Index of RTMR register to be extended. RTMR0 and RTMR1 registers
 *         are used by kernel and BIOS and hence are not allowed to be extended
 *         by the userspace.
 */
struct tdx_extend_rtmr_req {
	__u8 data[TDX_EXTEND_RTMR_DATA_LEN];
	__u8 index;
};

/*
 * Format of Quote data header. More details can be found in TDX
 * Guest-Host Communication Interface (GHCI) for Intel TDX 1.0,
 * section titled "TDG.VP.VMCALL<GetQuote>"
 */
struct tdx_quote_hdr {
	/* Quote version, filled by TD */
	__u64 version;
	/* Status code of Quote request, filled by VMM */
	__u64 status;
	/* Length of TDREPORT, filled by TD */
	__u32 in_len;
	/* Length of Quote, filled by VMM */
	__u32 out_len;
	/* Actual Quote data or TDREPORT on input */
	__u64 data[0];
};

/* struct tdx_quote_req: Request struct for TDX_CMD_GET_QUOTE IOCTL.
 *
 * @buf         : Address of user buffer that includes TDREPORT. Upon
 *                successful completion of IOCTL, output is copied
 *                back to the same buffer.
 * @len         : Length of the Quote buffer.
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
 * TDX_CMD_VERIFY_REPORT - Verify REPORTMACSTRUCT using
 *                         TDG.MR.VERIFYREPORT TDCALL.
 *
 * Returns 0 on success, and standard errono on other failures.
 */
#define TDX_CMD_VERIFY_REPORT		_IOWR('T', 2, struct tdx_verify_report_req)

/*
 * TDX_CMD_EXTEND_RTMR - Extend RTMR registers with user data using
 *                       TDG.MR.RTMR.EXTEND TDCALL.
 *
 * Returns 0 on success, and standard errono on other failures.
 */
#define TDX_CMD_EXTEND_RTMR		_IOW('T', 3, struct tdx_extend_rtmr_req)

/*
 * TDX_CMD_GET_QUOTE - Get TD Guest Quote from QE/QGS using GetQuote
 *		       TDVMCALL.
 *
 * Returns 0 on success, -EINTR for interrupted request, and
 * standard errono on other failures.
 */
#define TDX_CMD_GET_QUOTE		_IOWR('T', 4, struct tdx_quote_req)

#endif /* _UAPI_LINUX_TDX_GUEST_H_ */
