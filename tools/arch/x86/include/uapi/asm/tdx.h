/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_TDX_H
#define _UAPI_ASM_X86_TDX_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define TDX_GUEST_DEVICE		"tdx-guest"

/* Length of the REPORTDATA used in TDG.MR.REPORT TDCALL */
#define TDX_REPORTDATA_LEN              64

/* Length of TDREPORT used in TDG.MR.REPORT TDCALL */
#define TDX_REPORT_LEN                  1024

/**
 * struct tdx_report_req: Get TDREPORT using REPORTDATA as input.
 *
 * @reportdata     : User-defined REPORTDATA to be included into
 *                   TDREPORT. Typically it can be some nonce
 *                   provided by attestation service, so the
 *                   generated TDREPORT can be uniquely verified.
 * @tdreport       : TDREPORT output from TDCALL[TDG.MR.REPORT].
 * @rpd_len        : Length of the REPORTDATA (fixed as 64 bytes by
 *                   the TDX Module specification, but parameter is
 *                   added to handle future extension).
 * @tdr_len        : Length of the TDREPORT (fixed as 1024 bytes by
 *                   the TDX Module specification, but a parameter
 *                   is added to accommodate future extension).
 * @subtype        : Subtype of TDREPORT (fixed as 0 by TDX Module
 *                   specification, but added a parameter to handle
 *                   future extension).
 * @reserved       : Reserved entries to handle future requirements.
 *                   Default acceptable value is 0.
 *
 * Used in TDX_CMD_GET_REPORT IOCTL request.
 */
struct tdx_report_req {
	__u64 reportdata;
	__u64 tdreport;
	__u32 rpd_len;
	__u32 tdr_len;
	__u8  subtype;
	__u8 reserved[7];
};

/*
 * TDX_CMD_GET_REPORT - Get TDREPORT using TDCALL[TDG.MR.REPORT]
 *
 * Return 0 on success, -EIO on TDCALL execution failure, and
 * standard errno on other general error cases.
 *
 */
#define TDX_CMD_GET_REPORT		_IOWR('T', 0x01, __u64)

/* TD Quote status codes */
#define GET_QUOTE_SUCCESS               0
#define GET_QUOTE_IN_FLIGHT             0xffffffffffffffff
#define GET_QUOTE_ERROR                 0x8000000000000000
#define GET_QUOTE_SERVICE_UNAVAILABLE   0x8000000000000001

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

/* struct tdx_quote_req: Request to generate TD Quote using TDREPORT
 *
 * @buf         : Pass user data that includes TDREPORT as input. Upon
 *                successful completion of IOCTL, output is copied
 *                back to the same buffer.
 * @len         : Length of the Quote buffer.
 */
struct tdx_quote_req {
	__u64 buf;
	__u64 len;
};

/*
 * TDX_CMD_GET_QUOTE - Get TD Quote from QE/QGS using GetQuote
 *		       TDVMCALL.
 *
 * Returns 0 on success, -EINTR for interrupted request, and
 * standard errono on other failures.
 */
#define TDX_CMD_GET_QUOTE		_IOR('T', 0x02, __u64)

/* Length of the REPORTMACSTRUCT */
#define TDX_REPORTMACSTRUCT_LEN		256

/* struct tdx_verifyreport_req: Request to verify REPORTMACSTRUCT to
 *                              determine that it was created on the
 *                              current Trusted Execution Environment
 *                              (TEE) on the current platform
 *
 * @reportmac      : REPORTMACSTRUCT from TDREPORT output of
 *                   TDCALL[TDG.MR.REPORT]. It is the first field in the
 *                   TDREPORT struct, which contains hash of TEE TCB
 *                   information and hash of the TDINFO_STRUCT and MAC ID.
 * @rpm_len        : Length of the REPORTMACSTRUCT (fixed as 256 bytes
 *                   by the TDX Module specification, but parameter is
 *                   added to handle future extension).
 */
struct tdx_verifyreport_req {
	__u64 reportmac;
	__u32 rpm_len;
};

/*
 * TDX_CMD_VERIFYREPORT - Verify REPORTMACSTRUCT using TDG.MR.VERIFYREPORT
 *                        TDCALL.
 *
 * Returns 0 on success, and standard errono on other failures.
 */
#define TDX_CMD_VERIFYREPORT		_IOR('T', 0x03, __u64)

#endif /* _UAPI_ASM_X86_TDX_H */
