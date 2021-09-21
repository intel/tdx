/* SPDX-License-Identifier: GPL-2.0 */
/* data structures and C wrapper functions for the NP-SEAMLDR ABI and the P-SEAMLDR ABI */

#ifndef _X86_TDX_P_SEAMLOADER_H
#define _X86_TDX_P_SEAMLOADER_H

#include <linux/types.h>
#include <asm/page.h>

/*
 * NP-SEAMLDR error codes
 */
#define NP_SEAMLDR_EMODBUSY	0x8000000000000001ULL
#define NP_SEAMLDR_EUNSPECERR	0x8000000000010003ULL

/*
 * P-SEAMLDR error codes
 */
#define P_SEAMLDR_SEAMCALL_ERROR_CODE	0x8000000000000000ULL

#define P_SEAMLDR_SUCCESS	0x0000000000000000ULL

#define P_SEAMLDR_ERROR_CODE(name)	{ name, #name }

#define P_SEAMLDR_ERROR_CODES				\
	P_SEAMLDR_ERROR_CODE(P_SEAMLDR_SUCCESS)

const char *p_seamldr_error_name(u64 error_code);

/*
 * P-SEAMLDR function leaves
 */
#define SEAMCALL_SEAMLDR_BASE		BIT_ULL(63)
#define SEAMCALL_SEAMLDR_INFO		SEAMCALL_SEAMLDR_BASE

struct tee_tcb_svn {
	u16 seam;
	u8 reserved[14];
} __packed;

struct __tee_tcb_info {
	u64 valid;
	struct tee_tcb_svn tee_tcb_svn;
	u64 mrseam[6];		/* SHA-384 */
	u64 mrsignerseam[6];	/* SHA-384 */
	u64 attributes;
} __packed;

struct tee_tcb_info {
	struct __tee_tcb_info info;
	u8 reserved[111];
} __packed;

#define P_SEAMLDR_INFO_ALIGNMENT	256
struct p_seamldr_info {
	u32 version;
	u32 attributes;
	u32 vendor_id;
	u32 build_date;
	u16 build_num;
	u16 minor;
	u16 major;
	u8 reserved0[2];
	u32 acm_x2apicid;
	u8 reserved1[4];
	struct __tee_tcb_info seaminfo;
	u8 seam_ready;
	u8 seam_debug;
	u8 p_seamldr_ready;
	u8 reserved2[88];
} __packed __aligned(P_SEAMLDR_INFO_ALIGNMENT);


int seamldr_info(phys_addr_t seamldr_info);

int __init load_p_seamldr(void);

#endif /* _X86_TDX_P_SEAMLOADER_H */
