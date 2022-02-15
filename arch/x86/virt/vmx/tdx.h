/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

#include <linux/types.h>
#include <linux/compiler.h>

/*
 * TDX architectural data structures
 */

#define P_SEAMLDR_INFO_ALIGNMENT	256

struct p_seamldr_info {
	u32	version;
	u32	attributes;
	u32	vendor_id;
	u32	build_date;
	u16	build_num;
	u16	minor;
	u16	major;
	u8	reserved0[2];
	u32	acm_x2apicid;
	u8	reserved1[4];
	u8	seaminfo[128];
	u8	seam_ready;
	u8	seam_debug;
	u8	p_seamldr_ready;
	u8	reserved2[88];
} __packed __aligned(P_SEAMLDR_INFO_ALIGNMENT);

/*
 * P-SEAMLDR SEAMCALL leaf function
 */
#define P_SEAMLDR_SEAMCALL_BASE		BIT_ULL(63)
#define P_SEAMCALL_SEAMLDR_INFO		(P_SEAMLDR_SEAMCALL_BASE | 0x0)

/*
 * TDX module SEAMCALL leaf functions
 */
#define TDH_SYS_LP_SHUTDOWN	44

struct tdx_module_output;
u64 __seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
	       struct tdx_module_output *out);

#endif
