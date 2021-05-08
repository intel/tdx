/* SPDX-License-Identifier: GPL-2.0 */
/* data structures and C wrapper functions for the NP-SEAMLDR ABI and the P-SEAMLDR ABI */

#ifndef _X86_TDX_P_SEAMLOADER_H
#define _X86_TDX_P_SEAMLOADER_H

#include <asm/tdx_errno.h>

/*
 * TDX_SEAMCALL_VMFAILINVALID is chosen so that it doesn't conflict with any
 * P-SEAMLDR error codes for OS use.  See tdx_errno.h.
 */
#define P_SEAMLDR_VMFAILINVALID	TDX_SEAMCALL_VMFAILINVALID

/*
 * P-SEAMLDR error codes
 */
#define P_SEAMLDR_SEAMCALL_ERROR_CODE	0x8000000000000000ULL

#define P_SEAMLDR_SUCCESS	0x0000000000000000ULL

#endif /* _X86_TDX_P_SEAMLOADER_H */
