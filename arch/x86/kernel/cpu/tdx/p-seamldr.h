/* SPDX-License-Identifier: GPL-2.0 */
/* data structures and C wrapper functions for the NP-SEAMLDR ABI and the P-SEAMLDR ABI */

#ifndef _X86_TDX_P_SEAMLOADER_H
#define _X86_TDX_P_SEAMLOADER_H

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

int __init load_p_seamldr(void);

#endif /* _X86_TDX_P_SEAMLOADER_H */
