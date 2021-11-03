/* SPDX-License-Identifier: GPL-2.0 */
/* architectural status code for SEAMCALL */

#ifndef __ASM_X86_TDX_ERRNO_H
#define __ASM_X86_TDX_ERRNO_H

#define TDX_SEAMCALL_STATUS_MASK		0xFFFFFFFF00000000ULL

/*
 * TDX SEAMCALL Status Codes (returned in RAX)
 */
#define TDX_SUCCESS				0x0000000000000000ULL
#define TDX_OPERAND_INVALID			0xC000010000000000ULL
#define TDX_SYSCONFIG_NOT_DONE                  0xC000050700000000ULL
#define TDX_KEY_GENERATION_FAILED		0x8000080000000000ULL
#define TDX_KEY_CONFIGURED			0x0000081500000000ULL


/*
 * Picked up a value that does not conflict with any TDX status codes and
 * any P-SEAMLDR error codes.
 *
 * The format of TDX module status codes:
 * * 63:32: class code
 *   63: error
 *   62: non-recoverable
 *   47:40: class ID 0xFF reserved for OS use
 *   39:32: details_L1
 * 31:0: details_L2
 *
 * The format of P-SEAMLDR error codes:
 * 0x80000000_cccceeee
 *   cccc: error class
 *   eeee: details
 */
#define TDX_SEAMCALL_VMFAILINVALID		0x8000FF00FFFF0000ULL

#define TDX_STATUS_CODE(name)	{ name, #name }

#define TDX_STATUS_CODES					\
	TDX_STATUS_CODE(TDX_SUCCESS),				\
	TDX_STATUS_CODE(TDX_OPERAND_INVALID),			\
	TDX_STATUS_CODE(TDX_SYSCONFIG_NOT_DONE),		\
	TDX_STATUS_CODE(TDX_KEY_GENERATION_FAILED),		\
	TDX_STATUS_CODE(TDX_KEY_CONFIGURED),			\
	TDX_STATUS_CODE(TDX_SEAMCALL_VMFAILINVALID)

#endif /* __ASM_X86_TDX_ERRNO_H */
