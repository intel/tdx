/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

#include <linux/types.h>
#include <linux/bits.h>

/*
 * This file contains both macros and data structures defined by the TDX
 * architecture and Linux defined software data structures and functions.
 * The two should not be mixed together for better readability.  The
 * architectural definitions come first.
 */

/*
 * Intel Trusted Domain CPU Architecture Extension spec:
 *
 * IA32_MTRRCAP:
 *   Bit 15:	The support of SEAMRR
 *
 * IA32_SEAMRR_PHYS_MASK (core-scope):
 *   Bit 10:	Lock bit
 *   Bit 11:	Enable bit
 */
#define MTRR_CAP_SEAMRR			BIT_ULL(15)

#define MSR_IA32_SEAMRR_PHYS_MASK	0x00001401

#define SEAMRR_PHYS_MASK_ENABLED	BIT_ULL(11)
#define SEAMRR_PHYS_MASK_LOCKED		BIT_ULL(10)
#define SEAMRR_ENABLED_BITS	\
	(SEAMRR_PHYS_MASK_ENABLED | SEAMRR_PHYS_MASK_LOCKED)

/*
 * IA32_MKTME_KEYID_PARTIONING:
 *   Bit [31:0]:	Number of MKTME KeyIDs.
 *   Bit [63:32]:	Number of TDX private KeyIDs.
 *
 * MKTME KeyIDs start from KeyID 1. TDX private KeyIDs start
 * after the last MKTME KeyID.
 */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

#define TDX_KEYID_START(_keyid_part)	\
		((u32)(((_keyid_part) & 0xffffffffull) + 1))
#define TDX_KEYID_NUM(_keyid_part)	((u32)((_keyid_part) >> 32))


/*
 * Do not put any hardware-defined TDX structure representations below this
 * comment!
 */

struct tdx_module_output;
u64 __seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
	       struct tdx_module_output *out);

#endif
