/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

#include <linux/types.h>

/*
 * This file contains both macros and data structures defined by the TDX
 * architecture and Linux defined software data structures and functions.
 * The two should not be mixed together for better readability.  The
 * architectural definitions come first.
 */

/* MSR to report KeyID partitioning between MKTME and TDX */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

/*
 * Do not put any hardware-defined TDX structure representations below
 * this comment!
 */

struct tdx_module_output;
u64 __seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
	       struct tdx_module_output *out);
#endif
