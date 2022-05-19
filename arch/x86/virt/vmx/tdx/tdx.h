/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

/*
 * This file contains both macros and data structures defined by the TDX
 * architecture and Linux defined software data structures and functions.
 * The two should not be mixed together for better readability.  The
 * architectural definitions come first.
 */

/* MSR to report KeyID partitioning between MKTME and TDX */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

#endif
