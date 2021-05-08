/* SPDX-License-Identifier: GPL-2.0 */
/* architectural constants/data definitions for TDX SEAMCALLs */

#ifndef __ASM_X86_TDX_ARCH_H
#define __ASM_X86_TDX_ARCH_H

struct tdx_ex_ret {
	union {
		/* Used to retrieve values from hardware. */
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
			u64 r11;
		};
	};
};

#endif /* __ASM_X86_TDX_ARCH_H */
