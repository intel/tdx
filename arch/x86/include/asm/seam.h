/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Secure Arbitration Mode (SEAM) support
 */
#ifndef _ASM_X86_SEAM_H
#define _ASM_X86_SEAM_H

#include <asm/processor.h>

#ifdef CONFIG_INTEL_TDX_HOST

#include <linux/linkage.h>
#include <linux/types.h>

void detect_seam(struct cpuinfo_x86 *c);
bool seamrr_enabled(void);

/*
 * All SEAMCALLs use %rax to indicate the leaf function number, with
 * bit 63 indicating whether the call is for P-SEAMLDR or the TDX
 * module.  The completion status is also returned in %rax.
 *
 * Additional GPRs may be further used as input/output for specific
 * leaf functions.  Introduce two structures (seamcall_regs_in and
 * seamcall_regs_out) to encapsulate all possible GPRs for the common
 * SEAMCALL wrapper.
 *
 * The only exception not covered here is TDENTER leaf function, which
 * takes all GPRs and XMM0-XMM15 as both input/output. The caller of
 * TDENTER should implement its own logic directly instead of calling
 * the wrapper function defined in this file.
 */
struct seamcall_regs_in {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
};

struct seamcall_regs_out {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

/**
 * samcall - C function of SEAMCALL instruction.
 *
 * @op:	Leaf number for specific SEAMCALL
 * @in: Additional input operands (can be NULL).
 * @out: Additional output operands (can be NULL).
 *
 * Note: Call this function only when SEAMRR is enabled,
 * and CPU is already in VMX operation, otherwise #UD.
 *
 * Return: 0 for success, -ENODEV if SEAM firmware is not
 *	   loaded/enabled or P-SEAMLDR is busy with another
 *	   SEAMCALL, or actual error code per leaf function.
 */
asmlinkage u64 seamcall(u64 op, struct seamcall_regs_in *in,
			struct seamcall_regs_out *out);

#else
static inline void detect_seam(struct cpuinfo_x86 *c) { }
static inline bool seamrr_enabled(void) { return false; }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* _ASM_X86_SEAM_H */
