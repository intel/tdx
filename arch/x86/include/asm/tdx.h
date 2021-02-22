/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/init.h>

#define TDX_CPUID_LEAF_ID	0x21
#define TDX_IDENT		"IntelTDX    "

#define TDX_HYPERCALL_STANDARD  0

/*
 * Used in __tdx_module_call() to gather the output registers'
 * values of the TDCALL instruction when requesting services from
 * the TDX module. This is a software only structure and not part
 * of the TDX module/VMM ABI
 */
struct tdx_module_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

/*
 * Used in __tdx_hypercall() to gather the output registers' values
 * of the TDCALL instruction when requesting services from the VMM.
 * This is a software only structure and not part of the TDX
 * module/VMM ABI.
 */
struct tdx_hypercall_output {
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);
bool is_tdx_guest(void);

/* Used to communicate with the TDX module */
u64 __tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		      struct tdx_module_output *out);

/* Used to request services from the VMM */
u64 __tdx_hypercall(u64 type, u64 fn, u64 r12, u64 r13, u64 r14,
		    u64 r15, struct tdx_hypercall_output *out);

#else

static inline void tdx_early_init(void) { };
static inline bool is_tdx_guest(void) { return false; }

#endif /* CONFIG_INTEL_TDX_GUEST */

#endif /* _ASM_X86_TDX_H */
