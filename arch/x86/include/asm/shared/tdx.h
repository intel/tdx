#ifndef _ASM_X86_SHARED_TDX_H
#define _ASM_X86_SHARED_TDX_H

#include <linux/types.h>

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

#define TDX_HYPERCALL_STANDARD  0

#define TDX_CPUID_LEAF_ID	0x21
#define TDX_IDENT		"IntelTDX    "

/* Used to request services from the VMM */
u64 __tdx_hypercall(u64 type, u64 fn, u64 r12, u64 r13, u64 r14,
		    u64 r15, struct tdx_hypercall_output *out);

#endif
