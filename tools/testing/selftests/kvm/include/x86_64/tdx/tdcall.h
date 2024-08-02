/* SPDX-License-Identifier: GPL-2.0-only */
/* Adapted from arch/x86/include/asm/shared/tdx.h */

#ifndef SELFTESTS_TDX_TDCALL_H
#define SELFTESTS_TDX_TDCALL_H

#include <linux/bits.h>
#include <linux/types.h>

#define TDG_VP_VMCALL_INSTRUCTION_IO_READ 0
#define TDG_VP_VMCALL_INSTRUCTION_IO_WRITE 1

#define TDG_VP_VMCALL_SUCCESS 0x0000000000000000
#define TDG_VP_VMCALL_INVALID_OPERAND 0x8000000000000000

#define TDX_HCALL_HAS_OUTPUT BIT(0)

#define TDX_HYPERCALL_STANDARD 0

/*
 * Used in __tdx_hypercall() to pass down and get back registers' values of
 * the TDCALL instruction when requesting services from the VMM.
 *
 * This is a software only structure and not part of the TDX module/VMM ABI.
 */
struct tdx_hypercall_args {
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

/* Used to request services from the VMM */
u64 __tdx_hypercall(struct tdx_hypercall_args *args, unsigned long flags);

#endif // SELFTESTS_TDX_TDCALL_H
