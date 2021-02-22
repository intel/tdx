/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/unwind_hints.h>

#include <linux/linkage.h>

/*
 * Expose registers R10-R15 to VMM (for bitfield info
 * refer to TDX GHCI specification).
 */
#define TDVMCALL_EXPOSE_REGS_MASK	0xfc00

/*
 * TDX guests use the TDCALL instruction to make
 * hypercalls to the VMM. It is supported in
 * Binutils >= 2.36.
 */
#define tdcall .byte 0x66,0x0f,0x01,0xcc

/*
 * __tdcall()  - Used to communicate with the TDX module
 *
 * @arg1 (RDI) - TDCALL Leaf ID
 * @arg2 (RSI) - Input parameter 1 passed to TDX module
 *               via register RCX
 * @arg2 (RDX) - Input parameter 2 passed to TDX module
 *               via register RDX
 * @arg3 (RCX) - Input parameter 3 passed to TDX module
 *               via register R8
 * @arg4 (R8)  - Input parameter 4 passed to TDX module
 *               via register R9
 * @arg5 (R9)  - struct tdcall_output pointer
 *
 * @out        - Return status of tdcall via RAX.
 *
 * NOTE: This function should only used for non TDVMCALL
 *       use cases
 */
SYM_FUNC_START(__tdcall)
	FRAME_BEGIN

	/* Save non-volatile GPRs that are exposed to the VMM. */
	push %r15
	push %r14
	push %r13
	push %r12

	/* Move TDCALL Leaf ID to RAX */
	mov %rdi, %rax
	/* Move output pointer to R12 */
	mov %r9, %r12
	/* Move input param 4 to R9 */
	mov %r8, %r9
	/* Move input param 3 to R8 */
	mov %rcx, %r8
	/* Leave input param 2 in RDX */
	/* Move input param 1 to RCX */
	mov %rsi, %rcx

	tdcall

	/* Check for TDCALL success: 0 - Successful, otherwise failed */
	test %rax, %rax
	jnz 1f

	/* Check for a TDCALL output struct */
	test %r12, %r12
	jz 1f

	/* Copy TDCALL result registers to output struct: */
	movq %rcx, TDCALL_rcx(%r12)
	movq %rdx, TDCALL_rdx(%r12)
	movq %r8,  TDCALL_r8(%r12)
	movq %r9,  TDCALL_r9(%r12)
	movq %r10, TDCALL_r10(%r12)
	movq %r11, TDCALL_r11(%r12)
1:
	/* Zero out registers exposed to the TDX Module. */
	xor %rcx,  %rcx
	xor %rdx,  %rdx
	xor %r8d,  %r8d
	xor %r9d,  %r9d
	xor %r10d, %r10d
	xor %r11d, %r11d

	/* Restore non-volatile GPRs that are exposed to the VMM. */
	pop %r12
	pop %r13
	pop %r14
	pop %r15

	FRAME_END
	ret
SYM_FUNC_END(__tdcall)

/*
 * do_tdvmcall()  - Used to communicate with the VMM.
 *
 * @arg1 (RDI)    - TDVMCALL function, e.g. exit reason
 * @arg2 (RSI)    - Input parameter 1 passed to VMM
 *                  via register R12
 * @arg3 (RDX)    - Input parameter 2 passed to VMM
 *                  via register R13
 * @arg4 (RCX)    - Input parameter 3 passed to VMM
 *                  via register R14
 * @arg5 (R8)     - Input parameter 4 passed to VMM
 *                  via register R15
 * @arg6 (R9)     - struct tdvmcall_output pointer
 *
 * @out           - Return status of tdvmcall(R10) via RAX.
 *
 */
SYM_CODE_START_LOCAL(do_tdvmcall)
	FRAME_BEGIN

	/* Save non-volatile GPRs that are exposed to the VMM. */
	push %r15
	push %r14
	push %r13
	push %r12

	/* Set TDCALL leaf ID to TDVMCALL (0) in RAX */
	xor %eax, %eax
	/* Move TDVMCALL function id (1st argument) to R11 */
	mov %rdi, %r11
	/* Move Input parameter 1-4 to R12-R15 */
	mov %rsi, %r12
	mov %rdx, %r13
	mov %rcx, %r14
	mov %r8,  %r15
	/* Leave tdvmcall output pointer in R9 */

	/*
	 * Value of RCX is used by the TDX Module to determine which
	 * registers are exposed to VMM. Each bit in RCX represents a
	 * register id. You can find the bitmap details from TDX GHCI
	 * spec.
	 */
	movl $TDVMCALL_EXPOSE_REGS_MASK, %ecx

	tdcall

	/*
	 * Check for TDCALL success: 0 - Successful, otherwise failed.
	 * If failed, there is an issue with TDX Module which is fatal
	 * for the guest. So panic.
	 */
	test %rax, %rax
	jnz 2f

	/* Move TDVMCALL success/failure to RAX to return to user */
	mov %r10, %rax

	/* Check for TDVMCALL success: 0 - Successful, otherwise failed */
	test %rax, %rax
	jnz 1f

	/* Check for a TDVMCALL output struct */
	test %r9, %r9
	jz 1f

	/* Copy TDVMCALL result registers to output struct: */
	movq %r11, TDVMCALL_r11(%r9)
	movq %r12, TDVMCALL_r12(%r9)
	movq %r13, TDVMCALL_r13(%r9)
	movq %r14, TDVMCALL_r14(%r9)
	movq %r15, TDVMCALL_r15(%r9)
1:
	/*
	 * Zero out registers exposed to the VMM to avoid
	 * speculative execution with VMM-controlled values.
	 */
	xor %r10d, %r10d
	xor %r11d, %r11d
	xor %r12d, %r12d
	xor %r13d, %r13d
	xor %r14d, %r14d
	xor %r15d, %r15d

	/* Restore non-volatile GPRs that are exposed to the VMM. */
	pop %r12
	pop %r13
	pop %r14
	pop %r15

	FRAME_END
	ret
2:
	ud2
SYM_CODE_END(do_tdvmcall)

/* Helper function for standard type of TDVMCALL */
SYM_FUNC_START(__tdvmcall)
	/* Set TDVMCALL type info (0 - Standard, > 0 - vendor) in R10 */
	xor %r10, %r10
	call do_tdvmcall
	retq
SYM_FUNC_END(__tdvmcall)
