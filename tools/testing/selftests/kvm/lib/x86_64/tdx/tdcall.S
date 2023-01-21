/* SPDX-License-Identifier: GPL-2.0-only */
/* Adapted from arch/x86/coco/tdx/tdcall.S */

#define TDX_HYPERCALL_r10 0 /* offsetof(struct tdx_hypercall_args, r10) */
#define TDX_HYPERCALL_r11 8 /* offsetof(struct tdx_hypercall_args, r11) */
#define TDX_HYPERCALL_r12 16 /* offsetof(struct tdx_hypercall_args, r12) */
#define TDX_HYPERCALL_r13 24 /* offsetof(struct tdx_hypercall_args, r13) */
#define TDX_HYPERCALL_r14 32 /* offsetof(struct tdx_hypercall_args, r14) */
#define TDX_HYPERCALL_r15 40 /* offsetof(struct tdx_hypercall_args, r15) */

/*
 * Bitmasks of exposed registers (with VMM).
 */
#define TDX_R10 0x400
#define TDX_R11 0x800
#define TDX_R12 0x1000
#define TDX_R13 0x2000
#define TDX_R14 0x4000
#define TDX_R15 0x8000

#define TDX_HCALL_HAS_OUTPUT 0x1

/*
 * These registers are clobbered to hold arguments for each
 * TDVMCALL. They are safe to expose to the VMM.
 * Each bit in this mask represents a register ID. Bit field
 * details can be found in TDX GHCI specification, section
 * titled "TDCALL [TDG.VP.VMCALL] leaf".
 */
#define TDVMCALL_EXPOSE_REGS_MASK	( TDX_R10 | TDX_R11 | \
					  TDX_R12 | TDX_R13 | \
					  TDX_R14 | TDX_R15 )

.code64
.section .text

.globl __tdx_hypercall
.type __tdx_hypercall, @function
__tdx_hypercall:
	/* Set up stack frame */
	push %rbp
	movq %rsp, %rbp

	/* Save callee-saved GPRs as mandated by the x86_64 ABI */
	push %r15
	push %r14
	push %r13
	push %r12

	/* Mangle function call ABI into TDCALL ABI: */
	/* Set TDCALL leaf ID (TDVMCALL (0)) in RAX */
	xor %eax, %eax

	/* Copy hypercall registers from arg struct: */
	movq TDX_HYPERCALL_r10(%rdi), %r10
	movq TDX_HYPERCALL_r11(%rdi), %r11
	movq TDX_HYPERCALL_r12(%rdi), %r12
	movq TDX_HYPERCALL_r13(%rdi), %r13
	movq TDX_HYPERCALL_r14(%rdi), %r14
	movq TDX_HYPERCALL_r15(%rdi), %r15

	movl $TDVMCALL_EXPOSE_REGS_MASK, %ecx

	tdcall

	/* TDVMCALL leaf return code is in R10 */
	movq %r10, %rax

	/* Copy hypercall result registers to arg struct if needed */
	testq $TDX_HCALL_HAS_OUTPUT, %rsi
	jz .Lout

	movq %r10, TDX_HYPERCALL_r10(%rdi)
	movq %r11, TDX_HYPERCALL_r11(%rdi)
	movq %r12, TDX_HYPERCALL_r12(%rdi)
	movq %r13, TDX_HYPERCALL_r13(%rdi)
	movq %r14, TDX_HYPERCALL_r14(%rdi)
	movq %r15, TDX_HYPERCALL_r15(%rdi)
.Lout:
	/* Restore callee-saved GPRs as mandated by the x86_64 ABI */
	pop %r12
	pop %r13
	pop %r14
	pop %r15

	pop %rbp
	ret

#define TDX_MODULE_rcx 0 /* offsetof(struct tdx_module_output, rcx) */
#define TDX_MODULE_rdx 8 /* offsetof(struct tdx_module_output, rdx) */
#define TDX_MODULE_r8 16 /* offsetof(struct tdx_module_output, r8) */
#define TDX_MODULE_r9 24 /* offsetof(struct tdx_module_output, r9) */
#define TDX_MODULE_r10 32 /* offsetof(struct tdx_module_output, r10) */
#define TDX_MODULE_r11 40 /* offsetof(struct tdx_module_output, r11) */

.globl __tdx_module_call
.type __tdx_module_call, @function
__tdx_module_call:
	/* Set up stack frame */
	push %rbp
	movq %rsp, %rbp

	/* Callee-saved, so preserve it */
	push %r12

	/*
	 * Push output pointer to stack.
	 * After the operation, it will be fetched into R12 register.
	 */
	push %r9

	/* Mangle function call ABI into TDCALL/SEAMCALL ABI: */
	/* Move Leaf ID to RAX */
	mov %rdi, %rax
	/* Move input 4 to R9 */
	mov %r8,  %r9
	/* Move input 3 to R8 */
	mov %rcx, %r8
	/* Move input 1 to RCX */
	mov %rsi, %rcx
	/* Leave input param 2 in RDX */

	tdcall

	/*
	 * Fetch output pointer from stack to R12 (It is used
	 * as temporary storage)
	 */
	pop %r12

	/*
	 * Since this macro can be invoked with NULL as an output pointer,
	 * check if caller provided an output struct before storing output
	 * registers.
	 *
	 * Update output registers, even if the call failed (RAX != 0).
	 * Other registers may contain details of the failure.
	 */
	test %r12, %r12
	jz .Lno_output_struct

	/* Copy result registers to output struct: */
	movq %rcx, TDX_MODULE_rcx(%r12)
	movq %rdx, TDX_MODULE_rdx(%r12)
	movq %r8,  TDX_MODULE_r8(%r12)
	movq %r9,  TDX_MODULE_r9(%r12)
	movq %r10, TDX_MODULE_r10(%r12)
	movq %r11, TDX_MODULE_r11(%r12)

.Lno_output_struct:
	/* Restore the state of R12 register */
	pop %r12

	pop %rbp
	ret

/* Disable executable stack */
.section .note.GNU-stack,"",%progbits
