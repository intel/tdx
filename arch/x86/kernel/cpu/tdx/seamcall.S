/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * ASM helper to call SEAMCALL for P-SEAMLDR and TDX module
 */

#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/frame.h>
#include <asm/errno.h>

.macro seamcall
	.byte 0x66, 0x0f, 0x01, 0xcf
.endm

/*
 * u64 seamcall(u64 op, struct seamcall_regs_in *in,
 *		struct seamcall_regs_out *out);
 *
 * @op  (RDI)   Leaf function number
 * @in  (RSI)   Pointer to input operands
 * @out (RDX)   Pointer to output operands
 *
 * Return (RDI): Completion code, or -ENODEV.
 */
SYM_FUNC_START(seamcall)
	FRAME_BEGIN

	/* Save @out to stack, since %rdx will be clobbered soon */
	pushq	%rdx

	/* Set up SEAMCALL leaf number */
	movq	%rdi, %rax

	/* Check whether additional input operands are provided */
	test	%rsi, %rsi
	jz	1f

	/* Set up additional input operands */
	movq	SEAMCALL_in_rcx(%rsi), %rcx
	movq	SEAMCALL_in_rdx(%rsi), %rdx
	movq	SEAMCALL_in_r8(%rsi), %r8
	movq	SEAMCALL_in_r9(%rsi), %r9
1:
	seamcall

	/* Restore @out so output operands can be saved */
	popq	%rdi

	/*
	 * SEAMCALL instruction is essentially a VMExit from VMX root mode
	 * to SEAM VMX root mode.  VMFailInvalid (CF=1) indicates that the
	 * targeted SEAM firmware is not loaded or disabled, or P-SEAMLDR
	 * is busy with another SEAMCALL.
	 *
	 * Return -ENODEV for VMFailInvalid.  This value will never be used
	 * as actual SEAMCALL error code.
	 */
	jnb	2f
	mov	$(-ENODEV), %rax
	jmp	3f
2:
	/*
	 * %rax contains SEAMCALL's completion status code.
	 * Save additional output operands if @out is not NULL.
	 */
	test	%rdi, %rdi
	jz	3f

	movq	%rcx, SEAMCALL_out_rcx(%rdi)
	movq	%rdx, SEAMCALL_out_rdx(%rdi)
	movq	%r8,  SEAMCALL_out_r8(%rdi)
	movq	%r9,  SEAMCALL_out_r9(%rdi)
	movq	%r10, SEAMCALL_out_r10(%rdi)
	movq	%r11, SEAMCALL_out_r11(%rdi)
3:
	FRAME_END
	ret
SYM_FUNC_END(seamcall)
