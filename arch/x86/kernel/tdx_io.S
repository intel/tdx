/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/linkage.h>
#include <asm/export.h>

#include <asm/tdx.h>

#ifdef CONFIG_INTEL_TDX_ICL_FIXES
#define TDCALL vmcall
#else
#define TDCALL .byte 0x66,0x0f,0x01,0xcc
#endif

#define EXIT_REASON_IO_INSTRUCTION 30

SYM_FUNC_START(tdx_outb)
	push	%r15
	push	%r12

	xor	%r15, %r15
	mov	%al, %r15b
	mov	$1, %r12
	jmp	1f

SYM_FUNC_START(tdx_outw)
	push	%r15
	push	%r12

	xor	%r15, %r15
	mov	%ax, %r15w
	mov	$2, %r12
	jmp	1f

SYM_FUNC_START(tdx_outl)
	push	%r15
	push	%r12

	xor	%r15, %r15
	mov	%eax, %r15d
	mov	$4, %r12
1:
	push	%rax
	push	%rcx
	push	%r10
	push	%r11
	push	%r13
	push	%r14

#ifndef TDX_SKIP_IO_FILTERING
	push	%rdx
	mov	%dx, %di
	call	tdx_allowed_port
	pop	%rdx
	test	%al, %al
	jz	out_tdx_out
#endif

	mov	$TDVMCALL, %rax
	mov	$TDVMCALL_STANDARD, %r10
	mov	$EXIT_REASON_IO_INSTRUCTION, %r11
	mov	$1, %r13
	xor	%r14, %r14
	mov	%dx, %r14w
	/* Allow to pass R10, R11, R12, R13, R14 and R15 down to the VMM */
	mov	$0xfc00, %rcx

	TDCALL

	/* Panic if TDVMCALL reports failure */
	test	%rax, %rax
	jnz	1f

	/* Panic if TDVMCALL reports failure */
	test	%r10, %r10
	jnz	1f
out_tdx_out:
	pop	%r14
	pop	%r13
	pop	%r11
	pop	%r10
	pop	%rcx
	pop	%rax

	pop	%r12
	pop	%r15
	ret
1:
	ud2
SYM_FUNC_END(tdx_outb)
SYM_FUNC_END(tdx_outw)
SYM_FUNC_END(tdx_outl)
EXPORT_SYMBOL(tdx_outb)
EXPORT_SYMBOL(tdx_outw)
EXPORT_SYMBOL(tdx_outl)

SYM_FUNC_START(tdx_inb)
	push	%r12
	mov	$1, %r12
	jmp	1f

SYM_FUNC_START(tdx_inw)
	push	%r12
	mov	$2, %r12
	jmp	1f

SYM_FUNC_START(tdx_inl)
	push	%r12

	mov	$4, %r12
1:
	push	%r11
	push	%rax
	push	%rcx
	push	%r10
	push	%r13
	push	%r14

#ifndef TDX_SKIP_IO_FILTERING
	push	%rdx
	mov	%dx, %di
	call	tdx_allowed_port
	pop	%rdx
	test	%al, %al
	jz	out_tdx_in
#endif

	mov	$TDVMCALL, %rax
	mov	$TDVMCALL_STANDARD, %r10
	mov	$EXIT_REASON_IO_INSTRUCTION, %r11
	mov	$0, %r13
	xor	%r14, %r14
	mov	%dx, %r14w

	/* Allow to pass R10, R11, R12, R13 and R14 down to the VMM */
	mov	$0x7c00, %rcx

	TDCALL

	/* Panic if TDVMCALL reports failure */
	test	%rax, %rax
	jnz	1f

	/* Panic if TDVMCALL reports failure */
	test	%r10, %r10
	jnz	1f
out_tdx_in:
	pop	%r14
	pop	%r13
	pop	%r10
	pop	%rcx
	pop	%rax

	mov %r11d, %eax

	pop	%r11
	pop	%r12
	ret
1:
	ud2
SYM_FUNC_END(tdx_inb)
SYM_FUNC_END(tdx_inw)
SYM_FUNC_END(tdx_inl)
EXPORT_SYMBOL(tdx_inb)
EXPORT_SYMBOL(tdx_inw)
EXPORT_SYMBOL(tdx_inl)
