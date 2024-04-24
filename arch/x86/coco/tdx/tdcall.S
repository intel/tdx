/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/shared/tdx.h>

#include <linux/linkage.h>

/* TDCALL is supported in Binutils >= 2.36 */
#define tdcall		.byte 0x66,0x0f,0x01,0xcc

.pushsection .noinstr.text, "ax"
SYM_FUNC_START(tdvmcall_trampoline)
	movq	%rax, %r10
	movq    %rbx, %r11
	movq    %rdi, %r12
	movq    %rsi, %r13
	movq    %rdx, %r14
	movq    %rcx, %r15

	movq	$TDG_VP_VMCALL, %rax
	movq    $(TDX_R10 | TDX_R11 | TDX_R12 | TDX_R13 | TDX_R14 | TDX_R15), %rcx

	tdcall

	testq   %rax, %rax
	jnz     1f

	RET
1:
	ud2
SYM_FUNC_END(tdvmcall_trampoline)
.popsection

SYM_FUNC_START(tdvmcall_report_fatal_error)
	movq	$TDX_HYPERCALL_STANDARD, %r10
	movq	$TDVMCALL_REPORT_FATAL_ERROR, %r11
	movq	%rdi, %r12
	movq	$0, %r13

	movq	%rsi, %rcx

	/* Order according to the GHCI */
	movq	0*8(%rcx), %r14
	movq	1*8(%rcx), %r15
	movq	2*8(%rcx), %rbx
	movq	3*8(%rcx), %rdi
	movq	4*8(%rcx), %rsi
	movq	5*8(%rcx), %r8
	movq	6*8(%rcx), %r9
	movq	7*8(%rcx), %rdx

	movq	$TDG_VP_VMCALL, %rax
	movq	$(TDX_RDX | TDX_RBX | TDX_RSI | TDX_RDI | TDX_R8  | TDX_R9  | \
		  TDX_R10 | TDX_R11 | TDX_R12 | TDX_R13 | TDX_R14 | TDX_R15), \
		%rcx

	tdcall

	ud2
SYM_FUNC_END(tdvmcall_report_fatal_error)

#ifdef CONFIG_HYPERV
SYM_FUNC_START(hv_tdx_hypercall)
	movq	%rdi, %r10
	movq    %rsi, %rdx
	movq    %rcx, %r8

	movq	$TDG_VP_VMCALL, %rax
	movq    $(TDX_R8 | TDX_R10 | TDX_RDX), %rcx

	tdcall

	testq   %rax, %rax
	jnz     1f

	movq	%r11, %rax

	RET
1:
	ud2
SYM_FUNC_END(hv_tdx_hypercall)
#endif
