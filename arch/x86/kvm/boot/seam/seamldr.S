/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ASM helper to load Intel SEAM module.
 *
 * Copyright (C) 2019 Intel Corporation
 *
 * Authors:
 *	Kai Huang <kai.huang>@intel.com
 */
#include <linux/linkage.h>
#include <linux/init.h>
#include <uapi/asm/processor-flags.h>
#include <asm/asm.h>
#include <asm/errno.h>
#include <asm/msr-index.h>
#include <asm/segment.h>
#include <asm/unwind_hints.h>

.macro save_msr _msr
	movl	$(\_msr), %ecx
	rdmsr
	pushq	%rax
	pushq	%rdx
.endm

.macro restore_msr _msr
	popq	%rdx
	popq	%rax
	movl	$(\_msr), %ecx
	wrmsr
.endm

	.text
	__INIT
	.code64
SYM_CODE_START(launch_seamldr)
	UNWIND_HINT_FUNC

	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx

	/* Save DR7, SEAMLDR sets it to 0x400. */
	movq	%dr7, %rax
	pushq	%rax

	/*
	 * SEAMLDR restores GDTR and CS before ExitAC, DS/ES/SS don't need to
	 * be manually preserved as this is 64-bit mode, and FS/GS are
	 * not modified by EnterACCS or SEAMLDR.
	 */

	/* EnterACCS and SEAMLDR modify CR0 and CR4. */
	movq	%cr0, %rax
	pushq	%rax
	movq	%cr4, %rax
	pushq	%rax

	/* Enable CR4.SMXE for GETSEC */
	orq	$X86_CR4_SMXE, %rax
	movq	%rax, %cr4

	/*
	 * Load R8-R11 immediately, they won't be clobbered, unlike RDX.
	 *
	 *  - R8: SEAMLDR_PARAMS physical address
	 *  - R9: GDT base to be setup by SEMALDR when returning to kernel
	 *  - R10: RIP of resume point
	 *  - R11: CR3 when returning to kernel
	 *  - R12: IDT to be setup by SEAMLDR when returning to kernel
	 */
	movq	%rdx, %r8
	sgdt	kernel_gdt64(%rip)
	movq	kernel_gdt64_base(%rip), %r9
	leaq	.Lseamldr_resume(%rip), %r10
	movq	%cr3, %r11
	sidt	kernel_idt(%rip)
	movq	kernel_idt_base(%rip), %r12

	/* Save MSRs that are modified by EnterACCS and/or SEAMLDR */
	save_msr MSR_EFER
	save_msr MSR_IA32_CR_PAT
	save_msr MSR_IA32_MISC_ENABLE

	/*
	 * MSRs that are clobbered by SEAMLDR but are not enabled during early
	 * boot and so don't need to be saved/restored.
	 *
	 * save_msr MSR_IA32_DEBUGCTLMSR
	 * save_msr MSR_CORE_PERF_GLOBAL_CTRL
	 * save_msr MSR_IA32_PEBS_ENABLE
	 * save_msr MSR_IA32_RTIT_CTL
	 * save_msr MSR_IA32_LBR_CTRL
	 */

	/* Now as last step, save RSP before invoking GETSEC[ENTERACCS] */
	movq	%rsp, saved_rsp(%rip)

	/*
	 * Load the Remaining params for EnterACCS.
	 *
	 *  - EBX: SEAMLDR ACM physical address
	 *  - ECX: SEAMLDR ACM size
	 *  - EAX: 2
	 */
	movl	%edi, %ebx
	movl	%esi, %ecx

	/* Invoke GETSEC[ENTERACCS] */
	movl	$2, %eax
.Lseamldr_enteraccs:
	getsec

.Lseamldr_resume:
	/*
	 * SEAMLDR restores CRs, GDT and IDT.  Segment registers are flat, but
	 * don't hold kernel selectors.  Reload the data segs now.
	 */
	movl	$__KERNEL_DS, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss

	/*
	 * Restore stack from RIP relative storage, and then restore everything
	 * else from the stack.
	 */
	movq	saved_rsp(%rip), %rsp

	/*
	 * Restore CPU status, in reverse order of saving. Firstly, restore
	 * MSRs.
	 */
	restore_msr  MSR_IA32_MISC_ENABLE
	restore_msr  MSR_IA32_CR_PAT
	restore_msr  MSR_EFER

	popq	%rax
	movq	%rax, %cr4
	popq	%rax
	movq	%rax, %cr0

	popq	%rax
	movq	%rax, %dr7

	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp

	/* Far return to load the kernel's CS. */
	popq	%rax
	pushq	$__KERNEL_CS
	pushq	%rax

	movq	%r9, %rax
	UNWIND_HINT sp_reg=ORG_REG_SP sp_offset=16 type=UNWIND_HINT_TYPE_FUNC
	lretq

.pushsection .fixup, "ax"
	/*
	 * ENTERACCS faulted, return -EFAULT.  Restore CR4 (to clear SMXE) and
	 * GPRs (to make objtool happy, only RBP/RSP are actually modified).
	 */
1:	movq	8 * 6(%rsp), %rax
	movq	%rax, %cr4
	addq	$(8 *9), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	movq	$-EFAULT, %rax
	ret
.popsection
	_ASM_EXTABLE(.Lseamldr_enteraccs, 1b)

SYM_CODE_END(launch_seamldr)

	__INITDATA
	.balign	8
kernel_idt:
	.word	0
kernel_idt_base:
	.quad	0
kernel_gdt64:
	.word	0
kernel_gdt64_base:
	.quad	0
saved_rsp:
	.quad	0
