/* SPDX-License-Identifier: GPL-2.0 */
/* ASM helper to load Intel NP-SEAMLDR. */
#include <linux/linkage.h>
#include <linux/init.h>
#include <uapi/asm/processor-flags.h>
#include <asm/unwind_hints.h>
#include <asm/msr-index.h>
#include <asm/segment.h>
#include <asm/errno.h>
#include <asm/frame.h>
#include <asm/asm.h>

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

/*
 * u64 np_seamldr_launch(unsigned long seamldr_pa, unsigned long seamldr_size)
 * launch NP-SEAMLDR by invoking GETSEC[ENTERACC]
 *
 * @seamldr_pa(EDI): physical address of NP-SEAMLDR < 4GB
 * @seamldr_size(ESI): size of seamldr
 * @return(RAX): 0 on success, seamldr error code on failure, -EFAULT on exception
 */
	.text
	__INIT
	.code64
SYM_FUNC_START(np_seamldr_launch)
	pushq	%rbp
	movq	%rsp, %rbp

	/* NP-SEAMLDR sets %rflags to 0x2.  Save rflags to unmask interrupt later. */
	pushfq

	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx

	/* Save DR7, NP-SEAMLDR sets it to 0x400. */
	movq	%dr7, %rax
	pushq	%rax

	/*
	 * NP-SEAMLDR restores GDTR and CS before ExitAC, DS/ES/SS don't need
	 * to be manually preserved as this is 64-bit mode, and FS/GS are not
	 * modified by EnterACCS or NP-SEAMLDR.
	 */

	/*
	 * NP-SEAMLDR sets CR4.PCIDE = 0 and restores CR3 from %r11. It requires
	 * CR3.PCID=0.  Save CR3 to restore CR3.PCID later.
	 */
	movq	%cr3, %r11
	pushq	%r11

	/* EnterACCS and NP-SEAMLDR modify CR0 and CR4. */
	movq	%cr0, %rax
	pushq	%rax
	movq	%cr4, %rax
	pushq	%rax

	/* Enable CR4.SMXE for GETSEC. */
	orq	$X86_CR4_SMXE, %rax
	movq	%rax, %cr4

	/*
	 * Load R9-R12 immediately, they won't be clobbered, unlike RDX.
	 * SEAMLDR spec: 4.1 OS/VMM Loader steps to launch NP-SEAMLDR
	 *
	 *  - R9: GDT base to be setup by SEMALDR when returning to kernel
	 *  - R10: RIP of resume point
	 *  - R11: CR3 with PCID=0 when returning to kernel
	 *  - R12: IDT to be setup by NP-SEAMLDR when returning to kernel
	 */
	sgdt	kernel_gdt64(%rip)
	movq	kernel_gdt64_base(%rip), %r9
	leaq	.Lseamldr_resume(%rip), %r10
	/* %r11 is set above. */
	andq	$~X86_CR3_PCID_MASK, %r11
	sidt	kernel_idt64(%rip)
	movq	kernel_idt64_base(%rip), %r12

	/* Save MSRs that are modified by EnterACCS and/or NP-SEAMLDR. */
	save_msr MSR_EFER
	save_msr MSR_IA32_CR_PAT
	save_msr MSR_IA32_MISC_ENABLE

	/*
	 * MSRs that are clobbered by NP-SEAMLDR, but the caller
	 * saves/restores them.  They require discovery and conditional
	 * save/restore by rdmsr_safe/wrmsr_safe.  It's cumbersome to do so in
	 * assembly code.
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
	 *  - EBX: NP-SEAMLDR ACM physical address
	 *  - ECX: NP-SEAMLDR ACM size
	 *  - EAX: 2
	 */
	movl	%edi, %ebx
	movl	%esi, %ecx

	/* Invoke GETSEC[ENTERACCS] */
	movl	$2, %eax
.Lseamldr_enteraccs:
	getsec

.Lseamldr_resume:
	UNWIND_HINT_EMPTY
	/*
	 * NP-SEAMLDR restores CRs, GDT and IDT.  Segment registers are flat,
	 * but don't hold kernel selectors.  Reload the data segs now.
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
	/* objtools loses stack size because no way to specify stack size. */
	UNWIND_HINT sp_reg=ORC_REG_SP sp_offset=8*18 type=UNWIND_HINT_TYPE_CALL

	/*
	 * Restore CPU status, in reverse order of saving. Firstly, restore
	 * MSRs.
	 */
	restore_msr MSR_IA32_MISC_ENABLE
	restore_msr MSR_IA32_CR_PAT
	restore_msr MSR_EFER

	popq	%rax
	movq	%rax, %cr4
	popq	%rax
	movq	%rax, %cr0
	popq	%rax
	movq	%rax, %cr3

	popq	%rax
	movq	%rax, %dr7

	/* Workaround for TDX module version that doesn't restore idt. */
	lidt	kernel_idt64(%rip)

	/* Far return to load the kernel CS before unmasking interrupt. */
	pushq	$__KERNEL_CS
	leaq	.Lkernel_cs(%rip), %rax
	pushq	%rax
	lretq
.Lkernel_cs:
	UNWIND_HINT sp_reg=ORC_REG_SP sp_offset=8*8 type=UNWIND_HINT_TYPE_CALL

	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	/*
	 * frame unwinder requires valid %rbp.  Restore %rbp before unmasking
	 * interrupt.
	 */
	movq	8(%rsp), %rbp
	popfq	/* interrupt is unmasked. */
	addq	$8, %rsp

	movq	%r9, %rax
	/* workaround for objtool to lose stack size. */
	UNWIND_HINT_FUNC
	ret

.pushsection .fixup, "ax"
	/*
	 * ENTERACCS faulted, return -EFAULT.  Restore CR4 (to clear SMXE) and
	 * GPRs (to make objtool happy, only RBP/RSP are actually modified).
	 */
1:
	movq	16 * 3(%rsp), %rax	/* 3 MSRs: EFER, CR_PAT, MISC_ENABLE */
	movq	%rax, %cr4
	/* skip 3 MSRs, %cr4, %cr0, %cr3 and %dr7. */
	addq	$(16 * 3 + 8 * 4), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popfq
	popq	%rbp
	movq	$-EFAULT, %rax
	ret
.popsection
	_ASM_EXTABLE(.Lseamldr_enteraccs, 1b)

SYM_FUNC_END(np_seamldr_launch)

	__INITDATA
	.balign	8
kernel_gdt64:
	.word	0
kernel_gdt64_base:
	.quad	0

	.balign	8
kernel_idt64:
	.word	0
kernel_idt64_base:
	.quad	0

	.balign	8
saved_rsp:
	.quad	0
