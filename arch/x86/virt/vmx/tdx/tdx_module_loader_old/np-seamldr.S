/* SPDX-License-Identifier: GPL-2.0 */
/*
 * An ASM helper to launch the Intel NP-SEAMLDR to load P-SEAMLDR to handle
 * the special calling convention to NP-SEAMLDR.
 */

#include <linux/linkage.h>
#include <linux/init.h>
#include <uapi/asm/processor-flags.h>
#include <asm/unwind_hints.h>
#include <asm/segment.h>
#include <asm/errno.h>
#include <asm/msr-index.h>

/*
 * u64 np_seamldr_launch(unsigned long seamldr_pa, unsigned long seamldr_size)
 * Launch the NP-SEAMLDR by invoking the GETSEC[EnterACCS] instruction.
 *
 * @seamldr_pa(EDI): Physical address of the NP-SEAMLDR < 4GB
 * @seamldr_size(ESI): Size of seamldr
 * @return(RAX): 0 on success, seamldr error code on failure,
 *               -EFAULT on exception
 *
 * The caller must saves/restores DR7 and the following MSRs:
 *   IA32_MISC_ENABLE, IA32_EFER, IA32_PAT, IA32_DEBUGCTL, IA32_PEBS_ENABLE,
 *   IA32_RTIT_CTRL, IA32_LBR_CTL
 *
 * The CPU state after GETSEC[EnterACC] to execute NP-SEAMLDR ACM.
 * CR0: PE=1, PG=1, NE=1; other bits cleared.
 * CR3: As provided by OS in R11.
 * CR4: PAE=1, SMXE=1; PGE and LA57 are unchanged; other bits cleared.
 * RFLAGS: Reset value (0x2). Note that the interrupts are masked.
 * IA32_EFER: LME=1, LMA=1, NXE=1; other bits cleared.
 * IA32_PAT: Reset value (0x00070406_00070406).
 *
 * RIP: As provided by OS in R10.
 * RAX: EXITAC leaf number (0x3).
 * RBX: As Provided by OS in R10.
 * R9: Load status returned by NP-SEAMLDR: success (0x0) or error code.
 * Other GPRs, including RSP 0x0
 *
 * CS: Flat.  Its segment selector is clobbered.
 * DS: Flat.  Its segment selector is clobbered.
 * GDTR: Base = As provided by OS in R9; Limit unchanged.
 * IDTR: Base = As provided by OS in R12; Limit unchanged.
 * DR7: 0x400
 * IA32_DEBUGCTL: 0x0
 * IA32_PERF_GLOBAL_CTRL: 0x0
 * IA32_PEBS_ENABLE: 0x0
 * IA32_RTIT_CTRL: TraceEn = 0, other bits are unchanged.
 * IA32_LBR_CTRL: 0x0
 * IA32_MISC_ENABLES: 0x8 (only thermal throttling is enabled)
 * Other registers (including MSRs, XCR0, XSAVES-able registers, DRs): Unchanged
 *
 * Save/restore the following registries:
 *   CR0, CR3, CR4,
 *   rflags,
 * Restore segment registers. don't save them because they have known values.
 *   DS, ES, CS, SS
 * Note that the CR4.CET depends on CR0.WP, so we need restore CR0 then CR4,
 * otherwise #GP when we restore CR4.CET if CR0.WP = 0
 */
	.text
	__INIT
	.code64
SYM_FUNC_START(np_seamldr_launch)
	pushq	%rbp
	movq	%rsp, %rbp

	/* Save the callee-saved registers. */
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx

	/*
	 * The NP-SEAMLDR clobbers %rflags to the reset value. Save rflags to
	 * restore system/control flags and unmask interrupts later.
	 */
	pushfq

	rdgsbase %rax
	movq	%rax, np_seamldr_saved_gs_base(%rip)

	/*
	 * The NP-SEAMLDR unconditionally sets CR4.PCIDE = 0 and restores CR3
	 * from %r11.  If CR4.PCIDE = 0, CR3 bit 3 and bit 4 are interpreted as
	 * PWT and PCD, not as a part of CR3.PCID[0:11].  When changing
	 * CR4.PCIDE from 0 to 1 if CR3.PCID != 0, it results in #GP.
	 *
	 * Clear CR3.PCID = 0 to avoid interpreting CR3.{PWT, PCD} and to allow
	 * to set CR4.PCIDE from 0 to 1.
	 */
	movq	%cr3, %r11
	pushq	%r11
	andq	$~X86_CR3_PCID_MASK, %r11

	/* EnterACCS and the NP-SEAMLDR modify CR4 and CR0. */
	movq	%cr4, %rax
	/*
	 * If exception or interrupt happens before restoring CR0/CR4, fsgsbase
	 * feature is disabled.  The handler needs to restore CR0/CR4 from the
	 * global variable.
	 */
	movq	%rax, np_seamldr_saved_cr4(%rip)
	movq	%cr0, %rax
	movq	%rax, np_seamldr_saved_cr0(%rip)

	/* Enable CR4.SMXE for GETSEC. */
	movq	%cr4, %rax
	orq	$X86_CR4_SMXE, %rax
	movq	%rax, %cr4

	/*
	 * Load R9-R12 immediately, they won't be clobbered, unlike RDX.
	 * The SEAMLDR spec: 4.1 OS/VMM Loader steps to launch the NP-SEAMLDR
	 *
	 *  - R9: GDT base to be set up by the SEAMLDR when returning to the
	 *        kernel
	 *  - R10: RIP of resume point
	 *  - R11: CR3 with PCID=0 when returning to kernel (set above)
	 *  - R12: IDT to be set up by the NP-SEAMLDR when returning to the
	 *	   kernel
	 */
	sgdt	kernel_gdt64(%rip)
	movq	kernel_gdt64_base(%rip), %r9
	leaq	.Lseamldr_resume(%rip), %r10
	sidt	kernel_idt64(%rip)
	movq	kernel_idt64_base(%rip), %r12

	/* Save RSP before invoking GETSEC[EnterACCS] */
	movq	%rsp, saved_rsp(%rip)
	/* The frame unwinder requires valid %rbp to restore %rbp early. */
	movq	%rbp, saved_rbp(%rip)

	/*
	 * Load the remaining params for EnterACCS.
	 *
	 *  - EBX: NP-SEAMLDR ACM physical address
	 *  - ECX: NP-SEAMLDR ACM size
	 *  - EAX: 2=EnterACCS
	 */
	movl	%edi, %ebx
	movl	%esi, %ecx

	/* Invoke GETSEC[EnterACCS] */
	movl	$2, %eax
.Lseamldr_enteraccs:
	getsec

.Lseamldr_resume:
	UNWIND_HINT_EMPTY

1:
	movq	$0x400, %rax
	movq	$0x0, %rdx
	movl	$0x830, %ecx
	wrmsr

	movq	$0x2, %rax
	movq	$0x0, %rdx
	movl	$0x83f, %ecx
	wrmsr

2:
	UNWIND_HINT_EMPTY
	/*
	 * The NP-SEAMLDR restores CRs, GDT, and IDT.  Segment registers are
	 * flat, but don't necessarily hold valid kernel selectors.  Reload the
	 * data segment selectors now.
	 *
	 * CR4.MCE: Cleared.
	 * rflags: Reset state 0x2.  Interrupt is masked.
	 * %cs, %ds, %es, %ss: Clobbered. The descriptor cache has flat segment.
	 * %r9: Status code NP-SEAMLDR returns.
	 *
	 * NP-SEAMLDR loads flat segment descriptor cache with its GDT and
	 * restores OS GDT, but it doesn't restore segment selectors and leaves
	 * segment selectors clobbered.  If exception/interrupt happens before
	 * restoring CS/SS, the clobbered CS/SS are saved and the handler is
	 * invoked with CS from IDT.  The following iret trying to re-load
	 * clobbered CS/SS segment selector causes #GP.
	 *
	 * np_seamldr_die_notify() corrects the clobbered CR4 and the saved
	 * CS/SS so that nmi handler and iret work as expected.
	 */
	movl	$__KERNEL_DS, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss

	/*
	 * The frame unwinder requires valid %rbp.  Restore %rbp early before
	 * enabling machine check and unmasking interrupts.
	 */
	movq	saved_rbp(%rip), %rbp

	/*
	 * Restore stack from RIP relative storage, and then restore everything
	 * else from the stack.
	*/
	movq	saved_rsp(%rip), %rsp
	/*
	 * The objtool loses stack size due to no way to specify its stack size.
	 */
	UNWIND_HINT sp_reg=ORC_REG_SP sp_offset=8*9 type=UNWIND_HINT_TYPE_CALL

	/* Far return to load the kernel CS. */
	pushq	$__KERNEL_CS
	leaq	.Lkernel_cs(%rip), %rax
	pushq	%rax
	lretq
.Lkernel_cs:
	UNWIND_HINT sp_reg=ORC_REG_SP sp_offset=8*9 type=UNWIND_HINT_TYPE_CALL

	/* Restore CPU status, in reverse order of saving. */
	movq	np_seamldr_saved_cr0(%rip), %rax
	movq	%rax, %cr0
	movq	$0, np_seamldr_saved_cr0(%rip)

	movq	np_seamldr_saved_cr4(%rip), %rax
	/* This changes CR4.PCIDE from 0 to 1, CR3.PCID must be 0.  Or #GP. */
	movq	%rax, %cr4
	movq	$0, np_seamldr_saved_cr4(%rip)

	popq	%rax
	movq	%rax, %cr3	/* Restore CR3.PCID */

	movq	np_seamldr_saved_gs_base(%rip), %rax
	wrgsbase %rax
	movq	$0, np_seamldr_saved_gs_base(%rip)

	popfq	/* Restore system/control flags and unmask interrupts. */

	movq	%r9, %rax	/* Return value from NP-SEAMLDR is in %r9 */

	/* Restore the callee-saved registers. */
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15

	popq	%rbp

	/* Workaround for objtool to lose the stack size. */
	UNWIND_HINT_FUNC
	ret

	/*
	 * The CPU doesn't clobber its state when an exception happens with
	 * GETSEC[EtnerACCS] because it does the exception check before
	 * switching to the ACM mode.  Although it's unnecessary to restore the
	 * not-clobbered registers, share the exit code path because this isn't
	 * a fast path.
	 *
	 * If the GETSEC[EnterACCS] instruction faulted, return -EFAULT.
	 * As NP-SEAMLDR stores the error code in %r9, store the error code to
	 * %r9 to share the exit path.
	 */
1:
	movq	$-EFAULT, %r9
	jmp	2b
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
saved_rbp:
	.quad	0

SYM_DATA(np_seamldr_saved_cr4, .quad 0)
SYM_DATA(np_seamldr_saved_cr0, .quad 0)

.data
SYM_DATA(np_seamldr_saved_gs_base, .quad 0)
