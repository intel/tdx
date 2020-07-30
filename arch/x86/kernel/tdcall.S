/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/unwind_hints.h>
#include <asm/export.h>

#include <linux/linkage.h>
#include <linux/bits.h>

#define TDG_R10		BIT(10)
#define TDG_R11		BIT(11)
#define TDG_R12		BIT(12)
#define TDG_R13		BIT(13)
#define TDG_R14		BIT(14)
#define TDG_R15		BIT(15)

/*
 * Expose registers R10-R15 to VMM. It is passed via RCX register
 * to the TDX Module, which will be used by the TDX module to
 * identify the list of registers exposed to VMM. Each bit in this
 * mask represents a register ID. You can find the bit field details
 * in TDX GHCI specification.
 */
#define TDVMCALL_EXPOSE_REGS_MASK	( TDG_R10 | TDG_R11 | \
					  TDG_R12 | TDG_R13 | \
					  TDG_R14 | TDG_R15 )

#define TDVMCALL_VENDOR_KVM		0x4d564b2e584454 /* "TDX.KVM" */
#define EXIT_REASON_IO_INSTRUCTION	30
/*
 * Current size of struct tdx_hypercall_output is 40 bytes,
 * but allocate double to account future changes.
 */
#define TDVMCALL_OUTPUT_SIZE		80

/* For IN instruction failure return all 1s */
#define IO_IN_FAILED_RET_VALUE		0xfffffffff

/*
 * TDX guests use the TDCALL instruction to make requests to the
 * TDX module and hypercalls to the VMM. It is supported in
 * Binutils >= 2.36.
 */
#ifdef CONFIG_INTEL_TDX_ICL_FIXES
#define tdcall  vmcall
#else
#define tdcall .byte 0x66,0x0f,0x01,0xcc
#endif

.macro trace_save_registers
	push %rax
	push %rcx
	push %rdx
	push %rdi
	push %rsi
	push %r8
	push %r9
	push %r10
	push %r11
.endm
.macro trace_restore_registers
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rsi
	pop %rdi
	pop %rdx
	pop %rcx
	pop %rax
.endm

/*
 * Wrapper macros to mangle TDCALL registers into format acceptable
 * for making call to _trace_tdx_module_call_{enter()/exit()}
 * functions. After tracepoint call, register state is restored to
 * previous state.
 */
.macro trace_module_call_enter
	/* Save register context before calling tracepoint */
	trace_save_registers
	mov %rax, %rdi /* Move TDCALL leaf ID to RDI */
	mov %rcx, %rsi /* Move input 1 to RSI */
	mov %rdx, %rdx /* Move input 2 to RDX */
	mov %r8,  %rcx /* Move input 3 to RCX */
	mov %r9,  %r8  /* Move input 4 to R8  */
	call _trace_tdx_module_call_enter /* Call tracepoint hook */
	/* Restore register context after calling tracepoint */
	trace_restore_registers
.endm

.macro trace_module_call_exit
	/* Save register context before calling tracepoint */
	trace_save_registers
	mov %rax, %rdi /* Move TDCALL status to RDI */
	mov %rcx, %rsi /* Move output 1 to RSI */
	mov %rdx, %rdx /* Move output 2 to RDX */
	mov %r8,  %rcx /* Move output 3 to RCX */
	mov %r9,  %r8  /* Move output 4 to R8  */
	mov %r10, %r9  /* Move output 5 to R9  */
	pushq %r11     /* Move output 6 to stack */
	call _trace_tdx_module_call_exit /* Call tracepoint hook */
	popq %r11      /* Remove output 6 stack allocation */
	/* Restore register context after calling tracepoint */
	trace_restore_registers
.endm

/*
 * Wrapper macros to mangle TDCALL registers into format acceptable
 * for making call to _trace_tdx_hypercall{enter()/exit()} function.
 * After tracepoint call, register state is restored to previous
 * state.
 */
.macro trace_hypercall_enter
	/* Save register context before calling tracepoint */
	trace_save_registers
	/* Mangle TDCALL ABI into trace function ABI */
	mov %r11, %rdi /* Move TDG.VP.VMCALL subid to RDI */
	mov %r12, %rsi /* Move input 1 to RSI */
	mov %r13, %rdx /* Move input 2 to RDX */
	mov %r14, %rcx /* Move input 3 to RCX */
	mov %r15, %r8  /* Move input 4 to R8  */
	call _trace_tdx_hypercall_enter /* Call tracepoint hook */
	/* Restore register context after calling tracepoint */
	trace_restore_registers
.endm

.macro trace_hypercall_exit
	/* Save register context before calling tracepoint */
	trace_save_registers
	/* Mangle TDCALL ABI into trace function ABI */
	mov %r10, %rdi /* Move TDG.VP.VMCALL return ID to RDI */
	mov %r11, %rsi /* Move output 1 to RSI */
	mov %r12, %rdx /* Move output 2 to RDX */
	mov %r13, %rcx /* Move output 3 to RCX */
	mov %r14, %r8  /* Move output 4 to R8  */
	mov %r15, %r9  /* Move output 5 to R9  */
	call _trace_tdx_hypercall_exit /* Call tracepoint hook */
	/* Restore register context after calling tracepoint */
	trace_restore_registers
.endm

/*
 * __tdx_module_call()  - Helper function used by TDX guests to request
 * services from the TDX module (does not include VMM services).
 *
 * This function serves as a wrapper to move user call arguments to the
 * correct registers as specified by "tdcall" ABI and shares it with the
 * TDX module.  And if the "tdcall" operation is successful and a valid
 * "struct tdx_module_output" pointer is available (in "out" argument),
 * output from the TDX module is saved to the memory specified in the
 * "out" pointer. Also the status of the "tdcall" operation is returned
 * back to the user as a function return value.
 *
 * @fn  (RDI)		- TDCALL Leaf ID,    moved to RAX
 * @rcx (RSI)		- Input parameter 1, moved to RCX
 * @rdx (RDX)		- Input parameter 2, moved to RDX
 * @r8  (RCX)		- Input parameter 3, moved to R8
 * @r9  (R8)		- Input parameter 4, moved to R9
 *
 * @out (R9)		- struct tdx_module_output pointer
 *			  stored temporarily in R12 (not
 * 			  shared with the TDX module)
 *
 * Return status of tdcall via RAX.
 *
 * NOTE: This function should not be used for TDX hypercall
 *       use cases.
 */
SYM_FUNC_START(__tdx_module_call)
	FRAME_BEGIN

	/*
	 * R12 will be used as temporary storage for
	 * struct tdx_module_output pointer. You can
	 * find struct tdx_module_output details in
	 * arch/x86/include/asm/tdx.h. Also note that
	 * registers R12-R15 are not used by TDCALL
	 * services supported by this helper function.
	 */
	push %r12	/* Callee saved, so preserve it */
	mov %r9,  %r12 	/* Move output pointer to R12 */

	/* Mangle function call ABI into TDCALL ABI: */
	mov %rdi, %rax	/* Move TDCALL Leaf ID to RAX */
	mov %r8,  %r9	/* Move input 4 to R9 */
	mov %rcx, %r8	/* Move input 3 to R8 */
	mov %rsi, %rcx	/* Move input 1 to RCX */
	/* Leave input param 2 in RDX */

	/*
	 * TDG_SKIP_TRACE_SUPPORT macro is used to disable
	 * tracing support in compressed boot code. Since
	 * this file is included in arch/x86/boot/compressed/tdcall.S
	 * and tracepoint support cannot be enabled in compressed
	 * boot code, TDG_SKIP_TRACE_SUPPORT macro will be defined
	 * in compressed boot code.
	 */
#ifndef TDG_SKIP_TRACE_SUPPORT
	/*
	 * Call TDCALL trace point. Although this operation
	 * is costly in TDCALL code path, but still it is
	 * negligible compared to TDCALL instruction.
	 */
	trace_module_call_enter
#endif

	tdcall

#ifndef TDG_SKIP_TRACE_SUPPORT
	trace_module_call_exit
#endif

	/* Check for TDCALL success: 0 - Successful, otherwise failed */
	test %rax, %rax
	jnz 1f

	/* Check for TDCALL output struct != NULL */
	test %r12, %r12
	jz 1f

	/* Copy TDCALL result registers to output struct: */
	movq %rcx, TDX_MODULE_rcx(%r12)
	movq %rdx, TDX_MODULE_rdx(%r12)
	movq %r8,  TDX_MODULE_r8(%r12)
	movq %r9,  TDX_MODULE_r9(%r12)
	movq %r10, TDX_MODULE_r10(%r12)
	movq %r11, TDX_MODULE_r11(%r12)
1:
	pop %r12 /* Restore the state of R12 register */

	FRAME_END
	ret
SYM_FUNC_END(__tdx_module_call)

/*
 * do_tdx_hypercall()  - Helper function used by TDX guests to request
 * services from the VMM. All requests are made via the TDX module
 * using "TDCALL" instruction.
 *
 * This function is created to contain common between vendor specific
 * and standard type tdx hypercalls. So the caller of this function had
 * to set the TDVMCALL type in the R10 register before calling it.
 *
 * This function serves as a wrapper to move user call arguments to the
 * correct registers as specified by "tdcall" ABI and shares it with VMM
 * via the TDX module. And if the "tdcall" operation is successful and a
 * valid "struct tdx_hypercall_output" pointer is available (in "out"
 * argument), output from the VMM is saved to the memory specified in the
 * "out" pointer. 
 *
 * @fn  (RDI)		- TDVMCALL function, moved to R11
 * @r12 (RSI)		- Input parameter 1, moved to R12
 * @r13 (RDX)		- Input parameter 2, moved to R13
 * @r14 (RCX)		- Input parameter 3, moved to R14
 * @r15 (R8)		- Input parameter 4, moved to R15
 *
 * @out (R9)		- struct tdx_hypercall_output pointer
 *
 * On successful completion, return TDX hypercall error code.
 * If the "tdcall" operation fails, panic.
 *
 */
SYM_FUNC_START_LOCAL(do_tdx_hypercall)
	FRAME_BEGIN

	/* Save non-volatile GPRs that are exposed to the VMM. */
	push %r15
	push %r14
	push %r13
	push %r12

	/* Leave hypercall output pointer in R9, it's not clobbered by VMM */

	/* Mangle function call ABI into TDCALL ABI: */
	xor %eax, %eax /* Move TDCALL leaf ID (TDVMCALL (0)) to RAX */
	mov %rdi, %r11 /* Move TDVMCALL function id to R11 */
	mov %rsi, %r12 /* Move input 1 to R12 */
	mov %rdx, %r13 /* Move input 2 to R13 */
	mov %rcx, %r14 /* Move input 1 to R14 */
	mov %r8,  %r15 /* Move input 1 to R15 */
	/* Caller of do_tdx_hypercall() will set TDVMCALL type in R10 */

	movl $TDVMCALL_EXPOSE_REGS_MASK, %ecx

	/*
	 * TDG_SKIP_TRACE_SUPPORT macro is used to disable
	 * tracing support in compressed boot code. Since
	 * this file is included in arch/x86/boot/compressed/tdcall.S
	 * and tracepoint support cannot be enabled in compressed
	 * boot code, TDG_SKIP_TRACE_SUPPORT macro will be defined
	 * in compressed boot code.
	 */
#ifndef TDG_SKIP_TRACE_SUPPORT
	/*
	 * Call TDCALL trace point. Although this operation
	 * is costly in TDVMCALL code path, but still it is
	 * negligible compared to TDCALL instruction.
	 */
	trace_hypercall_enter
#endif

	tdcall

#ifndef TDG_SKIP_TRACE_SUPPORT
	trace_hypercall_exit
#endif
	/*
	 * Check for TDCALL success: 0 - Successful, otherwise failed.
	 * If failed, there is an issue with TDX Module which is fatal
	 * for the guest. So panic. Also note that RAX is controlled
	 * only by the TDX module and not exposed to VMM.
	 */
	test %rax, %rax
	jnz 2f

	/* Move hypercall error code to RAX to return to user */
	mov %r10, %rax

	/* Check for hypercall success: 0 - Successful, otherwise failed */
	test %rax, %rax
	jnz 1f

	/* Check for hypercall output struct != NULL */
	test %r9, %r9
	jz 1f

	/* Copy hypercall result registers to output struct: */
	movq %r11, TDX_HYPERCALL_r11(%r9)
	movq %r12, TDX_HYPERCALL_r12(%r9)
	movq %r13, TDX_HYPERCALL_r13(%r9)
	movq %r14, TDX_HYPERCALL_r14(%r9)
	movq %r15, TDX_HYPERCALL_r15(%r9)
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
SYM_FUNC_END(do_tdx_hypercall)

/* Helper function for standard type of TDVMCALL */
SYM_FUNC_START(__tdx_hypercall)
	/* Set TDVMCALL type info (0 - Standard, > 0 - vendor) in R10 */
	xor %r10, %r10
	call do_tdx_hypercall
	retq
SYM_FUNC_END(__tdx_hypercall)

/* Helper function for KVM vendor TDVMCALLs */
SYM_FUNC_START(__tdx_hypercall_vendor_kvm)
	movq $TDVMCALL_VENDOR_KVM, %r10
	call do_tdx_hypercall
	retq
SYM_FUNC_END(__tdx_hypercall_vendor_kvm)

.macro io_save_registers
	push %rbp
	push %rbx
	push %rcx
	push %rdx
	push %rdi
	push %rsi
	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15
.endm
.macro io_restore_registers
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rsi
	pop %rdi
	pop %rdx
	pop %rcx
	pop %rbx
	pop %rbp
.endm

/*
 * tdg_out{b,w,l}()  - Write given data to the specified port. It sets
 *		       registers in correct format acceptable to call
 *		       do_tdx_hypercall().
 *
 * RAX       - Value to be written (passed via R8 to do_tdx_hypercall()).
 * RDX       - Port id (passed via RCX to do_tdx_hypercall()).
 *
 */
SYM_FUNC_START(tdg_outb)
	io_save_registers
	xor %r8, %r8
	mov %al, %r8b		/* Move data to R8 */
	mov $1, %rsi		/* Set data width to 1 byte */
	jmp 1f

SYM_FUNC_START(tdg_outw)
	io_save_registers
	xor %r8, %r8
	mov %ax, %r8w		/* Move data to R8 */
	mov $2, %rsi		/* Set data width to 2 bytes */
	jmp 1f

SYM_FUNC_START(tdg_outl)
	io_save_registers
	xor %r8, %r8
	mov %eax, %r8d		/* Move data to R8 */
	mov $4, %rsi		/* Set data width to 4 bytes */
1:
	/*
	 * Since io_save_registers does not save rax
	 * state, save it here so that we can preserve
	 * the caller register state.
	 */
	push %rax

#ifndef TDG_SKIP_IO_FILTERING
	push %rdx
	mov %dx, %di
	/* Check whether given port is allowed */
	call tdg_allowed_port
	pop %rdx
	/* Check for status of tdg_allowed_port() */
	test %al, %al
	jz out_tdg_out
#endif

	mov %rdx, %rcx
	/* Set 1 in RDX to select out operation */
	mov $1, %rdx
	/* Set TDVMCALL function id in RDI */
	mov $EXIT_REASON_IO_INSTRUCTION, %rdi
	/* Set TDVMCALL type info (0 - Standard, > 0 - vendor) in R10 */
	xor %r10, %r10
	/* Since we don't use tdx_hypercall output, set it to NULL */
	xor %r9, %r9

	call do_tdx_hypercall

out_tdg_out:
	pop %rax
	io_restore_registers
	ret
SYM_FUNC_END(tdg_outb)
SYM_FUNC_END(tdg_outw)
SYM_FUNC_END(tdg_outl)
EXPORT_SYMBOL(tdg_outb)
EXPORT_SYMBOL(tdg_outw)
EXPORT_SYMBOL(tdg_outl)

/*
 * tdg_in{b,w,l}()   - Read data to the specified port. It sets
 *		       registers in correct format acceptable to call
 *		       do_tdx_hypercall().
 *
 * RDX       - Port id (passed via RCX to do_tdx_hypercall()).
 *
 * Returns data read via RAX register.
 *
 */
SYM_FUNC_START(tdg_inb)
	io_save_registers
	mov $1, %rsi		/* Set data width to 1 byte */
	jmp 1f

SYM_FUNC_START(tdg_inw)
	io_save_registers
	mov $2, %rsi		/* Set data width to 2 bytes */
	jmp 1f

SYM_FUNC_START(tdg_inl)
	io_save_registers
	mov $4, %rsi		/* Set data width to 4 bytes */
1:
	/* Allocate memory in stack for struct tdx_hypercall_output */
	subq $TDVMCALL_OUTPUT_SIZE, %rsp
	/* R9 is not clobbered by VMM, So use it as temporary storage */
	movq %rsp, %r9

#ifndef TDG_SKIP_IO_FILTERING
	push %rdx
	mov %dx, %di
	/* Check whether given port is allowed */
	call tdg_allowed_port
	pop %rdx
	/* Check for status of tdg_allowed_port() */
	test %al, %al
	jz tdg_in_failed
#endif

	mov %rdx, %rcx
	/* Set 0 in RDX to select IN operation */
	mov $0, %rdx
	/* Set TDVMCALL function id in RDI */
	mov $EXIT_REASON_IO_INSTRUCTION, %rdi
	/* Set TDVMCALL type info (0 - Standard, > 0 - vendor) in R10 */
	xor %r10, %r10

	call do_tdx_hypercall

	/* Check for success of TDVMCALL */
	test %rax, %rax
	jnz tdg_in_failed

	/* Move data read from port to RAX */
	mov TDX_HYPERCALL_r11(%r9), %eax

	jmp out_tdg_in

tdg_in_failed:
	/* For failed "in" instruction return 0xff */
	mov $IO_IN_FAILED_RET_VALUE, %rax

out_tdg_in:
	/* Free allocated memory */
	addq $TDVMCALL_OUTPUT_SIZE, %rsp
	io_restore_registers
	ret
SYM_FUNC_END(tdg_inb)
SYM_FUNC_END(tdg_inw)
SYM_FUNC_END(tdg_inl)
EXPORT_SYMBOL(tdg_inb)
EXPORT_SYMBOL(tdg_inw)
EXPORT_SYMBOL(tdg_inl)
