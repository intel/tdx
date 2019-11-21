/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/unwind_hints.h>

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

/*
 * TDX guests use the TDCALL instruction to make requests to the
 * TDX module and hypercalls to the VMM. It is supported in
 * Binutils >= 2.36.
 */
#define tdcall .byte 0x66,0x0f,0x01,0xcc

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

	tdcall

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

	tdcall

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
