/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/unwind_hints.h>

#include <linux/linkage.h>
#include <linux/bits.h>
#include <linux/errno.h>

/*
 * Bitmasks of exposed registers (with VMM).
 */
#define TDX_R10		BIT(10)
#define TDX_R11		BIT(11)
#define TDX_R12		BIT(12)
#define TDX_R13		BIT(13)
#define TDX_R14		BIT(14)
#define TDX_R15		BIT(15)

/* Frame offset + 8 (for arg1) */
#define ARG7_SP_OFFSET		(FRAME_OFFSET + 0x08)

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

/*
 * TDX guests use the TDCALL instruction to make requests to the
 * TDX module and hypercalls to the VMM. It is supported in
 * Binutils >= 2.36.
 */
#define tdcall .byte 0x66,0x0f,0x01,0xcc

/*
 * __tdx_module_call()  - Used by TDX guests to request services from
 * the TDX module (does not include VMM services).
 *
 * Transforms function call register arguments into the TDCALL
 * register ABI.  After TDCALL operation, TDX module output is saved
 * in @out (if it is provided by the user)
 *
 *-------------------------------------------------------------------------
 * TDCALL ABI:
 *-------------------------------------------------------------------------
 * Input Registers:
 *
 * RAX                 - TDCALL Leaf number.
 * RCX,RDX,R8-R9       - TDCALL Leaf specific input registers.
 *
 * Output Registers:
 *
 * RAX                 - TDCALL instruction error code.
 * RCX,RDX,R8-R11      - TDCALL Leaf specific output registers.
 *
 *-------------------------------------------------------------------------
 *
 * __tdx_module_call() function ABI:
 *
 * @fn  (RDI)          - TDCALL Leaf ID,    moved to RAX
 * @rcx (RSI)          - Input parameter 1, moved to RCX
 * @rdx (RDX)          - Input parameter 2, moved to RDX
 * @r8  (RCX)          - Input parameter 3, moved to R8
 * @r9  (R8)           - Input parameter 4, moved to R9
 *
 * @out (R9)           - struct tdx_module_output pointer
 *                       stored temporarily in R12 (not
 *                       shared with the TDX module). It
 *                       can be NULL.
 *
 * Return status of TDCALL via RAX.
 */
SYM_FUNC_START(__tdx_module_call)
	FRAME_BEGIN

	/*
	 * R12 will be used as temporary storage for
	 * struct tdx_module_output pointer. Since R12-R15
	 * registers are not used by TDCALL services supported
	 * by this function, it can be reused.
	 */

	/* Callee saved, so preserve it */
	push %r12

	/*
	 * Push output pointer to stack.
	 * After the TDCALL operation, it will be fetched
	 * into R12 register.
	 */
	push %r9

	/* Mangle function call ABI into TDCALL ABI: */
	/* Move TDCALL Leaf ID to RAX */
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

	/* Check for TDCALL success: 0 - Successful, otherwise failed */
	test %rax, %rax
	jnz .Lno_output_struct

	/*
	 * Since this function can be initiated without an output pointer,
	 * check if caller provided an output struct before storing
	 * output registers.
	 */
	test %r12, %r12
	jz .Lno_output_struct

	/* Copy TDCALL result registers to output struct: */
	movq %rcx, TDX_MODULE_rcx(%r12)
	movq %rdx, TDX_MODULE_rdx(%r12)
	movq %r8,  TDX_MODULE_r8(%r12)
	movq %r9,  TDX_MODULE_r9(%r12)
	movq %r10, TDX_MODULE_r10(%r12)
	movq %r11, TDX_MODULE_r11(%r12)

.Lno_output_struct:
	/* Restore the state of R12 register */
	pop %r12

	FRAME_END
	ret
SYM_FUNC_END(__tdx_module_call)

/*
 * __tdx_hypercall() - Make hypercalls to a TDX VMM.
 *
 * Transforms function call register arguments into the TDCALL
 * register ABI.  After TDCALL operation, VMM output is saved in @out.
 *
 *-------------------------------------------------------------------------
 * TD VMCALL ABI:
 *-------------------------------------------------------------------------
 *
 * Input Registers:
 *
 * RAX                 - TDCALL instruction leaf number (0 - TDG.VP.VMCALL)
 * RCX                 - BITMAP which controls which part of TD Guest GPR
 *                       is passed as-is to the VMM and back.
 * R10                 - Set 0 to indicate TDCALL follows standard TDX ABI
 *                       specification. Non zero value indicates vendor
 *                       specific ABI.
 * R11                 - VMCALL sub function number
 * RBX, RBP, RDI, RSI  - Used to pass VMCALL sub function specific arguments.
 * R8-R9, R12-R15      - Same as above.
 *
 * Output Registers:
 *
 * RAX                 - TDCALL instruction status (Not related to hypercall
 *                        output).
 * R10                 - Hypercall output error code.
 * R11-R15             - Hypercall sub function specific output values.
 *
 *-------------------------------------------------------------------------
 *
 * __tdx_hypercall() function ABI:
 *
 * @type  (RDI)        - TD VMCALL type, moved to R10
 * @fn    (RSI)        - TD VMCALL sub function, moved to R11
 * @r12   (RDX)        - Input parameter 1, moved to R12
 * @r13   (RCX)        - Input parameter 2, moved to R13
 * @r14   (R8)         - Input parameter 3, moved to R14
 * @r15   (R9)         - Input parameter 4, moved to R15
 *
 * @out   (stack)      - struct tdx_hypercall_output pointer (cannot be NULL)
 *
 * On successful completion, return TDCALL status or -EINVAL for invalid
 * inputs.
 */
SYM_FUNC_START(__tdx_hypercall)
	FRAME_BEGIN

	/* Move argument 7 from caller stack to RAX */
	movq ARG7_SP_OFFSET(%rsp), %rax

	/* Check if caller provided an output struct */
	test %rax, %rax
	/* If out pointer is NULL, return -EINVAL */
	jz .Lret_err

	/* Save callee-saved GPRs as mandated by the x86_64 ABI */
	push %r15
	push %r14
	push %r13
	push %r12

	/*
	 * Save output pointer (rax) on the stack, it will be used again
	 * when storing the output registers after the TDCALL operation.
	 */
	push %rax

	/* Mangle function call ABI into TDCALL ABI: */
	/* Set TDCALL leaf ID (TDVMCALL (0)) in RAX */
	xor %eax, %eax
	/* Move TDVMCALL type (standard vs vendor) in R10 */
	mov %rdi, %r10
	/* Move TDVMCALL sub function id to R11 */
	mov %rsi, %r11
	/* Move input 1 to R12 */
	mov %rdx, %r12
	/* Move input 2 to R13 */
	mov %rcx, %r13
	/* Move input 3 to R14 */
	mov %r8,  %r14
	/* Move input 4 to R15 */
	mov %r9,  %r15

	movl $TDVMCALL_EXPOSE_REGS_MASK, %ecx

	tdcall

	/* Restore output pointer to R9 */
	pop  %r9

	/* Copy hypercall result registers to output struct: */
	movq %r10, TDX_HYPERCALL_r10(%r9)
	movq %r11, TDX_HYPERCALL_r11(%r9)
	movq %r12, TDX_HYPERCALL_r12(%r9)
	movq %r13, TDX_HYPERCALL_r13(%r9)
	movq %r14, TDX_HYPERCALL_r14(%r9)
	movq %r15, TDX_HYPERCALL_r15(%r9)

	/*
	 * Zero out registers exposed to the VMM to avoid
	 * speculative execution with VMM-controlled values.
	 * This needs to include all registers present in
	 * TDVMCALL_EXPOSE_REGS_MASK (except R12-R15).
	 * R12-R15 context will be restored.
	 */
	xor %r10d, %r10d
	xor %r11d, %r11d

	/* Restore callee-saved GPRs as mandated by the x86_64 ABI */
	pop %r12
	pop %r13
	pop %r14
	pop %r15

	jmp .Lhcall_done
.Lret_err:
       movq $-EINVAL, %rax
.Lhcall_done:
       FRAME_END

       retq
SYM_FUNC_END(__tdx_hypercall)
