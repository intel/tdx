/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/unwind_hints.h>
#include <asm/export.h>

#include <linux/linkage.h>

/*
 * Expose registers R10-R15 to VMM (for bitfield info
 * refer to TDX GHCI specification).
 */
#define TDVMCALL_EXPOSE_REGS_MASK	0xfc00
#define TDVMCALL_VENDOR_KVM		0x4d564b2e584454 /* "TDX.KVM" */
#define EXIT_REASON_IO_INSTRUCTION	30
/*
 * Current size of struct tdvmcall_output is 40 bytes,
 * but allocate double to account future changes.
 */
#define TDVMCALL_OUTPUT_SIZE		80

/*
 * TDX guests use the TDCALL instruction to make
 * hypercalls to the VMM. It is supported in
 * Binutils >= 2.36.
 */
#define tdcall .byte 0x66,0x0f,0x01,0xcc

/*
 * __tdcall()  - Used to communicate with the TDX module
 *
 * @arg1 (RDI) - TDCALL Leaf ID
 * @arg2 (RSI) - Input parameter 1 passed to TDX module
 *               via register RCX
 * @arg2 (RDX) - Input parameter 2 passed to TDX module
 *               via register RDX
 * @arg3 (RCX) - Input parameter 3 passed to TDX module
 *               via register R8
 * @arg4 (R8)  - Input parameter 4 passed to TDX module
 *               via register R9
 * @arg5 (R9)  - struct tdcall_output pointer
 *
 * @out        - Return status of tdcall via RAX.
 *
 * NOTE: This function should only used for non TDVMCALL
 *       use cases
 */
SYM_FUNC_START(__tdcall)
	FRAME_BEGIN

	/* Save non-volatile GPRs that are exposed to the VMM. */
	push %r15
	push %r14
	push %r13
	push %r12

	/* Move TDCALL Leaf ID to RAX */
	mov %rdi, %rax
	/* Move output pointer to R12 */
	mov %r9, %r12
	/* Move input param 4 to R9 */
	mov %r8, %r9
	/* Move input param 3 to R8 */
	mov %rcx, %r8
	/* Leave input param 2 in RDX */
	/* Move input param 1 to RCX */
	mov %rsi, %rcx

	tdcall

	/* Check for TDCALL success: 0 - Successful, otherwise failed */
	test %rax, %rax
	jnz 1f

	/* Check for a TDCALL output struct */
	test %r12, %r12
	jz 1f

	/* Copy TDCALL result registers to output struct: */
	movq %rcx, TDCALL_rcx(%r12)
	movq %rdx, TDCALL_rdx(%r12)
	movq %r8,  TDCALL_r8(%r12)
	movq %r9,  TDCALL_r9(%r12)
	movq %r10, TDCALL_r10(%r12)
	movq %r11, TDCALL_r11(%r12)
1:
	/* Zero out registers exposed to the TDX Module. */
	xor %rcx,  %rcx
	xor %rdx,  %rdx
	xor %r8d,  %r8d
	xor %r9d,  %r9d
	xor %r10d, %r10d
	xor %r11d, %r11d

	/* Restore non-volatile GPRs that are exposed to the VMM. */
	pop %r12
	pop %r13
	pop %r14
	pop %r15

	FRAME_END
	ret
SYM_FUNC_END(__tdcall)

/*
 * do_tdvmcall()  - Used to communicate with the VMM.
 *
 * @arg1 (RDI)    - TDVMCALL function, e.g. exit reason
 * @arg2 (RSI)    - Input parameter 1 passed to VMM
 *                  via register R12
 * @arg3 (RDX)    - Input parameter 2 passed to VMM
 *                  via register R13
 * @arg4 (RCX)    - Input parameter 3 passed to VMM
 *                  via register R14
 * @arg5 (R8)     - Input parameter 4 passed to VMM
 *                  via register R15
 * @arg6 (R9)     - struct tdvmcall_output pointer
 *
 * @out           - Return status of tdvmcall(R10) via RAX.
 *
 */
SYM_CODE_START_LOCAL(do_tdvmcall)
	FRAME_BEGIN

	/* Save non-volatile GPRs that are exposed to the VMM. */
	push %r15
	push %r14
	push %r13
	push %r12

	/* Set TDCALL leaf ID to TDVMCALL (0) in RAX */
	xor %eax, %eax
	/* Move TDVMCALL function id (1st argument) to R11 */
	mov %rdi, %r11
	/* Move Input parameter 1-4 to R12-R15 */
	mov %rsi, %r12
	mov %rdx, %r13
	mov %rcx, %r14
	mov %r8,  %r15
	/* Leave tdvmcall output pointer in R9 */

	/*
	 * Value of RCX is used by the TDX Module to determine which
	 * registers are exposed to VMM. Each bit in RCX represents a
	 * register id. You can find the bitmap details from TDX GHCI
	 * spec.
	 */
	movl $TDVMCALL_EXPOSE_REGS_MASK, %ecx

	tdcall

	/*
	 * Check for TDCALL success: 0 - Successful, otherwise failed.
	 * If failed, there is an issue with TDX Module which is fatal
	 * for the guest. So panic.
	 */
	test %rax, %rax
	jnz 2f

	/* Move TDVMCALL success/failure to RAX to return to user */
	mov %r10, %rax

	/* Check for TDVMCALL success: 0 - Successful, otherwise failed */
	test %rax, %rax
	jnz 1f

	/* Check for a TDVMCALL output struct */
	test %r9, %r9
	jz 1f

	/* Copy TDVMCALL result registers to output struct: */
	movq %r11, TDVMCALL_r11(%r9)
	movq %r12, TDVMCALL_r12(%r9)
	movq %r13, TDVMCALL_r13(%r9)
	movq %r14, TDVMCALL_r14(%r9)
	movq %r15, TDVMCALL_r15(%r9)
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
SYM_CODE_END(do_tdvmcall)

/* Helper function for standard type of TDVMCALL */
SYM_FUNC_START(__tdvmcall)
	/* Set TDVMCALL type info (0 - Standard, > 0 - vendor) in R10 */
	xor %r10, %r10
	call do_tdvmcall
	retq
SYM_FUNC_END(__tdvmcall)

SYM_FUNC_START(__tdvmcall_vendor_kvm)
	movq $TDVMCALL_VENDOR_KVM, %r10
	call do_tdvmcall
	retq
SYM_FUNC_END(__tdvmcall_vendor_kvm)

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
 * tdg_out{b,w,l}()  - Write given data to the specified port.
 *
 * @arg1 (RAX)       - Value to be written (passed via R8 to do_tdvmcall()).
 * @arg2 (RDX)       - Port id (passed via RCX to do_tdvmcall()).
 *
 */
SYM_FUNC_START(tdg_outb)
	io_save_registers
	xor %r8, %r8
	/* Move data to R8 register */
	mov %al, %r8b
	/* Set data width to 1 byte */
	mov $1, %rsi
	jmp 1f

SYM_FUNC_START(tdg_outw)
	io_save_registers
	xor %r8, %r8
	/* Move data to R8 register */
	mov %ax, %r8w
	/* Set data width to 2 bytes */
	mov $2, %rsi
	jmp 1f

SYM_FUNC_START(tdg_outl)
	io_save_registers
	xor %r8, %r8
	/* Move data to R8 register */
	mov %eax, %r8d
	/* Set data width to 4 bytes */
	mov $4, %rsi
1:
	/*
	 * Since io_save_registers does not save rax
	 * state, save it here so that we can preserve
	 * the caller register state.
	 */
	push %rax

	mov %rdx, %rcx
	/* Set 1 in RDX to select out operation */
	mov $1, %rdx
	/* Set TDVMCALL function id in RDI */
	mov $EXIT_REASON_IO_INSTRUCTION, %rdi
	/* Set TDVMCALL type info (0 - Standard, > 0 - vendor) in R10 */
	xor %r10, %r10
	/* Since we don't use tdvmcall output, set it to NULL */
	xor %r9, %r9

	call do_tdvmcall

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
 * tdg_in{b,w,l}()   - Read data to the specified port.
 *
 * @arg1 (RDX)       - Port id (passed via RCX to do_tdvmcall()).
 *
 * Returns data read via RAX register.
 *
 */
SYM_FUNC_START(tdg_inb)
	io_save_registers
	/* Set data width to 1 byte */
	mov $1, %rsi
	jmp 1f

SYM_FUNC_START(tdg_inw)
	io_save_registers
	/* Set data width to 2 bytes */
	mov $2, %rsi
	jmp 1f

SYM_FUNC_START(tdg_inl)
	io_save_registers
	/* Set data width to 4 bytes */
	mov $4, %rsi
1:
	mov %rdx, %rcx
	/* Set 0 in RDX to select in operation */
	mov $0, %rdx
	/* Set TDVMCALL function id in RDI */
	mov $EXIT_REASON_IO_INSTRUCTION, %rdi
	/* Set TDVMCALL type info (0 - Standard, > 0 - vendor) in R10 */
	xor %r10, %r10
	/* Allocate memory in stack for Output */
	subq $TDVMCALL_OUTPUT_SIZE, %rsp
	/* Move tdvmcall_output pointer to R9 */
	movq %rsp, %r9

	call do_tdvmcall

	/* Move data read from port to RAX */
	mov TDVMCALL_r11(%r9), %eax
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
