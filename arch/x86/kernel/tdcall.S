/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/unwind_hints.h>
#include <asm/export.h>

#include <linux/linkage.h>

#define TDVMCALL_VENDOR_KVM		0x4d564b2e584454 /* "TDX.KVM" */
#define TDVMCALL_EXPOSE_REGS_MASK	0xfc00
#define EXIT_REASON_IO_INSTRUCTION	30
/*
 * Current size of struct tdvmcall_output is 40 bytes,
 * but allocate double to account future changes.
 */
#define TDVMCALL_OUTPUT_SIZE		80

/*
 * TDCALL instruction is newly added in TDX architecture,
 * used by TD for requesting the host VMM to provide
 * (untrusted) services. Supported in Binutils >= 2.36
 */
#ifdef CONFIG_INTEL_TDX_ICL_FIXES
#define tdcall  vmcall
#else
#define tdcall .byte 0x66,0x0f,0x01,0xcc
#endif

/* Only for non TDVMCALL use cases */
SYM_FUNC_START(__tdcall)
	FRAME_BEGIN

	/* Save/restore non-volatile GPRs that are exposed to the VMM. */
	push %r15
	push %r14
	push %r13
	push %r12

	/*
	 * RDI  => RAX = TDCALL leaf
	 * RSI  => RCX = input param 1
	 * RDX  => RDX = input param 2
	 * RCX  => N/A = output struct
	 */

	/* Save output pointer to R12 */
	mov %rcx, %r12
	/* Move TDCALL Leaf ID to RAX */
	mov %rdi, %rax
	/* Move input param 1 to rcx*/
	mov %rsi, %rcx

	tdcall

	/*
	 * On success, propagate TDCALL outputs values to the output struct,
	 * if an output struct is provided.
	 */
	test %rax, %rax
	jnz 1f
	test %r12, %r12
	jz 1f

	movq %rcx, TDCALL_rcx(%r12)
	movq %rdx, TDCALL_rdx(%r12)
	movq %r8, TDCALL_r8(%r12)
	movq %r9, TDCALL_r9(%r12)
	movq %r10, TDCALL_r10(%r12)
	movq %r11, TDCALL_r11(%r12)
1:
	/*
	 * Zero out registers exposed to the VMM to avoid speculative execution
	 * with VMM-controlled values.
	 */
        xor %rcx, %rcx
        xor %rdx, %rdx
        xor %r8d, %r8d
        xor %r9d, %r9d
        xor %r10d, %r10d
        xor %r11d, %r11d

	pop %r12
	pop %r13
	pop %r14
	pop %r15

	FRAME_END
	ret
SYM_FUNC_END(__tdcall)

SYM_CODE_START_LOCAL(do_tdvmcall)
	FRAME_BEGIN

	/* Save/restore non-volatile GPRs that are exposed to the VMM. */
	push %r15
	push %r14
	push %r13
	push %r12

	/*
	 * 0    => RAX = TDCALL leaf
	 * RDI  => R11 = TDVMCALL function, e.g. exit reason
	 * RSI  => R12 = input param 0
	 * RDX  => R13 = input param 1
	 * RCX  => R14 = input param 2
	 * R8   => R15 = input param 3
	 * MASK => RCX = TDVMCALL register behavior
	 * R9   => R9  = output struct
	 */

	xor %eax, %eax
	mov %rdi, %r11
	mov %rsi, %r12
	mov %rdx, %r13
	mov %rcx, %r14
	mov %r8,  %r15

	/*
	 * Expose R10 - R15, i.e. all GPRs that may be used by TDVMCALLs
	 * defined in the GHCI.  Note, RAX and RCX are consumed, but only by
	 * TDX-Module and so don't need to be listed in the mask.
	 */
	movl $TDVMCALL_EXPOSE_REGS_MASK, %ecx

	tdcall

	/* Panic if TDCALL reports failure. */
	test %rax, %rax
	jnz 2f

	/* Propagate TDVMCALL success/failure to return value. */
	mov %r10, %rax

	/*
	 * On success, propagate TDVMCALL outputs values to the output struct,
	 * if an output struct is provided.
	 */
	test %rax, %rax
	jnz 1f
	test %r9, %r9
	jz 1f

	movq %r11, TDVMCALL_r11(%r9)
	movq %r12, TDVMCALL_r12(%r9)
	movq %r13, TDVMCALL_r13(%r9)
	movq %r14, TDVMCALL_r14(%r9)
	movq %r15, TDVMCALL_r15(%r9)
1:
	/*
	 * Zero out registers exposed to the VMM to avoid speculative execution
	 * with VMM-controlled values.
	 */
	xor %r10d, %r10d
	xor %r11d, %r11d
	xor %r12d, %r12d
	xor %r13d, %r13d
	xor %r14d, %r14d
	xor %r15d, %r15d

	pop %r12
	pop %r13
	pop %r14
	pop %r15

	FRAME_END
	ret
2:
	ud2
SYM_CODE_END(do_tdvmcall)

SYM_FUNC_START(__tdvmcall)
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

SYM_FUNC_START(tdg_outb)
	io_save_registers
	xor %r8, %r8
	mov %al, %r8b
	mov $1, %rsi
	jmp 1f

SYM_FUNC_START(tdg_outw)
	io_save_registers
	xor %r8, %r8
	mov %ax, %r8w
	mov $2, %rsi
	jmp 1f

SYM_FUNC_START(tdg_outl)
	io_save_registers
	xor %r8, %r8
	mov %eax, %r8d
	mov $4, %rsi
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
	call tdg_allowed_port
	pop %rdx
	test %al, %al
	jz out_tdg_out
#endif

	/*
	 * 0             => RAX = TDCALL Standard leaf
	 * TDVMCALL FN   => RDI = TDVMCALL function, e.g. exit reason
	 * Width(1/2/4)  => RSI = input param 0
	 * OUT/IN(1/0)   => RDX = input param 1
	 * RDX (Port)    => RCX = input param 2
	 * RAX (value)   => R8  = input param 3
	 * NULL          => R9  = output struct
	 */

	mov %rdx, %rcx
	mov $1, %rdx
	mov $EXIT_REASON_IO_INSTRUCTION, %rdi
	xor %r10, %r10
	xor %r9, %r9
	call do_tdvmcall

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

SYM_FUNC_START(tdg_inb)
	io_save_registers
	mov $1, %rsi
	jmp 1f

SYM_FUNC_START(tdg_inw)
	io_save_registers
	mov $2, %rsi
	jmp 1f

SYM_FUNC_START(tdg_inl)
	io_save_registers
	mov $4, %rsi
1:
#ifndef TDG_SKIP_IO_FILTERING
	push %rdx
	mov %dx, %di
	call tdg_allowed_port
	pop %rdx
	test %al, %al
	jz out_tdg_in
#endif

	/*
	 * 0            => RAX = TDCALL Standard leaf
	 * TDVMCALL FN  => RDI = TDVMCALL function, e.g. exit reason
	 * Width(1/2/4) => RSI = input param 0
	 * OUT/IN(1/0)  => RDX = input param 1
	 * RDX (Port) 	=> RCX = input param 2
	 * Output ptr   => R9  = output struct
	 */

	mov %rdx, %rcx
	mov $0, %rdx
	mov $EXIT_REASON_IO_INSTRUCTION, %rdi
	xor %r10, %r10
	/* Allocate memory in stack for Output */
	subq $TDVMCALL_OUTPUT_SIZE, %rsp
	movq %rsp, %r9
	call do_tdvmcall

out_tdg_in:
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
