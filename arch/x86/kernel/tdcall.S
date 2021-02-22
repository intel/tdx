/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/unwind_hints.h>

#include <linux/linkage.h>

#define TDVMCALL_EXPOSE_REGS_MASK	0xfc00

/*
 * TDCALL instruction is newly added in TDX architecture,
 * used by TD for requesting the host VMM to provide
 * (untrusted) services. Supported in Binutils >= 2.36
 */
#define tdcall .byte 0x66,0x0f,0x01,0xcc

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
