/* SPDX-License-Identifier: GPL-2.0 */
/* ASM helper to call SEAMCALL for P-SEAMLDR, TDX module */

#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/asm-offsets.h>
#include <asm/frame.h>
#include <asm/asm.h>

#include "seamcall.h"

/*
 * kvm_seamcall - helper function to invoke SEAMCALL to request service
 *		  of TDX module for KVM.
 *
 * @op  (RDI)   SEAMCALL leaf ID
 * @rcx (RSI)   input 1 (optional based on leaf ID)
 * @rdx (RDX)   input 2 (optional based on leaf ID)
 * @r8  (RCX)   input 3 (optional based on leaf ID)
 * @r9  (R8)    input 4 (optional based on leaf ID)
 * @r10 (R9)    input 5 (optional based on leaf ID)
 * @ex  stack   pointer to struct tdx_ex_ret. optional return value stored.
 *
 * @return RAX: completion code of P-SEAMLDR or TDX module
 *		0 on success, non-0 on failure
 *		trapnumber on fault
 */
SYM_FUNC_START(kvm_seamcall)
	FRAME_BEGIN

	/* shuffle registers from function call ABI to SEAMCALL ABI. */
	movq	%r9, %r10
	movq	%r8, %r9
	movq	%rcx, %r8
	/* %rdx doesn't need shuffle. */
	movq	%rsi, %rcx
	movq	%rdi, %rax

1:
	seamcall

	/*
	 * Store extra returned values into ex.  Some registers
	 * may be unused depending on SEAMCALL functions.
	 */
	movq	(FRAME_OFFSET + 8)(%rsp), %rdi

	movq	%rcx, TDX_SEAM_rcx(%rdi)
	movq	%rdx, TDX_SEAM_rdx(%rdi)
	movq	%r8,  TDX_SEAM_r8(%rdi)
	movq	%r9,  TDX_SEAM_r9(%rdi)
	movq	%r10, TDX_SEAM_r10(%rdi)
	movq	%r11, TDX_SEAM_r11(%rdi)

2:
	FRAME_END
	ret

.pushsection .fixup, "ax"
	/* The seamcall instruction above can cause an exception. */
3:
	call	kvm_spurious_fault
	jmp	2b
.popsection
	_ASM_EXTABLE(1b, 3b)
SYM_FUNC_END(kvm_seamcall)
