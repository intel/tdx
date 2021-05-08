/* SPDX-License-Identifier: GPL-2.0 */
/* ASM helper to call SEAMCALL for P-SEAMLDR, TDX module */

#include <linux/linkage.h>

#include <asm/asm-offsets.h>
#include <asm/tdx_errno.h>
#include <asm/frame.h>
#include <asm/asm.h>

.macro seamcall
	.byte 0x66, 0x0f, 0x01, 0xcf
.endm

/*
 * u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
 *                struct tdx_ex_ret *ex);
 * A helper function to invoke SEAMCALL to request service for the
 * P-SEAMLDR or the "TDX module".
 *
 * @op  (RDI)   SEAMCALL leaf ID
 * @rcx (RSI)   input 1 (optional based on leaf ID)
 * @rdx (RDX)   input 2 (optional based on leaf ID)
 * @r8  (RCX)   input 3 (optional based on leaf ID)
 * @r9  (R8)    input 4 (optional based on leaf ID)
 * @ex  (R9)    pointer to struct tdx_ex_ret. optional returned values stored.
 *
 * @return RAX: completion code of P-SEAMLDR or TDX module
 *              0 on success, non-0 on failure, trap number on fault.
 */
SYM_FUNC_START(__seamcall)
	FRAME_BEGIN

	/* save ex to use after the seamcall instruction. */
	pushq	%r9

	/*
	 * shuffle registers from the function
	 * call ABI to the SEAMCALL ABI.
	 */
	movq	%r8,  %r9
	movq	%rcx, %r8
	/* %rdx doesn't need shuffle. */
	movq	%rsi, %rcx
	movq	%rdi, %rax

	seamcall
	/*
	 * In error case that the TDX firmware(the TDX module and the P-SEAMLDR)
	 * isn't loaded, CF=1, {PF, AF, ZF, SF, OF} = 0 and returns back to an
	 * OS.
	 *
	 * In success case that seamret from the TDX firmware to an OS,
	 * {CF, PF, AF, ZF, SF, OF} = 0 and %RAX: instruction return code.
	 *
	 * The value of TDX_SEAMCALL_VMFAILINVALID is chosen so that it does not
	 * conflict with any TDX status codes and any P-SEAMLDR error codes.
	 */
	jnb	1f
	mov	$TDX_SEAMCALL_VMFAILINVALID, %rax

	/*
	 * Store extra returned values into ex.  Some registers
	 * may be unused depending on SEAMCALL functions.
	 */
1:	popq	%rdi
	movq	%rcx, TDX_SEAM_rcx(%rdi)
	movq	%rdx, TDX_SEAM_rdx(%rdi)
	movq	%r8,  TDX_SEAM_r8(%rdi)
	movq	%r9,  TDX_SEAM_r9(%rdi)
	movq	%r10, TDX_SEAM_r10(%rdi)
	movq	%r11, TDX_SEAM_r11(%rdi)

	FRAME_END
	ret
SYM_FUNC_END(__seamcall)
