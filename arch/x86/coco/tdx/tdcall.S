/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>

#include <linux/linkage.h>
#include <linux/errno.h>

#include "../../virt/vmx/tdx/tdxcall.S"

.section .noinstr.text, "ax"

/*
 * __tdcall()  - Used by TDX guests to request services from the TDX
 * module (does not include VMM services) using TDCALL instruction.
 *
 * __tdcall() function ABI:
 *
 * @fn   (RDI)	- TDCALL Leaf ID, moved to RAX
 * @args (RSI)	- struct tdx_module_args for input
 *
 * Only RCX/RDX/R8-R11 are used as input registers.
 *
 * Return status of TDCALL via RAX.
 */
SYM_FUNC_START(__tdcall)
	TDX_MODULE_CALL host=0
SYM_FUNC_END(__tdcall)

/*
 * __tdcall_ret() - Used by TDX guests to request services from the TDX
 * module (does not include VMM services) using TDCALL instruction, with
 * saving output registers to the 'struct tdx_module_args' used as input.
 *
 * __tdcall_ret() function ABI:
 *
 * @fn   (RDI)	- TDCALL Leaf ID, moved to RAX
 * @args (RSI)	- struct tdx_module_args for input and output
 *
 * Only RCX/RDX/R8-R11 are used as input/output registers.
 *
 * Return status of TDCALL via RAX.
 */
SYM_FUNC_START(__tdcall_ret)
	TDX_MODULE_CALL host=0 ret=1
SYM_FUNC_END(__tdcall_ret)

/*
 * __tdcall_saved_ret() - Used by TDX guests to request services from the
 * TDX module (including VMM services) using TDCALL instruction, with
 * saving output registers to the 'struct tdx_module_args' used as input.
 *
 * __tdcall_saved_ret() function ABI:
 *
 * @fn   (RDI)	- TDCALL leaf ID, moved to RAX
 * @args (RSI)	- struct tdx_module_args for input/output
 *
 * All registers in @args are used as input/output registers.
 *
 * On successful completion, return the hypercall error code.
 */
SYM_FUNC_START(__tdcall_saved_ret)
	TDX_MODULE_CALL host=0 ret=1 saved=1
SYM_FUNC_END(__tdcall_saved_ret)

.pushsection .noinstr.text, "ax"
SYM_FUNC_START(tdvmcall_trampoline)
	movq	%rax, %r10
	movq    %rbx, %r11
	movq    %rdi, %r12
	movq    %rsi, %r13
	movq    %rdx, %r14
	movq    %rcx, %r15

	movq	$TDG_VP_VMCALL, %rax
	movq    $(TDX_R10 | TDX_R11 | TDX_R12 | TDX_R13 | TDX_R14 | TDX_R15), %rcx

	tdcall

	testq   %rax, %rax
	jnz     1f

	RET
1:
	ud2
SYM_FUNC_END(tdvmcall_trampoline)
.popsection
