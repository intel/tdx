/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/frame.h>

#include "../../virt/tdxcall.S"

/*
 * kvm_seamcall()  - Host-side interface functions to SEAM software (TDX module)
 *
 * Transform function call register arguments into the SEAMCALL register
 * ABI.  Return the completion status of the SEAMCALL.  Additional output
 * operands are saved in @out (if it is provided by the user).
 * It doesn't check TDX_SEAMCALL_VMFAILINVALID unlike __semcall() because KVM
 * guarantees that VMX is enabled so that TDX_SEAMCALL_VMFAILINVALID doesn't
 * happen.  In the case of error completion status code, extended error code may
 * be stored in leaf specific output registers.
 *
 *-------------------------------------------------------------------------
 * SEAMCALL ABI:
 *-------------------------------------------------------------------------
 * Input Registers:
 *
 * RAX                 - SEAMCALL Leaf number.
 * RCX,RDX,R8-R9       - SEAMCALL Leaf specific input registers.
 *
 * Output Registers:
 *
 * RAX                 - SEAMCALL completion status code.
 * RCX,RDX,R8-R11      - SEAMCALL Leaf specific output registers.
 *
 *-------------------------------------------------------------------------
 *
 * kvm_seamcall() function ABI:
 *
 * @fn  (RDI)          - SEAMCALL Leaf number, moved to RAX
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
 * Return (via RAX) the completion status of the SEAMCALL
 */
SYM_FUNC_START(kvm_seamcall)
        FRAME_BEGIN
        TDX_MODULE_CALL host=1 error_check=0
        FRAME_END
        ret
SYM_FUNC_END(kvm_seamcall)
EXPORT_SYMBOL_GPL(kvm_seamcall)
