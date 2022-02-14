/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/frame.h>

#include "../../kernel/tdxcall.S"

/*
 * __seamcall()  - Host-side interface functions to SEAM software
 *		   (P-SEAMLDR or TDX module)
 *
 * Transform function call register arguments into the SEAMCALL register
 * ABI.  Return TDX_SEAMCALL_VMFAILINVALID (when SEAM software is not
 * loaded or SEAMCALLs are made into P-SEAMLDR concurrently), or the
 * completion status of the SEAMCALL.  Additional output operands are
 * saved in @out (if it is provided by the user).
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
 * __seamcall() function ABI:
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
 * Return (via RAX) the completion status of the SEAMCALL, or
 * TDX_SEAMCALL_VMFAILINVALID.
 */
SYM_FUNC_START(__seamcall)
	FRAME_BEGIN
	TDX_MODULE_CALL host=1
	FRAME_END
	ret
SYM_FUNC_END(__seamcall)
