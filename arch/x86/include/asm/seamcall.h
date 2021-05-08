/* SPDX-License-Identifier: GPL-2.0 */
/* assembler macro for seamcall instruction */

#ifndef _ASM_X86_SEAMCALL_H
#define _ASM_X86_SEAMCALL_H

#ifdef __ASSEMBLY__

.macro seamcall
	.byte 0x66, 0x0f, 0x01, 0xcf
.endm

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_SEAMCALL_H */
