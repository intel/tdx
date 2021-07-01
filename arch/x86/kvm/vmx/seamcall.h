/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_VMX_SEAMCALL_H
#define __KVM_VMX_SEAMCALL_H

#include <asm/asm.h>

#ifdef CONFIG_INTEL_TDX_HOST

#ifdef __ASSEMBLY__

.macro seamcall
	.byte 0x66, 0x0f, 0x01, 0xcf
.endm

#else

/*
 * TDX extended return:
 * Some of The "TDX module" SEAMCALLs return extended values (which are function
 * leaf specific) in registers in addition to the completion status code in RAX.
 */
struct tdx_ex_ret {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

static inline u64 seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
			struct tdx_ex_ret *ex)
{
	register unsigned long r8_in asm("r8");
	register unsigned long r9_in asm("r9");
	register unsigned long r10_in asm("r10");
	register unsigned long r8_out asm("r8");
	register unsigned long r9_out asm("r9");
	register unsigned long r10_out asm("r10");
	register unsigned long r11_out asm("r11");
	struct tdx_ex_ret dummy;
	u64 ret;

	if (!ex)
		/* The following inline assembly requires non-NULL ex. */
		ex = &dummy;

	/*
	 * Because the TDX module is known to be already initialized, seamcall
	 * instruction should always succeed without exceptions.  Don't check
	 * the instruction error with CF=1 for the availability of the TDX
	 * module.
	 */
	r8_in = r8;
	r9_in = r9;
	r10_in = r10;
	asm volatile (
		".byte 0x66, 0x0f, 0x01, 0xcf\n\t"	/* seamcall instruction */
		: ASM_CALL_CONSTRAINT, "=a"(ret),
		  "=c"(ex->rcx), "=d"(ex->rdx),
		  "=r"(r8_out), "=r"(r9_out), "=r"(r10_out), "=r"(r11_out)
		: "a"(op), "c"(rcx), "d"(rdx),
		  "r"(r8_in), "r"(r9_in), "r"(r10_in)
		: "cc", "memory");
	ex->r8 = r8_out;
	ex->r9 = r9_out;
	ex->r10 = r10_out;
	ex->r11 = r11_out;

	return ret;
}

#endif /* !__ASSEMBLY__ */

#endif	/* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_VMX_SEAMCALL_H */
