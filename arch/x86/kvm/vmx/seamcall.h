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

#include "tdx_trace.h"

/*
 * TDX extended return:
 * Some of The "TDX module" SEAMCALLs return extended values (which are function
 * leaf specific) in registers in addition to the completion status code in
 %rax.
 */
struct tdx_ex_ret {
	union {
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
			u64 r11;
		} regs;
		/* TDH_MNG_INIT returns CPUID info on error. */
		struct {
			u32 leaf;
			u32 subleaf;
		} mng_init;
		/* Functions that walk SEPT */
		struct {
			u64 septe;
			struct {
				u64 level		:3;
				u64 sept_reserved_0	:5;
				u64 state		:8;
				u64 sept_reserved_1	:48;
			};
		} sept_walk;
		/* TDH_MNG_{RD,WR} return the field value. */
		struct {
			u64 field_val;
		} mng_rdwr;
		/* TDH_MEM_{RD,WR} return the error info and value. */
		struct {
			u64 ext_err_info_1;
			u64 ext_err_info_2;
			u64 mem_val;
		} mem_rdwr;
		/* TDH_PHYMEM_PAGE_RDMD and TDH_PHYMEM_PAGE_RECLAIM return page metadata. */
		struct {
			u64 page_type;
			u64 owner;
			u64 page_size;
		} phymem_page_md;
	};
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
	trace_tdx_seamcall(op, rcx, rdx, r8, r9, r10);

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
		  "=c"(ex->regs.rcx), "=d"(ex->regs.rdx),
		  "=r"(r8_out), "=r"(r9_out), "=r"(r10_out), "=r"(r11_out)
		: "a"(op), "c"(rcx), "d"(rdx),
		  "r"(r8_in), "r"(r9_in), "r"(r10_in)
		: "cc", "memory");
	ex->regs.r8 = r8_out;
	ex->regs.r9 = r9_out;
	ex->regs.r10 = r10_out;
	ex->regs.r11 = r11_out;

	trace_tdx_seamret(op, ret, ex);
	return ret;
}

const char *tdx_error_name(u64 error_code);
void pr_tdx_ex_ret_info(u64 op, u64 error_code, const struct tdx_ex_ret *ex_ret);
void pr_tdx_error(u64 op, u64 error_code, const struct tdx_ex_ret *ex_ret);

#endif /* !__ASSEMBLY__ */

#endif	/* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_VMX_SEAMCALL_H */
