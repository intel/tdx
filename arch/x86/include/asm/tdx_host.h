/* SPDX-License-Identifier: GPL-2.0 */
/* constants/data definitions for TDX host */

#ifndef __ASM_X86_TDX_HOST_H
#define __ASM_X86_TDX_HOST_H

#ifdef CONFIG_INTEL_TDX_HOST
/*
 * TDX extended return:
 * Some of The "TDX module" SEAMCALLs return extended values (which are function
 * leaf specific) in registers in addition to the completion status code in
 * %rax.  For example, in the error case of TDH.SYS.INIT, the registers hold
 * more detailed information about the error in addition to an error code.  Note
 * that some registers may be unused depending on SEAMCALL functions.
 */
struct tdx_ex_ret {
	union {
		/*
		 * TODO: define symbolic names for each SEAMCALLs to the
		 * "TDX module" instead of register name for readability.
		 */
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
			u64 r11;
		} regs;
	};
};

const char *tdx_seamcall_error_name(u64 error_code);
void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
			     const struct tdx_ex_ret *ex_ret);
#else
static inline const char *tdx_seamcall_error_name(u64 error_code)
{
	return "";
}

struct tdx_ex_ret;
static inline void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
					   const struct tdx_ex_ret *ex_ret)
{
}
#endif

#endif /* __ASM_X86_TDX_HOST_H */
