/* SPDX-License-Identifier: GPL-2.0-only */
/* C function wrapper for SEAMCALL */
#ifndef __SEAM_SEAMCALL_H
#define __SEAM_SEAMCALL_H

#include <linux/linkage.h>

#include <asm/tdx_host.h>
#include <asm/trace/seam.h>

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
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
			u64 r11;
		} regs;
		/*
		 * TDH_SYS_INFO returns the buffer address and its size, and the
		 * CMR_INFO address and its number of entries.
		 */
		struct {
			u64 buffer;
			u64 nr_bytes;
			u64 cmr_info;
			u64 nr_cmr_entries;
		} sys_info;
		/* TDH_SYS_TDMR_INIT returns the input PA and next PA. */
		struct {
			u64 prev;
			u64 next;
		} sys_tdmr_init;
	};
};

asmlinkage u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			  struct tdx_ex_ret *ex);

static inline u64 seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			   struct tdx_ex_ret *ex)
{
	struct tdx_ex_ret dummy;
	u64 err;

	if (!ex)
		/* __seamcall requires non-NULL ex. */
		ex = &dummy;

	trace_seamcall_enter(op, rcx, rdx, r8, r9, 0, 0);
	err = __seamcall(op, rcx, rdx, r8, r9, ex);
	trace_seamcall_exit(op, err, ex);
	return err;
}

const char *tdx_seamcall_error_name(u64 error_code);

void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
			const struct tdx_ex_ret *ex_ret);
void pr_seamcall_error(u64 op, u64 error_code, const struct tdx_ex_ret *ex_ret);
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* __SEAM_SEAMCALL_H */
