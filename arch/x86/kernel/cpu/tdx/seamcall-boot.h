/* SPDX-License-Identifier: GPL-2.0-only */
/* C function wrapper for SEAMCALL */
#ifndef __SEAM_SEAMCALL_BOOT_H
#define __SEAM_SEAMCALL_BOOT_H

struct tdx_ex_ret;
asmlinkage u64 __seamcall_boot(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			       struct tdx_ex_ret *ex);

static inline u64 seamcall_boot(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
				struct tdx_ex_ret *ex)
{
	u64 err;

	/* TODO: add trace point */
	err = __seamcall_boot(op, rcx, rdx, r8, r9, ex);
	/* TODO: add trace point*/
	return err;
}

#endif /* __SEAM_SEAMCALL_BOOT_H */
