/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __BOOT_SEAM_SEAMCALL_H
#define __BOOT_SEAM_SEAMCALL_H

#ifdef CONFIG_KVM_INTEL_TDX

struct tdx_ex_ret;
asmlinkage u64 __seamcall_boot(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			       struct tdx_ex_ret *ex);

#define seamcall_boot(op, rcx, rdx, r8, r9, ex)				\
	__seamcall_boot(SEAMCALL_##op, (rcx), (rdx), (r8), (r9), (ex))

#define seamcall seamcall_boot

#endif

#endif /* __BOOT_SEAM_SEAMCALL_H */
