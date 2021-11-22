/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_VMX_SEAMCALL_H
#define __KVM_VMX_SEAMCALL_H

#ifdef CONFIG_INTEL_TDX_HOST

#ifdef __ASSEMBLY__

.macro seamcall
	.byte 0x66, 0x0f, 0x01, 0xcf
.endm

#else

struct tdx_module_output;
u64 kvm_seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
		struct tdx_module_output *out);

void pr_tdx_error(u64 op, u64 error_code, const struct tdx_module_output *out);

#endif /* !__ASSEMBLY__ */

#endif	/* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_VMX_SEAMCALL_H */
