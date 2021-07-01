/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_VMX_SEAMCALL_H
#define __KVM_VMX_SEAMCALL_H

#ifdef CONFIG_INTEL_TDX_HOST

#ifdef __ASSEMBLY__

.macro seamcall
	.byte 0x66, 0x0f, 0x01, 0xcf
.endm

#else

#include <asm/trace/seam.h>
#include <asm/tdx_host.h>

asmlinkage u64 kvm_seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
			struct tdx_ex_ret *ex);

static inline u64 _seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
			struct tdx_ex_ret *ex)
{
	u64 err;
	struct tdx_ex_ret dummy;
	if (!ex)
		/* kvm_seamcall requires non-NULL ex. */
		ex = &dummy;

	trace_seamcall_enter(op, rcx, rdx, r8, r9, r10, 0);
	err = kvm_seamcall(op, rcx, rdx, r8, r9, r10, ex);
	trace_seamcall_exit(op, err, ex);
	return err;
}

#define seamcall(op, rcx, rdx, r8, r9, r10, ex)				\
	_seamcall(SEAMCALL_##op, (rcx), (rdx), (r8), (r9), (r10), (ex))

static inline void __pr_seamcall_error(u64 op, const char *op_str,
				u64 err, struct tdx_ex_ret *ex)
{
	pr_err_ratelimited("SEAMCALL[%s] failed on cpu %d: %s (0x%llx)\n",
			op_str, smp_processor_id(),
			tdx_seamcall_error_name(err), (err));
	if (ex)
		pr_seamcall_ex_ret_info(op, err, ex);
}

#define pr_seamcall_error(op, err, ex)			\
	__pr_seamcall_error(SEAMCALL_##op, #op, (err), (ex))

/* ex is a pointer to struct tdx_ex_ret or NULL. */
#define TDX_ERR(err, op, ex)			\
({						\
	u64 __ret_warn_on = WARN_ON_ONCE(err);	\
						\
	if (unlikely(__ret_warn_on))		\
		pr_seamcall_error(op, err, ex);	\
	__ret_warn_on;				\
})

#endif	/* __ASSEMBLY__ */
#endif	/* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_VMX_SEAMCALL_H */
