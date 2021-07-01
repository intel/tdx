/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_VMX_SEAMCALL_H
#define __KVM_VMX_SEAMCALL_H

#ifdef __ASSEMBLY__

#define seamcall .byte 0x66, 0x0f, 0x01, 0xcf

#else

#ifndef seamcall

#include <asm/trace/seam.h>

struct tdx_ex_ret;
asmlinkage u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
			  struct tdx_ex_ret *ex);

static inline u64 _seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10,
			    struct tdx_ex_ret *ex)
{
	u64 err;

	trace_seamcall_enter(smp_processor_id(), op, rcx, rdx, r8, r9, r10, 0);
	err = __seamcall(op, rcx, rdx, r8, r9, r10, ex);
	trace_seamcall_exit(smp_processor_id(), op, err, ex);
	return err;
}

#define seamcall(op, rcx, rdx, r8, r9, r10, ex)				\
	_seamcall(SEAMCALL_##op, (rcx), (rdx), (r8), (r9), (r10), (ex))
#endif

static inline void __pr_seamcall_error(u64 op, const char *op_str,
				       u64 err, struct tdx_ex_ret *ex)
{
	pr_err_ratelimited("SEAMCALL[%s] failed on cpu %d: 0x%llx\n",
			   op_str, smp_processor_id(), (err));
	if (ex)
		pr_err_ratelimited(
			"RCX 0x%llx, RDX 0x%llx, R8 0x%llx, R9 0x%llx, R10 0x%llx, R11 0x%llx\n",
			(ex)->rcx, (ex)->rdx, (ex)->r8, (ex)->r9, (ex)->r10,
			(ex)->r11);
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

#endif

#endif /* __KVM_VMX_SEAMCALL_H */
