/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM tdx_seam

#if !defined(_TRACE_SEAM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SEAM_H

#include <linux/tracepoint.h>

#if IS_ENABLED(CONFIG_INTEL_TDX_HOST)

#include <asm/vmx.h>
#include "tdx_arch.h"
#include "../kvm_cache_regs.h"

TRACE_EVENT(tdx_seamcall,
	    TP_PROTO(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10),
	    TP_ARGS(fn, rcx, rdx, r8, r9, r10),
	    TP_STRUCT__entry(
		__field(u64, fn)
		__field(u64, rcx)
		__field(u64, rdx)
		__field(u64, r8)
		__field(u64, r9)
		__field(u64, r10)
	    ),
	    TP_fast_assign(
		__entry->fn = fn;
		__entry->rcx = rcx;
		__entry->rdx = rdx;
		__entry->r8 = r8;
		__entry->r9 = r9;
		__entry->r10 = r10;
	    ),
	    TP_printk("op: %s(%llx) %llx %llx %llx %llx %llx",
		__print_symbolic_u64(__entry->fn, TDX_SEAMCALLS),
		__entry->fn,
		__entry->rcx,
		__entry->rdx,
		__entry->r8,
		__entry->r9,
		__entry->r10
	    )
);

struct tdx_ex_ret;
TRACE_EVENT(tdx_seamret,
	    TP_PROTO(u64 fn, u64 err, const struct tdx_ex_ret *ex_ret),
	    TP_ARGS(fn, err, ex_ret),
	    TP_STRUCT__entry(
		__field(u64, fn)
		__field(u64, err)
		__field(u64, rcx)
		__field(u64, rdx)
		__field(u64, r8)
		__field(u64, r9)
		__field(u64, r10)
		__field(u64, r11)
	    ),
	    TP_fast_assign(
		__entry->fn = fn;
		__entry->err = err;
		__entry->rcx = ex_ret->regs.rcx;
		__entry->rdx = ex_ret->regs.rdx;
		__entry->r8 = ex_ret->regs.r8;
		__entry->r9 = ex_ret->regs.r9;
		__entry->r10 = ex_ret->regs.r10;
		__entry->r11 = ex_ret->regs.r11;
	    ),
	    TP_printk("op: %s(%llx) err: %s(%llx) %llx %llx %llx %llx %llx %llx",
		__print_symbolic_u64(__entry->fn, TDX_SEAMCALLS),
		__entry->fn,
		__print_symbolic_u64(__entry->err & TDX_SEAMCALL_STATUS_MASK,
				     TDX_STATUS_CODES),
		__entry->err,
		__entry->rcx,
		__entry->rdx,
		__entry->r8,
		__entry->r9,
		__entry->r10,
		__entry->r11
	    )
);

/*
 * Tracepoint for TDVMCALL from a TDX guest
 */
TRACE_EVENT(kvm_tdvmcall,
	TP_PROTO(struct kvm_vcpu *vcpu, __u32 exit_reason,
		 __u64 p1, __u64 p2, __u64 p3, __u64 p4),
	TP_ARGS(vcpu, exit_reason, p1, p2, p3, p4),

	TP_STRUCT__entry(
		__field(	__u64,		rip		)
		__field(	__u32,		exit_reason	)
		__field(	__u64,		p1		)
		__field(	__u64,		p2		)
		__field(	__u64,		p3		)
		__field(	__u64,		p4		)
	),

	TP_fast_assign(
		__entry->rip			= kvm_rip_read(vcpu);
		__entry->exit_reason		= exit_reason;
		__entry->p1			= p1;
		__entry->p2			= p2;
		__entry->p3			= p3;
		__entry->p4			= p4;
	),

	TP_printk("rip: %llx reason: %s p1: %llx p2: %llx p3: %llx p4: %llx",
		  __entry->rip,
		  __print_symbolic(__entry->exit_reason,
				   TDG_VP_VMCALL_EXIT_REASONS),
		  __entry->p1, __entry->p2, __entry->p3, __entry->p4)
);

/*
 * Tracepoint for SEPT related SEAMCALLs.
 */
TRACE_EVENT(kvm_sept_seamcall,
	TP_PROTO(__u64 op, __u64 gpa, __u64 hpa, int level),
	TP_ARGS(op, gpa, hpa, level),

	TP_STRUCT__entry(
		__field(	__u64,		op	)
		__field(	__u64,		gpa	)
		__field(	__u64,		hpa	)
		__field(	int,		level	)
	),

	TP_fast_assign(
		__entry->op			= op;
		__entry->gpa			= gpa;
		__entry->hpa			= hpa;
		__entry->level			= level;
	),

	TP_printk("op: %llu gpa: 0x%llx hpa: 0x%llx level: %u",
		  __entry->op, __entry->gpa, __entry->hpa, __entry->level)
);
#endif /* CONFIG_INTEL_TDX_HOST */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../../arch/x86/kvm/vmx/
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE tdx_trace
#endif /* _TRACE_SEAM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
