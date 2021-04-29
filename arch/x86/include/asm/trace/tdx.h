/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_TDX_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TDX_H

#include <linux/tracepoint.h>

#include <uapi/asm/vmx.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM tdx

#ifdef CONFIG_INTEL_TDX_GUEST

TRACE_EVENT(tdx_virtualization_exception,
	    TP_PROTO(u64 rip, u32 exit_reason, u64 exit_qual,
		     u64 gpa, u32 instr_len, u32 instr_info,
		     u64 cx, u64 ax, u64 dx),
	    TP_ARGS(rip, exit_reason, exit_qual, gpa, instr_len,
		    instr_info, cx, ax, dx),
	    TP_STRUCT__entry(
			     __field(u64, rip)
			     __field(u64, exit_qual)
			     __field(u64, gpa)
			     __field(u32, exit_reason)
			     __field(u32, instr_len)
			     __field(u32, instr_info)
			     __field(u64, cx)
			     __field(u64, ax)
			     __field(u64, dx)
			     ),
	    TP_fast_assign(
			   __entry->rip = rip;
			   __entry->exit_qual = exit_qual;
			   __entry->gpa = gpa;
			   __entry->exit_reason = exit_reason;
			   __entry->instr_len = instr_len;
			   __entry->instr_info = instr_info;
			   __entry->cx = cx;
			   __entry->ax = ax;
			   __entry->dx = dx;
			   ),
	    TP_printk("reason %s rip 0x%016llx len %u info 0x%08x qual 0x%016llx gpa 0x%016llx cx %llx ax %llx dx %llx",
		      __print_symbolic(__entry->exit_reason, VMX_EXIT_REASONS),
		      __entry->rip, __entry->instr_len, __entry->instr_info,
		      __entry->exit_qual, __entry->gpa,
		      __entry->cx, __entry->ax, __entry->dx
		      )
	    );

TRACE_EVENT(tdx_module_call_enter,
	    TP_PROTO(u64 id, u64 rcx, u64 rdx, u64 r8, u64 r9),
	    TP_ARGS(id, rcx, rdx, r8, r9),
	    TP_STRUCT__entry(
		__field(u64, id)
		__field(u64, rcx)
		__field(u64, rdx)
		__field(u64, r8)
		__field(u64, r9)
		),
	    TP_fast_assign(
		__entry->id  = id;
		__entry->rcx = rcx;
		__entry->rdx = rdx;
		__entry->r8  = r8;
		__entry->r9  = r9;
		),
	    TP_printk("id %lld rcx 0x%016llx rdx 0x%016llx r8 0x%016llx r9 0x%016llx",
		      __entry->id, __entry->rcx, __entry->rdx,
		      __entry->r8, __entry->r9
		      )
	    );

TRACE_EVENT(tdx_module_call_exit,
	    TP_PROTO(u64 rax, u64 rcx, u64 rdx, u64 r8, u64 r9,
		     u64 r10, u64 r11),
	    TP_ARGS(rax, rcx, rdx, r8, r9, r10, r11),
	    TP_STRUCT__entry(
		__field(u64, rax)
		__field(u64, rcx)
		__field(u64, rdx)
		__field(u64, r8)
		__field(u64, r9)
		__field(u64, r10)
		__field(u64, r11)
		),
	    TP_fast_assign(
		__entry->rax = rax;
		__entry->rcx = rcx;
		__entry->rdx = rdx;
		__entry->r8  = r8;
		__entry->r9  = r9;
		__entry->r10 = r10;
		__entry->r11 = r11;
		),
	    TP_printk("ret %lld rcx 0x%016llx rdx 0x%016llx r8 0x%016llx r9 0x%016llx r10 0x%016llx r11 0x%016llx",
		      __entry->rax, __entry->rcx, __entry->rdx,
		      __entry->r8, __entry->r9, __entry->r10, __entry->r11
		      )
	    );

TRACE_EVENT(tdx_hypercall_enter,
	    TP_PROTO(u64 id, u64 r12, u64 r13, u64 r14, u64 r15),
	    TP_ARGS(id, r12, r13, r14, r15),
	    TP_STRUCT__entry(
		__field(u64, id)
		__field(u64, r12)
		__field(u64, r13)
		__field(u64, r14)
		__field(u64, r15)
		),
	    TP_fast_assign(
		__entry->id  = id;
		__entry->r12 = r12;
		__entry->r13 = r13;
		__entry->r14 = r14;
		__entry->r15 = r15;
		),
	    TP_printk("subfn %lld r12 0x%016llx r13 0x%016llx r14 0x%016llx r15 0x%016llx",
		      __entry->id, __entry->r12, __entry->r13,
		      __entry->r14, __entry->r15
		      )
	    );

TRACE_EVENT(tdx_hypercall_exit,
	    TP_PROTO(u64 r10, u64 r11, u64 r12, u64 r13, u64 r14, u64 r15),
	    TP_ARGS(r10, r11, r12, r13, r14, r15),
	    TP_STRUCT__entry(
		__field(u64, r10)
		__field(u64, r11)
		__field(u64, r12)
		__field(u64, r13)
		__field(u64, r14)
		__field(u64, r15)
		),
	    TP_fast_assign(
		__entry->r10 = r10;
		__entry->r11 = r11;
		__entry->r12 = r12;
		__entry->r13 = r13;
		__entry->r14 = r14;
		__entry->r15 = r15;
		),
	    TP_printk("ret %lld r11 0x%016llx r12 0x%016llx r13 0x%016llx r14 0x%016llx r15 0x%016llx",
		      __entry->r10, __entry->r11, __entry->r12,
		      __entry->r13, __entry->r14, __entry->r15
		      )
	    );

#endif // CONFIG_INTEL_TDX_GUEST

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH asm/trace/
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE tdx
#endif /* _TRACE_TDX_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
