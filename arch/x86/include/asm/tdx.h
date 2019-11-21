/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/cpufeature.h>
#include <linux/types.h>

#define TDX_CPUID_LEAF_ID			0x21
#define TDX_HYPERCALL_STANDARD			0
#define TDX_HYPERCALL_VENDOR_KVM		0x4d564b2e584454

/*
 * Used in __tdx_module_call() helper function to gather the
 * output registers' values of TDCALL instruction when requesting
 * services from the TDX module. This is software only structure
 * and not related to TDX module/VMM.
 */
struct tdx_module_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

/*
 * Used in __tdx_hypercall() helper function to gather the
 * output registers' values of TDCALL instruction when requesting
 * services from the VMM. This is software only structure
 * and not related to TDX module/VMM.
 */
struct tdx_hypercall_output {
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

/*
 * Used by #VE exception handler to gather the #VE exception
 * info from the TDX module. This is software only structure
 * and not related to TDX module/VMM.
 */
struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	u64 gla;	/* Guest Linear (virtual) Address */
	u64 gpa;	/* Guest Physical (virtual) Address */
	u32 instr_len;
	u32 instr_info;
};

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);

bool tdx_prot_guest_has(unsigned long flag);

/* Helper function used to communicate with the TDX module */
u64 __tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		      struct tdx_module_output *out);

/* Helper function used to request services from VMM */
u64 __tdx_hypercall(u64 type, u64 fn, u64 r12, u64 r13, u64 r14,
		    u64 r15, struct tdx_hypercall_output *out);

unsigned long tdg_get_ve_info(struct ve_info *ve);

int tdg_handle_virtualization_exception(struct pt_regs *regs,
					struct ve_info *ve);

#else

static inline void tdx_early_init(void) { };

static inline bool tdx_prot_guest_has(unsigned long flag) { return false; }

#endif /* CONFIG_INTEL_TDX_GUEST */

#ifdef CONFIG_INTEL_TDX_GUEST_KVM

static inline long tdx_kvm_hypercall(unsigned int nr, unsigned long p1,
				     unsigned long p2, unsigned long p3,
				     unsigned long p4)
{
	struct tdx_hypercall_output out;
	u64 err;

	err = __tdx_hypercall(TDX_HYPERCALL_VENDOR_KVM, nr, p1, p2,
			      p3, p4, &out);

	BUG_ON(err);

	return out.r10;
}
#else
static inline long tdx_kvm_hypercall(unsigned int nr, unsigned long p1,
				     unsigned long p2, unsigned long p3,
				     unsigned long p4)
{
	return -ENODEV;
}
#endif /* CONFIG_INTEL_TDX_GUEST_KVM */

#endif /* _ASM_X86_TDX_H */
