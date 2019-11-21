/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#define TDX_CPUID_LEAF_ID	0x21

#ifdef CONFIG_INTEL_TDX_GUEST

#include <asm/cpufeature.h>
#include <linux/types.h>

#define TDINFO			1
#define TDGETVEINFO		3

struct tdcall_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

struct tdvmcall_output {
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	u64 gla;
	u64 gpa;
	u32 instr_len;
	u32 instr_info;
};

unsigned long tdg_get_ve_info(struct ve_info *ve);

int tdg_handle_virtualization_exception(struct pt_regs *regs,
		struct ve_info *ve);

/* Common API to check TDX support in decompression and common kernel code. */
bool is_tdx_guest(void);

void __init tdx_early_init(void);

/* Helper function used to communicate with the TDX module */
u64 __tdcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
	     struct tdcall_output *out);

/* Helper function used to request services from VMM */
u64 __tdvmcall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15,
	       struct tdvmcall_output *out);
u64 __tdvmcall_vendor_kvm(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15,
			  struct tdvmcall_output *out);

long tdx_kvm_hypercall0(unsigned int nr);
long tdx_kvm_hypercall1(unsigned int nr, unsigned long p1);
long tdx_kvm_hypercall2(unsigned int nr, unsigned long p1, unsigned long p2);
long tdx_kvm_hypercall3(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3);
long tdx_kvm_hypercall4(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3, unsigned long p4);

#else // !CONFIG_INTEL_TDX_GUEST

static inline bool is_tdx_guest(void)
{
	return false;
}

static inline void tdx_early_init(void) { };

static inline long tdx_kvm_hypercall0(unsigned int nr)
{
	return -ENODEV;
}

static inline long tdx_kvm_hypercall1(unsigned int nr, unsigned long p1)
{
	return -ENODEV;
}

static inline long tdx_kvm_hypercall2(unsigned int nr, unsigned long p1,
				      unsigned long p2)
{
	return -ENODEV;
}

static inline long tdx_kvm_hypercall3(unsigned int nr, unsigned long p1,
				      unsigned long p2, unsigned long p3)
{
	return -ENODEV;
}

static inline long tdx_kvm_hypercall4(unsigned int nr, unsigned long p1,
				      unsigned long p2, unsigned long p3,
				      unsigned long p4)
{
	return -ENODEV;
}

#endif /* CONFIG_INTEL_TDX_GUEST */

#endif /* _ASM_X86_TDX_H */
