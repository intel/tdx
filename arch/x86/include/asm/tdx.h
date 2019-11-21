/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#define TDX_CPUID_LEAF_ID	0x21

#include <asm/cpufeature.h>

#ifdef CONFIG_INTEL_TDX_GUEST

#define TDCALL	".byte 0x66,0x0f,0x01,0xcc"

#define TDVMCALL	0
#define TDINFO		1
#define TDGETVEINFO	3

/* TDVMCALL R10 Input */
#define TDVMCALL_STANDARD	0
#define TDVMCALL_VENDOR		1

static inline bool cpuid_has_tdx_guest(void)
{
	uint32_t eax, signature[3];

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &signature[0],
			&signature[1], &signature[2]);

	if (memcmp("IntelTDX    ", signature, 12))
		return false;

	return true;
}

/* Common API to check TDX support in decompression and common kernel code. */
bool is_tdx_guest(void);

void __init tdx_early_init(void);

#else // !CONFIG_INTEL_TDX_GUEST

static inline bool is_tdx_guest(void)
{
	return false;
}

static inline void tdx_early_init(void) { };

#endif /* CONFIG_INTEL_TDX_GUEST */

struct ve_info {
	unsigned int exit_reason;
	unsigned long exit_qual;
	unsigned long gla;
	unsigned long gpa;
	unsigned int instr_len;
	unsigned int instr_info;
};

unsigned long tdx_get_ve_info(struct ve_info *ve);
int tdx_handle_virtualization_exception(struct pt_regs *regs,
		struct ve_info *ve);

long tdx_kvm_hypercall0(unsigned int nr);
long tdx_kvm_hypercall1(unsigned int nr, unsigned long p1);
long tdx_kvm_hypercall2(unsigned int nr, unsigned long p1, unsigned long p2);
long tdx_kvm_hypercall3(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3);
long tdx_kvm_hypercall4(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3, unsigned p4);

#endif /* _ASM_X86_TDX_H */
