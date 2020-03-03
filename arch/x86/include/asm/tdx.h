/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#define TDVMCALL	0
#define TDINFO		1
#define TDGETVEINFO	3

/* TDVMCALL R10 Input */
#define TDVMCALL_STANDARD	0
#define TDVMCALL_VENDOR		1

#ifndef __ASSEMBLY__
#include <asm/cpufeature.h>

#define TDCALL	".byte 0x66,0x0f,0x01,0xcc"

#ifdef CONFIG_INTEL_TDX_GUEST

/* TDX support often needs to be queried before CPU caps is populated. */
static inline bool __is_tdx_guest(void)
{
	return cpuid_edx(1) & (1 << (X86_FEATURE_TDX_GUEST & 31));
}

static inline bool is_tdx_guest(void)
{
	return static_cpu_has(X86_FEATURE_TDX_GUEST);
}

void __init tdx_early_init(void);

/* Decompression code doesn't know how to handle alternatives */
#ifdef BOOT_COMPRESSED_MISC_H
#define __out(bwl, bw)							\
	if (__is_tdx_guest()) {						\
		asm volatile("call tdx_out" #bwl : :			\
				"a"(value), "d"(port));			\
	} else {							\
		asm volatile("out" #bwl " %" #bw "0, %w1" : :		\
				"a"(value), "Nd"(port));		\
	}
#define __in(bwl, bw)							\
	if (__is_tdx_guest()) {						\
		asm volatile("call tdx_in" #bwl : 			\
				"=a"(value) : "d"(port));		\
	} else {							\
		asm volatile("in" #bwl " %w1, %" #bw "0" :		\
				"=a"(value) : "Nd"(port));		\
	}
#else
#define __out(bwl, bw)							\
	alternative_input("out" #bwl " %" #bw "1, %w2",			\
			"call tdx_out" #bwl, X86_FEATURE_TDX_GUEST,	\
			"a"(value), "d"(port))

#define __in(bwl, bw)							\
	alternative_io("in" #bwl " %w2, %" #bw "0",			\
			"call tdx_in" #bwl, X86_FEATURE_TDX_GUEST,	\
			"=a"(value), "d"(port))
#endif

void tdx_outb(unsigned char value, unsigned short port);
void tdx_outw(unsigned short value, unsigned short port);
void tdx_outl(unsigned int value, unsigned short port);

unsigned char tdx_inb(unsigned short port);
unsigned short tdx_inw(unsigned short port);
unsigned int tdx_inl(unsigned short port);

#else // !CONFIG_INTEL_TDX_GUEST
static inline bool __is_tdx_guest(void)
{
	return false;
}

static inline bool is_tdx_guest(void)
{
	return false;
}

static inline void tdx_early_init(void)
{
}

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

#endif
#endif /* _ASM_X86_TDX_H */
