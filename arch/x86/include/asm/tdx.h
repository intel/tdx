/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#define TDX_CPUID_LEAF_ID	0x21

#define TDVMCALL	0
#define TDINFO		1
#define TDGETVEINFO	3
#define TDACCEPTPAGE	6

#define TDX_PAGE_ALREADY_ACCEPTED       0x00000B0A00000000

/* TDVMCALL R10 Input */
#define TDVMCALL_STANDARD	0
#define TDVMCALL_VENDOR_KVM	((u64) 0x4d564b2e584454) /* "TDX.KVM" */

#ifndef __ASSEMBLY__
#include <asm/cpufeature.h>

/*
 * TDCALL instruction is newly added in TDX architecture,
 * used by TD for requesting the host VMM to provide
 * (untrusted) services. Supported in Binutils >= 2.36
 */
#define TDCALL	".byte 0x66,0x0f,0x01,0xcc"

#ifdef CONFIG_INTEL_TDX_GUEST

/* Common API to check TDX support in decompression and common kernel code. */
bool is_tdx_guest(void);

void __init tdx_early_init(void);

/* Decompression code doesn't know how to handle alternatives */
#ifdef BOOT_COMPRESSED_MISC_H
#define __out(bwl, bw)							\
do {									\
	if (is_tdx_guest()) {						\
		asm volatile("call tdx_out" #bwl : :			\
				"a"(value), "d"(port));			\
	} else {							\
		asm volatile("out" #bwl " %" #bw "0, %w1" : :		\
				"a"(value), "Nd"(port));		\
	}								\
} while (0)
#define __in(bwl, bw)							\
do {									\
	if (is_tdx_guest()) {						\
		asm volatile("call tdx_in" #bwl :			\
				"=a"(value) : "d"(port));		\
	} else {							\
		asm volatile("in" #bwl " %w1, %" #bw "0" :		\
				"=a"(value) : "Nd"(port));		\
	}								\
} while (0)
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
		unsigned long p3, unsigned long p4);

phys_addr_t tdx_shared_mask(void);

int tdx_map_gpa(phys_addr_t gpa, int numpages, bool private);
#endif
#endif /* _ASM_X86_TDX_H */
