/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#define TDX_CPUID_LEAF_ID	0x21

#ifndef __ASSEMBLY__

enum tdx_map_type {
	TDX_MAP_PRIVATE,
	TDX_MAP_SHARED,
};

#ifdef CONFIG_INTEL_TDX_GUEST

#include <asm/cpufeature.h>
#include <linux/types.h>

#define TDINFO			1
#define TDGETVEINFO		3
#define TDACCEPTPAGE		6

#define TDX_PAGE_ALREADY_ACCEPTED	0x8000000000000001

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

/* Decompression code doesn't know how to handle alternatives */
#ifdef BOOT_COMPRESSED_MISC_H
#define __out(bwl, bw)							\
do {									\
	if (is_tdx_guest()) {						\
		asm volatile("call tdg_out" #bwl : :			\
				"a"(value), "d"(port));			\
	} else {							\
		asm volatile("out" #bwl " %" #bw "0, %w1" : :		\
				"a"(value), "Nd"(port));		\
	}								\
} while (0)
#define __in(bwl, bw)							\
do {									\
	if (is_tdx_guest()) {						\
		asm volatile("call tdg_in" #bwl :			\
				"=a"(value) : "d"(port));		\
	} else {							\
		asm volatile("in" #bwl " %w1, %" #bw "0" :		\
				"=a"(value) : "Nd"(port));		\
	}								\
} while (0)
#else
#define __out(bwl, bw)							\
	alternative_input("out" #bwl " %" #bw "1, %w2",			\
			"call tdg_out" #bwl, X86_FEATURE_TDX_GUEST,	\
			"a"(value), "d"(port))

#define __in(bwl, bw)							\
	alternative_io("in" #bwl " %w2, %" #bw "0",			\
			"call tdg_in" #bwl, X86_FEATURE_TDX_GUEST,	\
			"=a"(value), "d"(port))
#endif

void tdg_outb(unsigned char value, unsigned short port);
void tdg_outw(unsigned short value, unsigned short port);
void tdg_outl(unsigned int value, unsigned short port);

unsigned char tdg_inb(unsigned short port);
unsigned short tdg_inw(unsigned short port);
unsigned int tdg_inl(unsigned short port);

extern phys_addr_t tdg_shared_mask(void);
extern int tdg_map_gpa(phys_addr_t gpa, int numpages,
		       enum tdx_map_type map_type);

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

static inline phys_addr_t tdg_shared_mask(void)
{
	return 0;
}

static inline int tdg_map_gpa(phys_addr_t gpa, int numpages,
			      enum tdx_map_type map_type)
{
	return -ENODEV;
}
#endif /* CONFIG_INTEL_TDX_GUEST */
#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_TDX_H */
