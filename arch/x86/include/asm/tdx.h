/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/init.h>
#include <asm/ptrace.h>
#include <asm/shared/tdx.h>

/*
 * Used by the #VE exception handler to gather the #VE exception
 * info from the TDX module. This is a software only structure
 * and not part of the TDX module/VMM ABI.
 */
struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	/* Guest Linear (virtual) Address */
	u64 gla;
	/* Guest Physical (virtual) Address */
	u64 gpa;
	u32 instr_len;
	u32 instr_info;
};

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);
bool is_tdx_guest(void);

bool tdx_get_ve_info(struct ve_info *ve);

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve);

void tdx_safe_halt(void);

bool tdx_early_handle_ve(struct pt_regs *regs);

phys_addr_t tdx_shared_mask(void);

int tdx_hcall_request_gpa_type(phys_addr_t start, phys_addr_t end, bool enc);

int tdx_mcall_tdreport(void *data, void *reportdata);

#else

static inline void tdx_early_init(void) { };
static inline bool is_tdx_guest(void) { return false; }
static inline void tdx_safe_halt(void) { };

static inline bool tdx_early_handle_ve(struct pt_regs *regs) { return false; }

static inline phys_addr_t tdx_shared_mask(void) { return 0; }


static inline int tdx_hcall_request_gpa_type(phys_addr_t start,
					     phys_addr_t end, bool enc)
{
	return -ENODEV;
}

#endif /* CONFIG_INTEL_TDX_GUEST */

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_INTEL_TDX_GUEST)
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4);
#else
static inline long tdx_kvm_hypercall(unsigned int nr, unsigned long p1,
				     unsigned long p2, unsigned long p3,
				     unsigned long p4)
{
	return -ENODEV;
}
#endif /* CONFIG_INTEL_TDX_GUEST && CONFIG_KVM_GUEST */
#endif /* _ASM_X86_TDX_H */
