/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/init.h>
#include <linux/bits.h>

#include <asm/errno.h>
#include <asm/ptrace.h>
#include <asm/shared/tdx.h>

#include <asm/trapnr.h>

/*
 * SW-defined error codes.
 *
 * Bits 47:40 == 0xFF indicate Reserved status code class that never used by
 * TDX module.
 */
#define TDX_ERROR			_BITUL(63)
#define TDX_SW_ERROR			(TDX_ERROR | GENMASK_ULL(47, 40))
#define TDX_SEAMCALL_VMFAILINVALID	(TDX_SW_ERROR | _UL(0xFFFF0000))

#define TDX_SEAMCALL_GP			(TDX_SW_ERROR | X86_TRAP_GP)
#define TDX_SEAMCALL_UD			(TDX_SW_ERROR | X86_TRAP_UD)

#ifndef __ASSEMBLY__

/* TDX supported page sizes from the TDX module ABI. */
#define TDX_PS_4K	0
#define TDX_PS_2M	1
#define TDX_PS_1G	2
#define TDX_PS_NR	(TDX_PS_1G + 1)

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
	/* Guest Physical Address */
	u64 gpa;
	u32 instr_len;
	u32 instr_info;
};

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);

void tdx_get_ve_info(struct ve_info *ve);

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve);

void tdx_safe_halt(void);

bool tdx_early_handle_ve(struct pt_regs *regs);

int tdx_mcall_get_report0(u8 *reportdata, u8 *tdreport);

#else

static inline void tdx_early_init(void) { };
static inline void tdx_safe_halt(void) { };

static inline bool tdx_early_handle_ve(struct pt_regs *regs) { return false; }

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

#ifdef CONFIG_INTEL_TDX_HOST
bool platform_tdx_enabled(void);
int tdx_cpu_enable(void);
int tdx_enable(void);
void tdx_reset_memory(void);
bool tdx_is_private_mem(unsigned long phys);

/*
 * Key id globally used by TDX module: TDX module maps TDR with this TDX global
 * key id.  TDR includes key id assigned to the TD.  Then TDX module maps other
 * TD-related pages with the assigned key id.  TDR requires this TDX global key
 * id for cache flush unlike other TD-related pages.
 */
extern u32 tdx_global_keyid __ro_after_init;
int tdx_guest_keyid_alloc(void);
void tdx_guest_keyid_free(int keyid);

u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
	       struct tdx_module_output *out);
#else	/* !CONFIG_INTEL_TDX_HOST */
static inline bool platform_tdx_enabled(void) { return false; }
static inline int tdx_cpu_enable(void) { return -ENODEV; }
static inline int tdx_enable(void)  { return -ENODEV; }
static inline void tdx_reset_memory(void) { }
static inline bool tdx_is_private_mem(unsigned long phys) { return false; }
static inline u64 __seamcall(u64 op, u64 rcx, u64 rdx, u64 r8, u64 r9,
			     struct tdx_module_output *out) { return TDX_SEAMCALL_UD; };
static inline int tdx_guest_keyid_alloc(void) { return -EOPNOTSUPP; }
static inline void tdx_guest_keyid_free(int keyid) { }
#endif	/* CONFIG_INTEL_TDX_HOST */

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_TDX_H */
