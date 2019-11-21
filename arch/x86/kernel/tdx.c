// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2020 Intel Corporation */

#include <asm/tdx.h>
#include <asm/cpufeature.h>
#include <linux/cpu.h>
#include <asm/tdx.h>
#include <asm/vmx.h>

#ifdef CONFIG_KVM_GUEST
#include "tdx-kvm.c"
#endif

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

static inline bool cpuid_has_tdx_guest(void)
{
	u32 eax, signature[3];

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &signature[0],
			&signature[1], &signature[2]);

	if (memcmp("IntelTDX    ", signature, 12))
		return false;

	return true;
}

bool is_tdx_guest(void)
{
	return static_cpu_has(X86_FEATURE_TDX_GUEST);
}
EXPORT_SYMBOL_GPL(is_tdx_guest);

static void tdx_get_info(void)
{
	register long rcx asm("rcx");
	register long rdx asm("rdx");
	register long r8 asm("r8");
	long ret;

	asm volatile(TDCALL
		     : "=a"(ret), "=c"(rcx), "=r"(rdx), "=r"(r8)
		     : "a"(TDINFO)
		     : "r9", "r10", "r11", "memory");
	BUG_ON(ret);

	td_info.gpa_width = rcx & GENMASK(5, 0);
	td_info.attributes = rdx;
}

static __cpuidle void tdx_halt(void)
{
	register long r10 asm("r10") = TDVMCALL_STANDARD;
	register long r11 asm("r11") = EXIT_REASON_HLT;
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10 and R11 down to the VMM */
	rcx = BIT(10) | BIT(11);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10), "=r"(r11)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11)
			: );

	/* It should never fail */
	BUG_ON(ret || r10);
}

static __cpuidle void tdx_safe_halt(void)
{
	register long r10 asm("r10") = TDVMCALL_STANDARD;
	register long r11 asm("r11") = EXIT_REASON_HLT;
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10 and R11 down to the VMM */
	rcx = BIT(10) | BIT(11);

	/* Enable interrupts next to the TDVMCALL to avoid performance degradation */
	asm volatile("sti\n\t" TDCALL
			: "=a"(ret), "=r"(r10), "=r"(r11)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11)
			: );

	/* It should never fail */
	BUG_ON(ret || r10);
}

void __init tdx_early_init(void)
{
	if (!cpuid_has_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	tdx_get_info();

	pv_ops.irq.safe_halt = tdx_safe_halt;
	pv_ops.irq.halt = tdx_halt;

	pr_info("TDX guest is initialized\n");
}

unsigned long tdx_get_ve_info(struct ve_info *ve)
{
	register long r8 asm("r8");
	register long r9 asm("r9");
	register long r10 asm("r10");
	unsigned long ret;

	asm volatile(TDCALL
		     : "=a"(ret), "=c"(ve->exit_reason), "=d"(ve->exit_qual),
		     "=r"(r8), "=r"(r9), "=r"(r10)
		     : "a"(TDGETVEINFO)
		     :);

	ve->gla = r8;
	ve->gpa = r9;
	ve->instr_len = r10 & UINT_MAX;
	ve->instr_info = r10 >> 32;
	return ret;
}

int tdx_handle_virtualization_exception(struct pt_regs *regs,
		struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		tdx_halt();
		break;
	default:
		pr_warn("Unexpected #VE: %d\n", ve->exit_reason);
		return -EFAULT;
	}

	/* After successful #VE handling, move the IP */
	regs->ip += ve->instr_len;

	return ret;
}
