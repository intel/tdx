/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#include <linux/cpu.h>
#include <asm/tdx.h>
#include <asm/vmx.h>

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

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
	if (!__is_tdx_guest())
		return;

	tdx_get_info();

	pv_ops.irq.safe_halt = tdx_safe_halt;
	pv_ops.irq.halt = tdx_halt;
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
	unsigned long val;
	int ret = 0;

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		tdx_halt();
		break;
	default:
		pr_warn("Unhandled #VE: %d\n", ve->exit_reason);
		return -EFAULT;
	}

	if (!ret)
		regs->ip += ve->instr_len;
	return ret;
}
