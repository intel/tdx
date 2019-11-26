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

static bool tdx_is_context_switched_msr(unsigned int msr)
{
	/*  XXX: Update the list of context-switched MSRs */

	switch (msr) {
	case MSR_EFER:
	case MSR_IA32_CR_PAT:
	case MSR_FS_BASE:
	case MSR_GS_BASE:
	case MSR_KERNEL_GS_BASE:
	case MSR_IA32_SYSENTER_CS:
	case MSR_IA32_SYSENTER_EIP:
	case MSR_IA32_SYSENTER_ESP:
	case MSR_STAR:
	case MSR_LSTAR:
	case MSR_SYSCALL_MASK:
	case MSR_IA32_XSS:
	case MSR_TSC_AUX:
	case MSR_IA32_BNDCFGS:
		return true;
	}
	return false;
}

static u64 tdx_read_msr_safe(unsigned int msr, int *err)
{
	register long r10 asm("r10") = TDVMCALL_STANDARD;
	register long r11 asm("r11") = EXIT_REASON_MSR_READ;
	register long r12 asm("r12") = msr;
	register long rcx asm("rcx");
	long ret;

	WARN_ON_ONCE(tdx_is_context_switched_msr(msr));

	if (msr == MSR_CSTAR)
		return 0;

	/* Allow to pass R10, R11 and R12 down to the VMM */
	rcx = BIT(10) | BIT(11) | BIT(12);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10), "=r"(r11), "=r"(r12)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11), "r"(r12)
			: );

	/* XXX: Better error handling needed? */
	*err = (ret || r10) ? -EIO : 0;

	return r11;
}

static int tdx_write_msr_safe(unsigned int msr, unsigned int low,
			      unsigned int high)
{
	register long r10 asm("r10") = TDVMCALL_STANDARD;
	register long r11 asm("r11") = EXIT_REASON_MSR_WRITE;
	register long r12 asm("r12") = msr;
	register long r13 asm("r13") = (u64)high << 32 | low;
	register long rcx asm("rcx");
	long ret;

	WARN_ON_ONCE(tdx_is_context_switched_msr(msr));

	if (msr == MSR_CSTAR)
		return 0;

	/* Allow to pass R10, R11, R12 and R13 down to the VMM */
	rcx = BIT(10) | BIT(11) | BIT(12) | BIT(13);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10), "=r"(r11), "=r"(r12), "=r"(r13)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11), "r"(r12),
			  "r"(r13)
			: );

	return ret || r10 ? -EIO : 0;
}

static void tdx_handle_cpuid(struct pt_regs *regs)
{
	register long r10 asm("r10") = TDVMCALL_STANDARD;
	register long r11 asm("r11") = EXIT_REASON_CPUID;
	register long r12 asm("r12") = regs->ax;
	register long r13 asm("r13") = regs->cx;
	register long r14 asm("r14");
	register long r15 asm("r15");
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10, R11, R12, R13, R14 and R15 down to the VMM */
	rcx = BIT(10) | BIT(11) | BIT(12) | BIT(13) | BIT(14) | BIT(15);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10), "=r"(r11), "=r"(r12), "=r"(r13),
			  "=r"(r14), "=r"(r15)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11), "r"(r12),
			  "r"(r13)
			: );

	regs->ax = r12;
	regs->bx = r13;
	regs->cx = r14;
	regs->dx = r15;

	WARN_ON(ret || r10);
}

static void tdx_out(int size, unsigned int value, int port)
{
	register long r10 asm("r10") = TDVMCALL_STANDARD;
	register long r11 asm("r11") = EXIT_REASON_IO_INSTRUCTION;
	register long r12 asm("r12") = size;
	register long r13 asm("r13") = 1;
	register long r14 asm("r14") = port;
	register long r15 asm("r15") = value;
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10, R11, R12, R13, R14 and R15 down to the VMM */
	rcx = BIT(10) | BIT(11) | BIT(12) | BIT(13) | BIT(14) | BIT(15);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10), "=r"(r11), "=r"(r12), "=r"(r13),
			  "=r"(r14), "=r"(r15)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11), "r"(r12),
			  "r"(r13), "r"(r14), "r"(r15)
			: );

	WARN_ON(ret || r10);
}

static unsigned int tdx_in(int size, int port)
{
	register long r10 asm("r10") = TDVMCALL_STANDARD;
	register long r11 asm("r11") = EXIT_REASON_IO_INSTRUCTION;
	register long r12 asm("r12") = size;
	register long r13 asm("r13") = 0;
	register long r14 asm("r14") = port;
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10, R11, R12, R13 and R14 down to the VMM */
	rcx = BIT(10) | BIT(11) | BIT(12) | BIT(13) | BIT(14);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10), "=r"(r11), "=r"(r12), "=r"(r13),
			  "=r"(r14)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11), "r"(r12),
			  "r"(r13), "r"(r14)
			: );

	WARN_ON(ret || r10);

	return r11;
}

static void tdx_handle_io(struct pt_regs *regs, u32 exit_qual)
{
	bool string = exit_qual & 16;
	int out, size, port;

	/* I/O strings ops are unrolled at build time. */
	BUG_ON(string);

	out = (exit_qual & 8) ? 0 : 1;
	size = (exit_qual & 7) + 1;
	port = exit_qual >> 16;

	if (out) {
		tdx_out(size, regs->ax, port);
	} else {
		regs->ax &= ~GENMASK(8 * size, 0);
		regs->ax |= tdx_in(size, port) & GENMASK(8 * size, 0);
	}
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
	unsigned long val;
	int ret = 0;

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		tdx_halt();
		break;
	case EXIT_REASON_MSR_READ:
		val = tdx_read_msr_safe(regs->cx, (unsigned int *)&ret);
		if (!ret) {
			regs->ax = val & UINT_MAX;
			regs->dx = val >> 32;
		}
		break;
	case EXIT_REASON_MSR_WRITE:
		ret = tdx_write_msr_safe(regs->cx, regs->ax, regs->dx);
		break;
	case EXIT_REASON_CPUID:
		tdx_handle_cpuid(regs);
		break;
	case EXIT_REASON_IO_INSTRUCTION:
		tdx_handle_io(regs, ve->exit_qual);
		break;
	default:
		pr_warn("Unexpected #VE: %d\n", ve->exit_reason);
		return -EFAULT;
	}

	/* After successful #VE handling, move the IP */
	if (!ret)
		regs->ip += ve->instr_len;

	return ret;
}
