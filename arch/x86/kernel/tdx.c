// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#define pr_fmt(fmt) "TDX: " fmt

#include <asm/tdx.h>
#include <asm/vmx.h>

#include <linux/cpu.h>

#ifdef CONFIG_KVM_GUEST
#include "tdx-kvm.c"
#endif

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

/*
 * Wrapper for use case that checks for error code and print warning message.
 */
static inline u64 tdvmcall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	u64 err;

	err = __tdvmcall(fn, r12, r13, r14, r15, NULL);

	if (err)
		pr_warn_ratelimited("TDVMCALL fn:%llx failed with err:%llx\n",
				    fn, err);

	return err;
}

/*
 * Wrapper for the semi-common case where we need single output value (R11).
 */
static inline u64 tdvmcall_out_r11(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{

	struct tdvmcall_output out = {0};
	u64 err;

	err = __tdvmcall(fn, r12, r13, r14, r15, &out);

	if (err)
		pr_warn_ratelimited("TDVMCALL fn:%llx failed with err:%llx\n",
				    fn, err);

	return out.r11;
}

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

static void tdg_get_info(void)
{
	u64 ret;
	struct tdcall_output out = {0};

	ret = __tdcall(TDINFO, 0, 0, 0, 0, &out);

	BUG_ON(ret);

	td_info.gpa_width = out.rcx & GENMASK(5, 0);
	td_info.attributes = out.rdx;
}

static __cpuidle void tdg_halt(void)
{
	u64 ret;

	ret = __tdvmcall(EXIT_REASON_HLT, 0, 0, 0, 0, NULL);

	/* It should never fail */
	BUG_ON(ret);
}

static __cpuidle void tdg_safe_halt(void)
{
	/*
	 * Enable interrupts next to the TDVMCALL to avoid
	 * performance degradation.
	 */
	asm volatile("sti\n\t");

	tdg_halt();
}

static bool tdg_is_context_switched_msr(unsigned int msr)
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

static u64 tdg_read_msr_safe(unsigned int msr, int *err)
{
	u64 ret;
	struct tdvmcall_output out = {0};

	WARN_ON_ONCE(tdg_is_context_switched_msr(msr));

	/*
	 * Since CSTAR MSR is not used by Intel CPUs as SYSCALL
	 * instruction, just ignore it. Even raising TDVMCALL
	 * will lead to same result.
	 */
	if (msr == MSR_CSTAR)
		return 0;

	ret = __tdvmcall(EXIT_REASON_MSR_READ, msr, 0, 0, 0, &out);

	*err = (ret) ? -EIO : 0;

	return out.r11;
}

static int tdg_write_msr_safe(unsigned int msr, unsigned int low,
			      unsigned int high)
{
	u64 ret;

	WARN_ON_ONCE(tdg_is_context_switched_msr(msr));

	/*
	 * Since CSTAR MSR is not used by Intel CPUs as SYSCALL
	 * instruction, just ignore it. Even raising TDVMCALL
	 * will lead to same result.
	 */
	if (msr == MSR_CSTAR)
		return 0;

	ret = __tdvmcall(EXIT_REASON_MSR_WRITE, msr, (u64)high << 32 | low,
			 0, 0, NULL);

	return ret ? -EIO : 0;
}

static void tdg_handle_cpuid(struct pt_regs *regs)
{
	u64 ret;
	struct tdvmcall_output out = {0};

	ret = __tdvmcall(EXIT_REASON_CPUID, regs->ax, regs->cx, 0, 0, &out);

	WARN_ON(ret);

	regs->ax = out.r12;
	regs->bx = out.r13;
	regs->cx = out.r14;
	regs->dx = out.r15;
}

unsigned long tdg_get_ve_info(struct ve_info *ve)
{
	u64 ret;
	struct tdcall_output out = {0};

	/*
	 * The #VE cannot be nested before TDGETVEINFO is called,
	 * if there is any reason for it to nest the TD would shut
	 * down. The TDX module guarantees that no NMIs (or #MC or
	 * similar) can happen in this window. After TDGETVEINFO
	 * the #VE handler can nest if needed, although we don’t
	 * expect it to happen normally.
	 */

	ret = __tdcall(TDGETVEINFO, 0, 0, 0, 0, &out);

	ve->exit_reason = out.rcx;
	ve->exit_qual   = out.rdx;
	ve->gla         = out.r8;
	ve->gpa         = out.r9;
	ve->instr_len   = out.r10 & UINT_MAX;
	ve->instr_info  = out.r10 >> 32;

	return ret;
}

int tdg_handle_virtualization_exception(struct pt_regs *regs,
		struct ve_info *ve)
{
	unsigned long val;
	int ret = 0;

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		tdg_halt();
		break;
	case EXIT_REASON_MSR_READ:
		val = tdg_read_msr_safe(regs->cx, (unsigned int *)&ret);
		if (!ret) {
			regs->ax = val & UINT_MAX;
			regs->dx = val >> 32;
		}
		break;
	case EXIT_REASON_MSR_WRITE:
		ret = tdg_write_msr_safe(regs->cx, regs->ax, regs->dx);
		break;
	case EXIT_REASON_CPUID:
		tdg_handle_cpuid(regs);
		break;
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return -EFAULT;
	}

	/* After successful #VE handling, move the IP */
	if (!ret)
		regs->ip += ve->instr_len;

	return ret;
}

void __init tdx_early_init(void)
{
	if (!cpuid_has_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	tdg_get_info();

	pv_ops.irq.safe_halt = tdg_safe_halt;
	pv_ops.irq.halt = tdg_halt;

	pr_info("TDX guest is initialized\n");
}
