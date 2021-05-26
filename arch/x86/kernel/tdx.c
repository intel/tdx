// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "x86/tdx: " fmt

#include <linux/protected_guest.h>

#include <asm/tdx.h>
#include <asm/vmx.h>

/* TDX Module call Leaf IDs */
#define TDINFO				1
#define TDGETVEINFO			3

#define VE_IS_IO_OUT(exit_qual)		(((exit_qual) & 8) ? 0 : 1)
#define VE_GET_IO_SIZE(exit_qual)	(((exit_qual) & 7) + 1)
#define VE_GET_PORT_NUM(exit_qual)	((exit_qual) >> 16)
#define VE_IS_IO_STRING(exit_qual)	((exit_qual) & 16 ? 1 : 0)

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

/*
 * Wrapper for standard use of __tdx_hypercall with BUG_ON() check
 * for TDCALL error.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14,
				 u64 r15, struct tdx_hypercall_output *out)
{
	struct tdx_hypercall_output outl = {0};
	u64 err;

	/* __tdx_hypercall() does not accept NULL output pointer */
	if (!out)
		out = &outl;

	err = __tdx_hypercall(TDX_HYPERCALL_STANDARD, fn, r12, r13, r14,
			      r15, out);

	/* Non zero return value indicates buggy TDX module, so panic */
	BUG_ON(err);

	return out->r10;
}

static inline bool cpuid_has_tdx_guest(void)
{
	u32 eax, sig[3];

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[1], &sig[2]);

	return !memcmp("IntelTDX    ", sig, 12);
}

bool tdx_prot_guest_has(unsigned long flag)
{
	switch (flag) {
	case PR_GUEST_MEM_ENCRYPT:
	case PR_GUEST_MEM_ENCRYPT_ACTIVE:
	case PR_GUEST_UNROLL_STRING_IO:
	case PR_GUEST_SHARED_MAPPING_INIT:
	case PR_GUEST_TDX:
		return cpu_feature_enabled(X86_FEATURE_TDX_GUEST);
	}

	return false;
}
EXPORT_SYMBOL_GPL(tdx_prot_guest_has);

static void tdg_get_info(void)
{
	u64 ret;
	struct tdx_module_output out = {0};

	ret = __tdx_module_call(TDINFO, 0, 0, 0, 0, &out);

	BUG_ON(ret);

	td_info.gpa_width = out.rcx & GENMASK(5, 0);
	td_info.attributes = out.rdx;
}

static __cpuidle void tdg_halt(void)
{
	u64 ret;

	ret = _tdx_hypercall(EXIT_REASON_HLT, irqs_disabled(), 0, 0, 0, NULL);

	/* It should never fail */
	BUG_ON(ret);
}

static __cpuidle void tdg_safe_halt(void)
{
	u64 ret;

	/*
	 * Enable interrupts next to the TDVMCALL to avoid
	 * performance degradation.
	 */
	local_irq_enable();

	/* IRQ is enabled, So set R12 as 0 */
	ret = _tdx_hypercall(EXIT_REASON_HLT, 0, 0, 0, 0, NULL);

	/* It should never fail */
	BUG_ON(ret);
}

static bool tdg_is_context_switched_msr(unsigned int msr)
{
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
	struct tdx_hypercall_output out = {0};

	WARN_ON_ONCE(tdg_is_context_switched_msr(msr));

	ret = _tdx_hypercall(EXIT_REASON_MSR_READ, msr, 0, 0, 0, &out);

	*err = ret ? -EIO : 0;

	return out.r11;
}

static int tdg_write_msr_safe(unsigned int msr, unsigned int low,
			      unsigned int high)
{
	u64 ret;

	WARN_ON_ONCE(tdg_is_context_switched_msr(msr));

	ret = _tdx_hypercall(EXIT_REASON_MSR_WRITE, msr, (u64)high << 32 | low,
			     0, 0, NULL);

	return ret ? -EIO : 0;
}

static void tdg_handle_cpuid(struct pt_regs *regs)
{
	u64 ret;
	struct tdx_hypercall_output out = {0};

	ret = _tdx_hypercall(EXIT_REASON_CPUID, regs->ax, regs->cx, 0, 0, &out);

	WARN_ON(ret);

	regs->ax = out.r12;
	regs->bx = out.r13;
	regs->cx = out.r14;
	regs->dx = out.r15;
}

unsigned long tdg_get_ve_info(struct ve_info *ve)
{
	u64 ret;
	struct tdx_module_output out = {0};

	/*
	 * NMIs and machine checks are suppressed. Before this point any
	 * #VE is fatal. After this point (TDGETVEINFO call), NMIs and
	 * additional #VEs are permitted (but we don't expect them to
	 * happen unless you panic).
	 */
	ret = __tdx_module_call(TDGETVEINFO, 0, 0, 0, 0, &out);

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

/*
 * Handle early IO, mainly for early printks serial output.
 * This avoids anything that doesn't work early on, like tracing
 * or printks, by calling the low level functions directly. Any
 * problems are handled by falling back to a standard early exception.
 *
 * Assumes the IO instruction was using ax, which is enforced
 * by the standard io.h macros.
 */
static __init bool tdg_early_io(struct pt_regs *regs, u32 exit_qual)
{
	struct tdx_hypercall_output outh;
	int out = VE_IS_IO_OUT(exit_qual);
	int size = VE_GET_IO_SIZE(exit_qual);
	int port = VE_GET_PORT_NUM(exit_qual);
	u64 mask = GENMASK(8 * size, 0);
	bool string = VE_IS_IO_STRING(exit_qual);
	int ret;

	/* I/O strings ops are unrolled at build time. */
	if (string)
		return 0;

	ret = _tdx_hypercall(EXIT_REASON_IO_INSTRUCTION, size, out, port,
			     regs->ax, &outh);
	if (!out && !ret) {
		regs->ax &= ~mask;
		regs->ax |= outh.r11 & mask;
	}

	return !ret;
}

/*
 * Early #VE exception handler. Just used to handle port IOs
 * for early_printk. If anything goes wrong handle it like
 * a normal early exception.
 */
__init bool tdg_early_handle_ve(struct pt_regs *regs)
{
	struct ve_info ve;

	if (tdg_get_ve_info(&ve))
		return false;

	if (ve.exit_reason == EXIT_REASON_IO_INSTRUCTION)
		return tdg_early_io(regs, ve.exit_qual);

	return false;
}

void __init tdx_early_init(void)
{
	if (!cpuid_has_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	tdg_get_info();

	pv_ops.irq.safe_halt = tdg_safe_halt;
	pv_ops.irq.halt = tdg_halt;

	pr_info("Guest initialized\n");
}
