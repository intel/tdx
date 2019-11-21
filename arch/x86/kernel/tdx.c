// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2022 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/cpufeature.h>
#include <asm/tdx.h>
#include <asm/vmx.h>

/* TDX module Call Leaf IDs */
#define TDX_GET_VEINFO			3

static bool tdx_guest_detected __ro_after_init;

/*
 * Wrapper for standard use of __tdx_hypercall with panic report
 * for TDCALL error.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14,
				 u64 r15, struct tdx_hypercall_output *out)
{
	struct tdx_hypercall_output dummy_out;
	u64 err;

	/* __tdx_hypercall() does not accept NULL output pointer */
	if (!out)
		out = &dummy_out;

	/* Non zero return value indicates buggy TDX module, so panic */
	err = __tdx_hypercall(TDX_HYPERCALL_STANDARD, fn, r12, r13, r14,
			      r15, out);
	if (err)
		panic("Hypercall fn %llu failed (Buggy TDX module!)\n", fn);

	return out->r10;
}

static u64 __cpuidle _tdx_halt(const bool irq_disabled, const bool do_sti)
{
	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec 3.8 TDG.VP.VMCALL<Instruction.HLT>.
	 *
	 * The VMM uses the "IRQ disabled" param to understand IRQ
	 * enabled status (RFLAGS.IF) of the TD guest and to determine
	 * whether or not it should schedule the halted vCPU if an
	 * IRQ becomes pending. E.g. if IRQs are disabled, the VMM
	 * can keep the vCPU in virtual HLT, even if an IRQ is
	 * pending, without hanging/breaking the guest.
	 *
	 * do_sti parameter is used by the __tdx_hypercall() to decide
	 * whether to call the STI instruction before executing the
	 * TDCALL instruction.
	 */
	return _tdx_hypercall(EXIT_REASON_HLT, irq_disabled, 0, 0,
			      do_sti, NULL);
}

static bool tdx_halt(void)
{
	/*
	 * Since non safe halt is mainly used in CPU offlining
	 * and the guest will always stay in the halt state, don't
	 * call the STI instruction (set do_sti as false).
	 */
	const bool irq_disabled = irqs_disabled();
	const bool do_sti = false;

	if (_tdx_halt(irq_disabled, do_sti))
		return false;

	return true;
}

void __cpuidle tdx_safe_halt(void)
{
	 /*
	  * For do_sti=true case, __tdx_hypercall() function enables
	  * interrupts using the STI instruction before the TDCALL. So
	  * set irq_disabled as false.
	  */
	const bool irq_disabled = false;
	const bool do_sti = true;

	/*
	 * Use WARN_ONCE() to report the failure.
	 */
	if (_tdx_halt(irq_disabled, do_sti))
		WARN_ONCE(1, "HLT instruction emulation failed\n");
}

static bool tdx_read_msr(unsigned int msr, u64 *val)
{
	struct tdx_hypercall_output out;

	/*
	 * Emulate the MSR read via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec titled "TDG.VP.VMCALL<Instruction.RDMSR>".
	 */
	if (_tdx_hypercall(EXIT_REASON_MSR_READ, msr, 0, 0, 0, &out))
		return false;

	*val = out.r11;

	return true;
}

static bool tdx_write_msr(unsigned int msr, unsigned int low,
			       unsigned int high)
{
	u64 ret;

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) sec titled "TDG.VP.VMCALL<Instruction.WRMSR>".
	 */
	ret = _tdx_hypercall(EXIT_REASON_MSR_WRITE, msr, (u64)high << 32 | low,
			     0, 0, NULL);

	return ret ? false : true;
}

bool tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_output out;

	/*
	 * NMIs and machine checks are suppressed. Before this point any
	 * #VE is fatal. After this point (TDGETVEINFO call), NMIs and
	 * additional #VEs are permitted (but it is expected not to
	 * happen unless kernel panics).
	 */
	if (__tdx_module_call(TDX_GET_VEINFO, 0, 0, 0, 0, &out))
		return false;

	ve->exit_reason = out.rcx;
	ve->exit_qual   = out.rdx;
	ve->gla         = out.r8;
	ve->gpa         = out.r9;
	ve->instr_len   = lower_32_bits(out.r10);
	ve->instr_info  = upper_32_bits(out.r10);

	return true;
}

/*
 * Handle the user initiated #VE.
 *
 * For example, executing the CPUID instruction from user space
 * is a valid case and hence the resulting #VE has to be handled.
 *
 * For dis-allowed or invalid #VE just return failure.
 */
static bool tdx_virt_exception_user(struct pt_regs *regs, struct ve_info *ve)
{
	pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
	return false;
}

/* Handle the kernel #VE */
static bool tdx_virt_exception_kernel(struct pt_regs *regs, struct ve_info *ve)
{
	bool ret = false;
	u64 val;

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		ret = tdx_halt();
		break;
	case EXIT_REASON_MSR_READ:
		ret = tdx_read_msr(regs->cx, &val);
		if (ret) {
			regs->ax = lower_32_bits(val);
			regs->dx = upper_32_bits(val);
		}
		break;
	case EXIT_REASON_MSR_WRITE:
		ret = tdx_write_msr(regs->cx, regs->ax, regs->dx);
		break;
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		break;
	}

	return ret;
}

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve)
{
	bool ret;

	if (user_mode(regs))
		ret = tdx_virt_exception_user(regs, ve);
	else
		ret = tdx_virt_exception_kernel(regs, ve);

	/* After successful #VE handling, move the IP */
	if (ret)
		regs->ip += ve->instr_len;

	return ret;
}

bool is_tdx_guest(void)
{
	return tdx_guest_detected;
}

void __init tdx_early_init(void)
{
	u32 eax, sig[3];

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, 12))
		return;

	tdx_guest_detected = true;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	pr_info("Guest detected\n");
}
