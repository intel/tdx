// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2022 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/export.h>
#include <linux/sched/signal.h>

#include <asm/tdx.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>

/* TDX Module Call Leaf IDs */
#define TDX_GET_VEINFO			3

#define VE_IS_IO_IN(exit_qual)		(((exit_qual) & 8) ? 1 : 0)
#define VE_GET_IO_SIZE(exit_qual)	(((exit_qual) & 7) + 1)
#define VE_GET_PORT_NUM(exit_qual)	((exit_qual) >> 16)
#define VE_IS_IO_STRING(exit_qual)	((exit_qual) & 16 ? 1 : 0)

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

	err = __tdx_hypercall(TDX_HYPERCALL_STANDARD, fn, r12, r13, r14,
			      r15, out);

	/* Non zero return value indicates buggy TDX module, so panic */
	if (err)
		panic("Hypercall fn %llu failed (Buggy TDX module!)\n", fn);

	return out->r10;
}

#ifdef CONFIG_KVM_GUEST
/* Wrapper for KVM vendor specific hypercall */
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4)
{
	struct tdx_hypercall_output out;

	/* Non zero return value indicates buggy TDX module, so panic */
	if (__tdx_hypercall(nr, p1, p2, p3, p4, 0, &out))
		panic("KVM hypercall failed (Buggy TDX module!))\n");

	return out.r10;
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall);
#endif

static __cpuidle void _tdx_halt(const bool irq_disabled, const bool do_sti)
{
	u64 ret;

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
	ret = _tdx_hypercall(EXIT_REASON_HLT, irq_disabled, 0, 0, do_sti, NULL);

	/*
	 * Use WARN_ONCE() to report the failure.
	 */
	WARN_ONCE(ret, "HLT instruction emulation failed\n");
}

static __cpuidle void tdx_halt(void)
{
	/*
	 * Since non safe halt is mainly used in CPU offlining
	 * and the guest will always stay in the halt state, don't
	 * call the STI instruction (set do_sti as false).
	 */
	const bool irq_disabled = irqs_disabled();
	const bool do_sti = false;

	_tdx_halt(irq_disabled, do_sti);
}

static __cpuidle void tdx_safe_halt(void)
{
	 /*
	  * For do_sti=true case, __tdx_hypercall() function enables
	  * interrupts using the STI instruction before the TDCALL. So
	  * set irq_disabled as false.
	  */
	const bool irq_disabled = false;
	const bool do_sti = true;

	_tdx_halt(irq_disabled, do_sti);
}

static bool tdx_read_msr_safe(unsigned int msr, u64 *val)
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

static bool tdx_write_msr_safe(unsigned int msr, unsigned int low,
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

static bool tdx_handle_cpuid(struct pt_regs *regs)
{
	struct tdx_hypercall_output out;

	/*
	 * Emulate the CPUID instruction via a hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	if (_tdx_hypercall(EXIT_REASON_CPUID, regs->ax, regs->cx, 0, 0, &out))
		return false;

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contain contents of
	 * EAX, EBX, ECX, EDX registers after the CPUID instruction execution.
	 * So copy the register contents back to pt_regs.
	 */
	regs->ax = out.r12;
	regs->bx = out.r13;
	regs->cx = out.r14;
	regs->dx = out.r15;

	return true;
}

static unsigned long tdx_mmio(int size, bool write, unsigned long addr,
			      unsigned long *val)
{
	struct tdx_hypercall_output out;
	u64 err;

	err = _tdx_hypercall(EXIT_REASON_EPT_VIOLATION, size, write,
			     addr, *val, &out);
	if (!err)
		*val = out.r11;
	return err;
}

static int tdx_handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	char buffer[MAX_INSN_SIZE];
	unsigned long *reg, val = 0;
	struct insn insn = {};
	enum mmio_type mmio;
	int size, ret;
	u8 sign_byte;

	/* Only in-kernel MMIO is allowed */
	if (user_mode(regs))
		return -EFAULT;

	ret = copy_from_kernel_nofault(buffer, (void *)regs->ip,
				       MAX_INSN_SIZE);
	if (ret)
		return -EFAULT;
	insn_init(&insn, buffer, MAX_INSN_SIZE, 1);
	insn_get_length(&insn);

	mmio = insn_decode_mmio(&insn, &size);
	if (WARN_ON_ONCE(mmio == MMIO_DECODE_FAILED))
		return -EFAULT;

	if (mmio != MMIO_WRITE_IMM && mmio != MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			return -EFAULT;
	}

	switch (mmio) {
	case MMIO_WRITE:
		memcpy(&val, reg, size);
		ret = tdx_mmio(size, true, ve->gpa, &val);
		break;
	case MMIO_WRITE_IMM:
		val = insn.immediate.value;
		ret = tdx_mmio(size, true, ve->gpa, &val);
		break;
	case MMIO_READ:
		ret = tdx_mmio(size, false, ve->gpa, &val);
		if (ret)
			break;
		/* Zero-extend for 32-bit operation */
		if (size == 4)
			*reg = 0;
		memcpy(reg, &val, size);
		break;
	case MMIO_READ_ZERO_EXTEND:
		ret = tdx_mmio(size, false, ve->gpa, &val);
		if (ret)
			break;

		/* Zero extend based on operand size */
		memset(reg, 0, insn.opnd_bytes);
		memcpy(reg, &val, size);
		break;
	case MMIO_READ_SIGN_EXTEND:
		ret = tdx_mmio(size, false, ve->gpa, &val);
		if (ret)
			break;

		if (size == 1)
			sign_byte = (val & 0x80) ? 0xff : 0x00;
		else
			sign_byte = (val & 0x8000) ? 0xff : 0x00;

		/* Sign extend based on operand size */
		memset(reg, sign_byte, insn.opnd_bytes);
		memcpy(reg, &val, size);
		break;
	case MMIO_MOVS:
	case MMIO_DECODE_FAILED:
		return -EFAULT;
	}

	if (ret)
		return -EFAULT;
	return insn.length;
}

/*
 * Handle early I/O, mainly for earlyprintk serial output.
 *
 * Assumes the IO instruction was using ax, which is enforced
 * by the standard io.h macros.
 *
 * Return True on success or False on failure.
 */
static __init bool tdx_early_io(struct pt_regs *regs, u32 exit_qual)
{
	struct tdx_hypercall_output out;
	int size, port, ret;
	u64 mask;
	bool in;

	if (VE_IS_IO_STRING(exit_qual))
		return false;

	in   = VE_IS_IO_IN(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);
	mask = GENMASK(BITS_PER_BYTE * size, 0);

	/*
	 * Emulate the I/O read/write via hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) sec titled "TDG.VP.VMCALL<Instruction.IO>".
	 */
	ret = _tdx_hypercall(EXIT_REASON_IO_INSTRUCTION, size, !in, port,
			     in ? 0 : regs->ax, &out);
	if (!in)
		return !ret;

	regs->ax &= ~mask;
	regs->ax |= ret ? UINT_MAX : out.r11 & mask;

	return !ret;
}

/*
 * Early #VE exception handler. Only handles a subset of port I/O.
 * Intended only for earlyprintk. If failed, return false.
 */
__init bool tdx_early_handle_ve(struct pt_regs *regs)
{
	struct ve_info ve;

	if (tdx_get_ve_info(&ve))
		return false;

	if (ve.exit_reason != EXIT_REASON_IO_INSTRUCTION)
		return false;

	return tdx_early_io(regs, ve.exit_qual);
}

bool tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_output out;

	WARN_ON_ONCE(!ve);

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
	ve->instr_len   = out.r10 & UINT_MAX;
	ve->instr_info  = out.r10 >> 32;

	return true;
}

/*
 * Handle the user initiated #VE.
 *
 * For example, executing the CPUID instruction from the user
 * space is a valid case and hence the resulting #VE had to
 * be handled.
 *
 * For dis-allowed or invalid #VE just return failure.
 *
 * Return True on success and False on failure.
 */
static bool tdx_virt_exception_user(struct pt_regs *regs, struct ve_info *ve)
{
	bool ret = false;

	switch (ve->exit_reason) {
	case EXIT_REASON_CPUID:
		ret = tdx_handle_cpuid(regs);
		break;
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		break;
	}

	return ret;
}

/* Handle the kernel #VE */
static bool tdx_virt_exception_kernel(struct pt_regs *regs, struct ve_info *ve)
{
	bool ret = false;
	u64 val;

	switch (ve->exit_reason) {
	case EXIT_REASON_MSR_READ:
		ret = tdx_read_msr_safe(regs->cx, &val);
		if (ret) {
			regs->ax = (u32)val;
			regs->dx = val >> 32;
		}
		break;
	case EXIT_REASON_MSR_WRITE:
		ret = tdx_write_msr_safe(regs->cx, regs->ax, regs->dx);
		break;
	case EXIT_REASON_CPUID:
		ret = tdx_handle_cpuid(regs);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		/* Currently only MMIO triggers EPT violation */
		ve->instr_len = tdx_handle_mmio(regs, ve);
		ret = ve->instr_len > 0;
		if (!ret)
			pr_warn_once("MMIO failed\n");
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

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp("IntelTDX    ", sig, 12))
		return;

	tdx_guest_detected = true;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	pv_ops.irq.safe_halt = tdx_safe_halt;
	pv_ops.irq.halt = tdx_halt;

	pr_info("Guest detected\n");
}
