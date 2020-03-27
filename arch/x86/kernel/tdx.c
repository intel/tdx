// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#define pr_fmt(fmt) "TDX: " fmt

#include <asm/tdx.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <linux/sched/signal.h> /* force_sig_fault() */

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

static void tdg_out(int size, int port, unsigned int value)
{
	tdvmcall(EXIT_REASON_IO_INSTRUCTION, size, 1, port, value);
}

static unsigned int tdg_in(int size, int port)
{
	return tdvmcall_out_r11(EXIT_REASON_IO_INSTRUCTION, size, 0, port, 0);
}

static void tdg_handle_io(struct pt_regs *regs, u32 exit_qual)
{
	bool string = exit_qual & 16;
	int out, size, port;

	/* I/O strings ops are unrolled at build time. */
	BUG_ON(string);

	out = (exit_qual & 8) ? 0 : 1;
	size = (exit_qual & 7) + 1;
	port = exit_qual >> 16;

	if (out) {
		tdg_out(size, port, regs->ax);
	} else {
		regs->ax &= ~GENMASK(8 * size, 0);
		regs->ax |= tdg_in(size, port) & GENMASK(8 * size, 0);
	}
}

static unsigned long tdg_mmio(int size, bool write, unsigned long addr,
		unsigned long val)
{
	return tdvmcall_out_r11(EXIT_REASON_EPT_VIOLATION, size,
				write, addr, val);
}

static inline void *get_reg_ptr(struct pt_regs *regs, struct insn *insn)
{
	static const int regoff[] = {
		offsetof(struct pt_regs, ax),
		offsetof(struct pt_regs, cx),
		offsetof(struct pt_regs, dx),
		offsetof(struct pt_regs, bx),
		offsetof(struct pt_regs, sp),
		offsetof(struct pt_regs, bp),
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, di),
		offsetof(struct pt_regs, r8),
		offsetof(struct pt_regs, r9),
		offsetof(struct pt_regs, r10),
		offsetof(struct pt_regs, r11),
		offsetof(struct pt_regs, r12),
		offsetof(struct pt_regs, r13),
		offsetof(struct pt_regs, r14),
		offsetof(struct pt_regs, r15),
	};
	int regno;

	regno = X86_MODRM_REG(insn->modrm.value);
	if (X86_REX_R(insn->rex_prefix.value))
		regno += 8;

	return (void *)regs + regoff[regno];
}

static int tdg_handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	int size;
	bool write;
	unsigned long *reg;
	struct insn insn;
	unsigned long val = 0;

	/*
	 * User mode would mean the kernel exposed a device directly
	 * to ring3, which shouldn't happen except for things like
	 * DPDK.
	 */
	if (user_mode(regs)) {
		pr_err("Unexpected user-mode MMIO access.\n");
		force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *) ve->gla);
		return 0;
	}

	kernel_insn_init(&insn, (void *) regs->ip, MAX_INSN_SIZE);
	insn_get_length(&insn);
	insn_get_opcode(&insn);

	write = ve->exit_qual & 0x2;

	size = insn.opnd_bytes;
	switch (insn.opcode.bytes[0]) {
	/* MOV r/m8	r8	*/
	case 0x88:
	/* MOV r8	r/m8	*/
	case 0x8A:
	/* MOV r/m8	imm8	*/
	case 0xC6:
		size = 1;
		break;
	}

	if (inat_has_immediate(insn.attr)) {
		BUG_ON(!write);
		val = insn.immediate.value;
		tdg_mmio(size, write, ve->gpa, val);
		return insn.length;
	}

	BUG_ON(!inat_has_modrm(insn.attr));

	reg = get_reg_ptr(regs, &insn);

	if (write) {
		memcpy(&val, reg, size);
		tdg_mmio(size, write, ve->gpa, val);
	} else {
		val = tdg_mmio(size, write, ve->gpa, val);
		memset(reg, 0, size);
		memcpy(reg, &val, size);
	}
	return insn.length;
}

static int tdg_cpu_offline_prepare(unsigned int cpu)
{
	/*
	 * Per Intel TDX Virtual Firmware Design Guide,
	 * sec 4.3.5 and sec 9.4, Hotplug is not supported
	 * in TDX platforms. So don't support CPU
	 * offline feature once its turned on.
	 */
	return -EOPNOTSUPP;
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
	case EXIT_REASON_IO_INSTRUCTION:
		tdg_handle_io(regs, ve->exit_qual);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		ve->instr_len = tdg_handle_mmio(regs, ve);
		break;
	case EXIT_REASON_WBINVD:
		/*
		 * WBINVD is not supported inside TDX guests. All in-
		 * kernel uses should have been disabled.
		 */
		WARN_ONCE(1, "TD Guest used unsupported WBINVD instruction\n");
		break;
	case EXIT_REASON_MONITOR_INSTRUCTION:
	case EXIT_REASON_MWAIT_INSTRUCTION:
		/*
		 * Something in the kernel used MONITOR or MWAIT despite
		 * X86_FEATURE_MWAIT being cleared for TDX guests.
		 */
		WARN_ONCE(1, "TD Guest used unsupported MWAIT/MONITOR instruction\n");
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

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "tdg:cpu_hotplug",
			  NULL, tdg_cpu_offline_prepare);

	pr_info("TDX guest is initialized\n");
}
