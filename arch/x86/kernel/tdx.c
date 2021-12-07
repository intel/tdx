// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2022 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/cpufeature.h>
#include <linux/swiotlb.h>
#include <asm/tdx.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>

/* TDX module Call Leaf IDs */
#define TDX_GET_INFO			1
#define TDX_GET_VEINFO			3
#define TDX_ACCEPT_PAGE			6

/* TDX hypercall Leaf IDs */
#define TDVMCALL_MAP_GPA		0x10001

/* MMIO direction */
#define EPT_READ	0
#define EPT_WRITE	1

/* See Exit Qualification for I/O Instructions in VMX documentation */
#define VE_IS_IO_IN(e)		((e) & BIT(3))
#define VE_GET_IO_SIZE(e)	(((e) & GENMASK(2, 0)) + 1)
#define VE_GET_PORT_NUM(e)	((e) >> 16)
#define VE_IS_IO_STRING(e)	((e) & BIT(4))

/* Guest TD execution environment information */
static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

/*
 * Wrapper for standard use of __tdx_hypercall with panic report
 * for TDCALL error.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = fn,
		.r12 = r12,
		.r13 = r13,
		.r14 = r14,
		.r15 = r15,
	};

	if (__tdx_hypercall(&args))
		panic("Hypercall fn %llu failed (Buggy TDX module!)\n", fn);

	return args.r10;
}

#ifdef CONFIG_KVM_GUEST
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4)
{
	struct tdx_hypercall_args args = {
		.r10 = nr,
		.r11 = p1,
		.r12 = p2,
		.r13 = p3,
		.r14 = p4,
	};

	if (__tdx_hypercall(&args))
		panic("KVM hypercall %u failed. Buggy TDX module?\n", nr);

	return args.r10;
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall);
#endif

/*
 * The highest bit of a guest physical address is the "sharing" bit.
 * Set it for shared pages and clear it for private pages.
 */
phys_addr_t tdx_shared_mask(void)
{
	return BIT_ULL(td_info.gpa_width - 1);
}

static void tdx_get_info(void)
{
	struct tdx_module_output out;

	/*
	 * TDINFO TDX module call is used to get the TD execution environment
	 * information like GPA width, number of available vcpus, debug mode
	 * information, etc. More details about the ABI can be found in TDX
	 * Guest-Host-Communication Interface (GHCI), section 2.4.2 TDCALL
	 * [TDG.VP.INFO].
	 */
	if (__tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out))
		panic("TDINFO TDCALL failed (Buggy TDX module!)\n");

	td_info.gpa_width = out.rcx & GENMASK(5, 0);
	td_info.attributes = out.rdx;
}

static bool tdx_accept_page(phys_addr_t gpa, enum pg_level pg_level)
{
	/*
	 * Pass the page physical address to the TDX module to accept the
	 * pending, private page.
	 *
	 * Bits 2:0 of GPA encode page size: 0 - 4K, 1 - 2M, 2 - 1G.
	 */
	switch (pg_level) {
	case PG_LEVEL_4K:
		break;
	case PG_LEVEL_2M:
		gpa |= 1;
		break;
	case PG_LEVEL_1G:
		gpa |= 2;
		break;
	default:
		return false;
	}

	return !__tdx_module_call(TDX_ACCEPT_PAGE, gpa, 0, 0, 0, NULL);
}

/*
 * Inform the VMM of the guest's intent for this physical page: shared with
 * the VMM or private to the guest.  The VMM is expected to change its mapping
 * of the page in response.
 */
int tdx_hcall_request_gpa_type(phys_addr_t start, phys_addr_t end, bool enc)
{
	u64 ret;

	if (end <= start)
		return -EINVAL;

	if (!enc) {
		start |= tdx_shared_mask();
		end |= tdx_shared_mask();
	}

	/*
	 * Notify the VMM about page mapping conversion. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface (GHCI),
	 * section "TDG.VP.VMCALL<MapGPA>"
	 */
	ret = _tdx_hypercall(TDVMCALL_MAP_GPA, start, end - start, 0, 0);

	if (ret)
		ret = -EIO;

	if (ret || !enc)
		return ret;

	/*
	 * For shared->private conversion, accept the page using
	 * TDX_ACCEPT_PAGE TDX module call.
	 */
	while (start < end) {
		/* Try if 1G page accept is possible */
		if (!(start & ~PUD_MASK) && end - start >= PUD_SIZE &&
		    tdx_accept_page(start, PG_LEVEL_1G)) {
			start += PUD_SIZE;
			continue;
		}

		/* Try if 2M page accept is possible */
		if (!(start & ~PMD_MASK) && end - start >= PMD_SIZE &&
		    tdx_accept_page(start, PG_LEVEL_2M)) {
			start += PMD_SIZE;
			continue;
		}

		if (!tdx_accept_page(start, PG_LEVEL_4K))
			return -EIO;
		start += PAGE_SIZE;
	}

	return 0;
}

static u64 __cpuidle _tdx_halt(const bool irq_disabled, const bool do_sti)
{
	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section 3.8 TDG.VP.VMCALL<Instruction.HLT>.
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
	return _tdx_hypercall(EXIT_REASON_HLT, irq_disabled, 0, 0, do_sti);
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

static bool tdx_read_msr(struct pt_regs *regs)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_MSR_READ,
		.r12 = regs->cx,
	};

	/*
	 * Emulate the MSR read via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "TDG.VP.VMCALL<Instruction.RDMSR>".
	 */
	if (__tdx_hypercall(&args))
		panic("Hypercall failed (Buggy TDX module!)\n");

	if (args.r10)
		return false;

	regs->ax = lower_32_bits(args.r11);
	regs->dx = upper_32_bits(args.r11);
	return true;
}

static bool tdx_write_msr(struct pt_regs *regs)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_MSR_WRITE,
		.r12 = regs->cx,
		.r13 = (u64)regs->dx << 32 | regs->ax,
	};

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) section titled "TDG.VP.VMCALL<Instruction.WRMSR>".
	 */
	if (__tdx_hypercall(&args))
		panic("Hypercall failed (Buggy TDX module!)\n");

	return !args.r10;
}

static bool tdx_handle_cpuid(struct pt_regs *regs)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_CPUID,
		.r12 = regs->ax,
		.r13 = regs->cx,
	};

	/*
	 * Emulate the CPUID instruction via a hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	if (__tdx_hypercall(&args))
		panic("Hypercall failed (Buggy TDX module!)\n");
	if (args.r10)
		return false;

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contain contents of
	 * EAX, EBX, ECX, EDX registers after the CPUID instruction execution.
	 * So copy the register contents back to pt_regs.
	 */
	regs->ax = args.r12;
	regs->bx = args.r13;
	regs->cx = args.r14;
	regs->dx = args.r15;

	return true;
}

static bool tdx_mmio_read(int size, unsigned long addr, unsigned long *val)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_EPT_VIOLATION,
		.r12 = size,
		.r13 = EPT_READ,
		.r14 = addr,
		.r15 = *val,
	};

	if (__tdx_hypercall(&args))
		panic("Hypercall failed (Buggy TDX module!)\n");
	if (args.r10)
		return false;
	*val = args.r11;
	return true;
}

static bool tdx_mmio_write(int size, unsigned long addr, unsigned long val)
{
	return !_tdx_hypercall(EXIT_REASON_EPT_VIOLATION, size, EPT_WRITE,
			       addr, val);
}

static int tdx_handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	char buffer[MAX_INSN_SIZE];
	unsigned long *reg, val;
	struct insn insn = {};
	enum mmio_type mmio;
	int size, extend_size;
	u8 extend_val = 0;

	if (copy_from_kernel_nofault(buffer, (void *)regs->ip, MAX_INSN_SIZE))
		return false;

	if (insn_decode(&insn, buffer, MAX_INSN_SIZE, INSN_MODE_64))
		return false;

	mmio = insn_decode_mmio(&insn, &size);
	if (WARN_ON_ONCE(mmio == MMIO_DECODE_FAILED))
		return false;

	if (mmio != MMIO_WRITE_IMM && mmio != MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			return false;
	}

	ve->instr_len = insn.length;

	switch (mmio) {
	case MMIO_WRITE:
		memcpy(&val, reg, size);
		return tdx_mmio_write(size, ve->gpa, val);
		break;
	case MMIO_WRITE_IMM:
		val = insn.immediate.value;
		return tdx_mmio_write(size, ve->gpa, val);
		break;
	case MMIO_READ:
	case MMIO_READ_ZERO_EXTEND:
	case MMIO_READ_SIGN_EXTEND:
		break;
	case MMIO_MOVS:
	case MMIO_DECODE_FAILED:
		return false;
	default:
		BUG();
	}

	/* Handle reads */
	if (!tdx_mmio_read(size, ve->gpa, &val))
		return false;

	switch (mmio) {
	case MMIO_READ:
		/* Zero-extend for 32-bit operation */
		extend_size = size == 4 ? sizeof(*reg) : 0;
		break;
	case MMIO_READ_ZERO_EXTEND:
		/* Zero extend based on operand size */
		extend_size = insn.opnd_bytes;
		break;
	case MMIO_READ_SIGN_EXTEND:
		/* Sign extend based on operand size */
		extend_size = insn.opnd_bytes;
		if (size == 1 && val & BIT(7))
			extend_val = 0xFF;
		else if (size > 1 && val & BIT(15))
			extend_val = 0xFF;
		break;
	case MMIO_MOVS:
	case MMIO_DECODE_FAILED:
		return false;
	default:
		BUG();
	}

	if (extend_size)
		memset(reg, extend_val, extend_size);
	memcpy(reg, &val, size);
	return true;
}

/*
 * Emulate I/O using hypercall.
 *
 * Assumes the IO instruction was using ax, which is enforced
 * by the standard io.h macros.
 *
 * Return True on success or False on failure.
 */
static bool tdx_handle_io(struct pt_regs *regs, u32 exit_qual)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_IO_INSTRUCTION,
	};
	int size, port;
	u64 mask;
	bool in;

	if (VE_IS_IO_STRING(exit_qual))
		return false;

	in   = VE_IS_IO_IN(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);
	mask = GENMASK(BITS_PER_BYTE * size, 0);

	args.r12 = size;
	args.r13 = !in;
	args.r14 = port;
	args.r15 = in ? 0 : regs->ax;

	/*
	 * Emulate the I/O read/write via hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) section titled "TDG.VP.VMCALL<Instruction.IO>".
	 */
	if (__tdx_hypercall(&args))
		panic("Hypercall failed (Buggy TDX module!)\n");
	if (!in)
		return !args.r10;

	regs->ax &= ~mask;
	regs->ax |= args.r10 ? UINT_MAX : args.r11 & mask;

	return !args.r10;
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

	return tdx_handle_io(regs, ve.exit_qual);
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
	switch (ve->exit_reason) {
	case EXIT_REASON_CPUID:
		return tdx_handle_cpuid(regs);
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return false;
	}
}

/* Handle the kernel #VE */
static bool tdx_virt_exception_kernel(struct pt_regs *regs, struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		return tdx_halt();
	case EXIT_REASON_MSR_READ:
		return tdx_read_msr(regs);
	case EXIT_REASON_MSR_WRITE:
		return tdx_write_msr(regs);
	case EXIT_REASON_CPUID:
		return tdx_handle_cpuid(regs);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_handle_mmio(regs, ve);
	case EXIT_REASON_IO_INSTRUCTION:
		return tdx_handle_io(regs, ve->exit_qual);
	case EXIT_REASON_WBINVD:
		WARN_ONCE(1, "Unexpected WBINVD\n");
		return true;
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return false;
	}
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

void __init tdx_early_init(void)
{
	u32 eax, sig[3];

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, 12))
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	tdx_get_info();

	/*
	 * All bits above GPA width are reserved and kernel treats shared bit
	 * as flag, not as part of physical address.
	 *
	 * Adjust physical mask to only cover valid GPA bits.
	 */
	physical_mask &= GENMASK_ULL(td_info.gpa_width - 2, 0);

	swiotlb_force = SWIOTLB_FORCE;

	pr_info("Guest detected\n");
}
