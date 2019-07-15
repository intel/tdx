// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "x86/tdx: " fmt

#include <linux/protected_guest.h>
#include <linux/cpuhotplug.h>

#include <asm/tdx.h>
#include <asm/cmdline.h>
#include <asm/i8259.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <linux/sched/signal.h> /* force_sig_fault() */
#include <linux/swiotlb.h>

#define CREATE_TRACE_POINTS
#include <asm/trace/tdx.h>

/* TDX Module call Leaf IDs */
#define TDINFO				1
#define TDGETVEINFO			3
#define TDACCEPTPAGE			6

/* TDX hypercall Leaf IDs */
#define TDVMCALL_MAP_GPA		0x10001

/* TDX Module call error codes */
#define TDX_PAGE_ALREADY_ACCEPTED       0x8000000000000001

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

/* The highest bit of a guest physical address is the "sharing" bit */
phys_addr_t tdg_shared_mask(void)
{
	return 1ULL << (td_info.gpa_width - 1);
}

static void tdg_get_info(void)
{
	u64 ret;
	struct tdx_module_output out = {0};

	ret = __tdx_module_call(TDINFO, 0, 0, 0, 0, &out);

	BUG_ON(ret);

	td_info.gpa_width = out.rcx & GENMASK(5, 0);
	td_info.attributes = out.rdx;

	/* Exclude Shared bit from the __PHYSICAL_MASK */
	physical_mask &= ~tdg_shared_mask();
}

static void tdg_accept_page(phys_addr_t gpa)
{
	u64 ret;

	ret = __tdx_module_call(TDACCEPTPAGE, gpa, 0, 0, 0, NULL);

	BUG_ON(ret && ret != TDX_PAGE_ALREADY_ACCEPTED);
}

/*
 * Inform the VMM of the guest's intent for this physical page:
 * shared with the VMM or private to the guest.  The VMM is
 * expected to change its mapping of the page in response.
 */
int tdx_hcall_gpa_intent(phys_addr_t gpa, int numpages,
			 enum tdx_map_type map_type)
{
	u64 ret = 0;
	int i;

	if (map_type == TDX_MAP_SHARED)
		gpa |= tdg_shared_mask();

	ret = _tdx_hypercall(TDVMCALL_MAP_GPA, gpa, PAGE_SIZE * numpages, 0, 0,
			     NULL);
	if (ret)
		ret = -EIO;

	if (ret || map_type == TDX_MAP_SHARED)
		return ret;

	/*
	 * For shared->private conversion, accept the page using TDACCEPTPAGE
	 * TDX module call.
	 */
	for (i = 0; i < numpages; i++)
		tdg_accept_page(gpa + i * PAGE_SIZE);

	return 0;
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

/*
 * tdx_handle_early_io() cannot be re-used in #VE handler for handling
 * I/O because the way of handling string I/O is different between
 * normal and early I/O case. Also, once trace support is enabled,
 * tdg_handle_io() will be extended to use trace calls which is also
 * not valid for early I/O cases.
 */
static void tdg_handle_io(struct pt_regs *regs, u32 exit_qual)
{
	struct tdx_hypercall_output outh;
	int out = VE_IS_IO_OUT(exit_qual);
	int size = VE_GET_IO_SIZE(exit_qual);
	int port = VE_GET_PORT_NUM(exit_qual);
	u64 mask = GENMASK(8 * size, 0);
	bool string = VE_IS_IO_STRING(exit_qual);
	int ret;

	/* I/O strings ops are unrolled at build time. */
	BUG_ON(string);

	ret = _tdx_hypercall(EXIT_REASON_IO_INSTRUCTION, size, out, port,
			     regs->ax, &outh);
	if (!out) {
		regs->ax &= ~mask;
		regs->ax |= (ret ? UINT_MAX : outh.r11) & mask;
	}
}

static unsigned long tdg_mmio(int size, bool write, unsigned long addr,
			      unsigned long *val)
{
	struct tdx_hypercall_output out = {0};
	u64 err;

	err = _tdx_hypercall(EXIT_REASON_EPT_VIOLATION, size, write,
			     addr, *val, &out);
	*val = out.r11;
	return err;
}

static int tdg_handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	struct insn insn = {};
	char buffer[MAX_INSN_SIZE];
	enum mmio_type mmio;
	unsigned long *reg;
	int size, ret;
	u8 sign_byte;
	unsigned long val;

	if (user_mode(regs)) {
		ret = insn_fetch_from_user(regs, buffer);
		if (!ret)
			return -EFAULT;
		if (!insn_decode_from_regs(&insn, regs, buffer, ret))
			return -EFAULT;
	} else {
		ret = copy_from_kernel_nofault(buffer, (void *)regs->ip,
					       MAX_INSN_SIZE);
		if (ret)
			return -EFAULT;
		insn_init(&insn, buffer, MAX_INSN_SIZE, 1);
		insn_get_length(&insn);
	}

	mmio = insn_decode_mmio(&insn, &size);
	if (mmio == MMIO_DECODE_FAILED)
		return -EFAULT;

	if (mmio != MMIO_WRITE_IMM && mmio != MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			return -EFAULT;
	}

	switch (mmio) {
	case MMIO_WRITE:
		memcpy(&val, reg, size);
		ret = tdg_mmio(size, true, ve->gpa, &val);
		break;
	case MMIO_WRITE_IMM:
		val = insn.immediate.value;
		ret = tdg_mmio(size, true, ve->gpa, &val);
		break;
	case MMIO_READ:
		ret = tdg_mmio(size, false, ve->gpa, &val);
		if (ret)
			break;
		/* Zero-extend for 32-bit operation */
		if (size == 4)
			*reg = 0;
		memcpy(reg, &val, size);
		break;
	case MMIO_READ_ZERO_EXTEND:
		ret = tdg_mmio(size, false, ve->gpa, &val);
		if (ret)
			break;

		/* Zero extend based on operand size */
		memset(reg, 0, insn.opnd_bytes);
		memcpy(reg, &val, size);
		break;
	case MMIO_READ_SIGN_EXTEND:
		ret = tdg_mmio(size, false, ve->gpa, &val);
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

static int tdg_cpu_offline_prepare(unsigned int cpu)
{
	/*
	 * Per Intel TDX Virtual Firmware Design Guide,
	 * sec 4.3.5 and sec 9.4, Hotplug is not supported
	 * in TDX platforms. So don't support CPU
	 * offline feature once it is turned on.
	 */
	return -EOPNOTSUPP;
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

	trace_tdg_virtualization_exception_rcuidle(regs->ip, ve->exit_reason,
		ve->exit_qual, ve->gpa, ve->instr_len, ve->instr_info);

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
		/* Currently only MMIO triggers EPT violation */
		ve->instr_len = tdg_handle_mmio(regs, ve);
		if (ve->instr_len < 0) {
			pr_warn_once("MMIO failed\n");
			return -EFAULT;
		}
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
	bool tdg_forced;

	tdg_forced = cmdline_find_option_bool(boot_command_line,
					      "force_tdx_guest");
	if (tdg_forced)
		pr_info("Force enabling TDX Guest feature\n");

	if (!cpuid_has_tdx_guest() && !tdg_forced)
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	tdg_get_info();

	pv_ops.irq.safe_halt = tdg_safe_halt;
	pv_ops.irq.halt = tdg_halt;

	legacy_pic = &null_legacy_pic;

	swiotlb_force = SWIOTLB_FORCE;

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "tdg:cpu_hotplug",
			  NULL, tdg_cpu_offline_prepare);

	pr_info("Guest initialized\n");
}
