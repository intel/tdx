// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/cpuhotplug.h>

#include <asm/tdx.h>
#include <asm/i8259.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <linux/sched/signal.h> /* force_sig_fault() */
#include <linux/swiotlb.h>

#define CREATE_TRACE_POINTS
#include <asm/trace/tdx.h>

/* TDX Module call Leaf IDs */
#define TDX_GET_INFO			1
#define TDX_GET_VEINFO			3
#define TDX_GET_REPORT			4
#define TDX_ACCEPT_PAGE			6

/* TDX hypercall Leaf IDs */
#define TDVMCALL_MAP_GPA		0x10001

/* TDX Module call error codes */
#define TDX_PAGE_ALREADY_ACCEPTED	0x00000b0a00000000
#define TDCALL_RETURN_CODE_MASK		0xFFFFFFFF00000000
#define TDCALL_OPERAND_BUSY		0x8000020000000000
#define TDCALL_INVALID_OPERAND		0x8000000000000000
#define TDCALL_SUCCESS			0x0
#define TDCALL_RETURN_CODE(a)		((a) & TDCALL_RETURN_CODE_MASK)

#define VE_IS_IO_OUT(exit_qual)		(((exit_qual) & 8) ? 0 : 1)
#define VE_GET_IO_SIZE(exit_qual)	(((exit_qual) & 7) + 1)
#define VE_GET_PORT_NUM(exit_qual)	((exit_qual) >> 16)
#define VE_IS_IO_STRING(exit_qual)	((exit_qual) & 16 ? 1 : 0)

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

bool is_tdx_guest(void)
{
	static int tdx_guest = -1;
	u32 eax, sig[3];

	if (tdx_guest >= 0)
		goto done;

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID) {
		tdx_guest = 0;
		goto done;
	}

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2], &sig[1]);

	tdx_guest = !memcmp("IntelTDX    ", sig, 12);

done:
	return !!tdx_guest;
}

/*
 * Wrapper for standard use of __tdx_hypercall with BUG_ON() check
 * for TDCALL error.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14,
				 u64 r15, struct tdx_hypercall_output *out)
{
	struct tdx_hypercall_output outl;
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

/* Traced version of _tdx_hypercall() */
static u64 _trace_tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15,
				struct tdx_hypercall_output *out)
{
	struct tdx_hypercall_output dummy_out;
	u64 err;

	trace_tdx_hypercall_enter_rcuidle(fn, r12, r13, r14, r15);
	err = _tdx_hypercall(fn, r12, r13, r14, r15, out);
	if (!out)
		out = &dummy_out;
	trace_tdx_hypercall_exit_rcuidle(err, out->r11, out->r12, out->r13,
					 out->r14, out->r15);

	return err;
}

static u64 __trace_tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
				   struct tdx_module_output *out)
{
	struct tdx_module_output dummy_out;
	u64 err;

	trace_tdx_module_call_enter_rcuidle(fn, rcx, rdx, r8, r9);
	err = __tdx_module_call(fn, rcx, rdx, r8, r9, out);
	if (!out)
		out = &dummy_out;
	trace_tdx_module_call_exit_rcuidle(err, out->rcx, out->rdx, out->r8,
					   out->r9, out->r10, out->r11);

	return err;
}

/* The highest bit of a guest physical address is the "sharing" bit */
phys_addr_t tdx_shared_mask(void)
{
	return 1ULL << (td_info.gpa_width - 1);
}

/*
 * tdx_mcall_tdreport() - Generate TDREPORT_STRUCT using TDCALL.
 *
 * @data        : Physical address of 1024B aligned data to store
 *                TDREPORT_STRUCT.
 * @reportdata  : Physical address of 64B aligned report data
 *
 * return 0 on success or failure error number.
 */
int tdx_mcall_tdreport(u64 data, u64 reportdata)
{
	u64 ret;

	/*
	 * Use confidential guest TDX check to ensure this API is only
	 * used by TDX guest platforms.
	 */
	if (!data || !reportdata || !cc_platform_has(CC_ATTR_GUEST_TDX))
		return -EINVAL;

	/*
	 * Pass the physical address of user generated reportdata
	 * and the physical address of out pointer to store the
	 * tdreport data to the TDX module to generate the
	 * TD report. Generated data contains measurements/configuration
	 * data of the TD guest. More info about ABI can be found in TDX
	 * Guest-Host-Communication Interface (GHCI), sec 2.4.5.
	 */
	ret = __trace_tdx_module_call(TDX_GET_REPORT, data, reportdata, 0, 0,
				      NULL);

	if (ret == TDCALL_SUCCESS)
		return 0;
	else if (TDCALL_RETURN_CODE(ret) == TDCALL_INVALID_OPERAND)
		return -EINVAL;
	else if (TDCALL_RETURN_CODE(ret) == TDCALL_OPERAND_BUSY)
		return -EBUSY;

	return -EIO;
}
EXPORT_SYMBOL_GPL(tdx_mcall_tdreport);

static void tdx_get_info(void)
{
	struct tdx_module_output out;
	u64 ret;

	/*
	 * TDINFO TDX Module call is used to get the TD
	 * execution environment information like GPA
	 * width, number of available vcpus, debug mode
	 * information, etc. More details about the ABI
	 * can be found in TDX Guest-Host-Communication
	 * Interface (GHCI), sec 2.4.2 TDCALL [TDG.VP.INFO].
	 */
	ret = __trace_tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out);

	/*
	 * Non zero return means buggy TDX module (which is
	 * fatal). So raise a BUG().
	 */
	BUG_ON(ret);

	td_info.gpa_width = out.rcx & GENMASK(5, 0);
	td_info.attributes = out.rdx;

	/* Exclude Shared bit from the __PHYSICAL_MASK */
	physical_mask &= ~tdx_shared_mask();
}

static void tdx_accept_page(phys_addr_t gpa)
{
	u64 ret;

	/*
	 * Pass the page physical address and size (0-4KB) to the
	 * TDX module to accept the pending, private page. More info
	 * about ABI can be found in TDX Guest-Host-Communication
	 * Interface (GHCI), sec 2.4.7.
	 */
	ret = __trace_tdx_module_call(TDX_ACCEPT_PAGE, gpa, 0, 0, 0, NULL);

	/*
	 * Non zero return value means buggy TDX module (which is
	 * fatal for TDX guest). So panic here.
	 */
	BUG_ON(ret && TDCALL_RETURN_CODE(ret) != TDX_PAGE_ALREADY_ACCEPTED);
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
		gpa |= tdx_shared_mask();

	/*
	 * Notify VMM about page mapping conversion. More info
	 * about ABI can be found in TDX Guest-Host-Communication
	 * Interface (GHCI), sec 3.2.
	 */
	ret = _tdx_hypercall(TDVMCALL_MAP_GPA, gpa, PAGE_SIZE * numpages, 0, 0,
			     NULL);
	if (ret)
		ret = -EIO;

	if (ret || map_type == TDX_MAP_SHARED)
		return ret;

	/*
	 * For shared->private conversion, accept the page using
	 * TDX_ACCEPT_PAGE TDX module call.
	 */
	for (i = 0; i < numpages; i++)
		tdx_accept_page(gpa + i * PAGE_SIZE);

	return 0;
}

static __cpuidle void _tdx_halt(const bool irq_disabled, const bool do_sti)
{
	u64 ret;

	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec 3.8 TDG.VP.VMCALL<Instruction.HLT>.
	 *
	 * The VMM uses the "IRQ disabled" param to understand IRQ
	 * enabled status (RFLAGS.IF) of TD guest and determine
	 * whether or not it should schedule the halted vCPU if an
	 * IRQ becomes pending. E.g. if IRQs are disabled the VMM
	 * can keep the vCPU in virtual HLT, even if an IRQ is
	 * pending, without hanging/breaking the guest.
	 *
	 * do_sti parameter is used by __tdx_hypercall() to decide
	 * whether to call STI instruction before executing TDCALL
	 * instruction.
	 */
	ret = _trace_tdx_hypercall(EXIT_REASON_HLT, irq_disabled, 0, 0,
				   do_sti, NULL);

	/*
	 * Use WARN_ONCE() to report the failure. Since tdx_*halt() calls
	 * are also used in pv_ops, #VE error handler cannot be used to
	 * report the failure.
	 */
	WARN_ONCE(ret, "HLT instruction emulation failed\n");
}

static __cpuidle void tdx_halt(void)
{
	/*
	 * Non safe halt is mainly used in CPU offlining and
	 * the guest will stay in halt state. So, STI
	 * instruction call is not required (set do_sti as
	 * false).
	 */
	const bool irq_disabled = irqs_disabled();
	const bool do_sti = false;

	_tdx_halt(irq_disabled, do_sti);
}

static __cpuidle void tdx_safe_halt(void)
{
	 /*
	  * Since STI instruction will be called in __tdx_hypercall()
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
	if (_trace_tdx_hypercall(EXIT_REASON_MSR_READ, msr, 0, 0, 0, &out))
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
	ret = _trace_tdx_hypercall(EXIT_REASON_MSR_WRITE, msr,
				   (u64)high << 32 | low, 0, 0, NULL);

	return ret ? false : true;
}

static bool tdx_handle_cpuid(struct pt_regs *regs)
{
	struct tdx_hypercall_output out;

	/*
	 * Emulate CPUID instruction via hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	if (_trace_tdx_hypercall(EXIT_REASON_CPUID, regs->ax, regs->cx,
				 0, 0, &out))
		return false;

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contains contents of
	 * EAX, EBX, ECX, EDX registers after CPUID instruction execution.
	 * So copy the register contents back to pt_regs.
	 */
	regs->ax = out.r12;
	regs->bx = out.r13;
	regs->cx = out.r14;
	regs->dx = out.r15;

	return true;
}

/*
 * tdx_handle_early_io() cannot be re-used in #VE handler for handling
 * I/O because the way of handling string I/O is different between
 * normal and early I/O case. Also, once trace support is enabled,
 * tdx_handle_io() will be extended to use trace calls which is also
 * not valid for early I/O cases.
 */
static bool tdx_handle_io(struct pt_regs *regs, u32 exit_qual)
{
	struct tdx_hypercall_output outh;
	int out, size, port, ret;
	bool string;
	u64 mask;

	string = VE_IS_IO_STRING(exit_qual);

	/* I/O strings ops are unrolled at build time. */
	BUG_ON(string);

	out = VE_IS_IO_OUT(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);
	mask = GENMASK(8 * size, 0);

	if (!out) {
		ret = _trace_tdx_hypercall(EXIT_REASON_IO_INSTRUCTION,
					   size, out, port, regs->ax,
					   &outh);
		regs->ax &= ~mask;
		regs->ax |= (ret ? UINT_MAX : outh.r11) & mask;
	} else {
		ret = _tdx_hypercall(EXIT_REASON_IO_INSTRUCTION,
				     size, out, port, regs->ax,
				     &outh);
	}

	return ret ? false : true;
}

static unsigned long tdx_mmio(int size, bool write, unsigned long addr,
			      unsigned long *val)
{
	struct tdx_hypercall_output out;
	u64 err;

	err = _trace_tdx_hypercall(EXIT_REASON_EPT_VIOLATION, size, write,
				   addr, *val, &out);
	*val = out.r11;

	return err;
}

static int tdx_handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	char buffer[MAX_INSN_SIZE];
	unsigned long *reg, val;
	struct insn insn = {};
	enum mmio_type mmio;
	int size, ret;
	u8 sign_byte;

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

static int tdx_cpu_offline_prepare(unsigned int cpu)
{
	/*
	 * Per Intel TDX Virtual Firmware Design Guide,
	 * sec 4.3.5 and sec 9.4, Hotplug is not supported
	 * in TDX platforms. So don't support CPU
	 * offline feature once it is turned on.
	 */
	return -EOPNOTSUPP;
}

bool tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_output out;
	u64 ret;

	if (!ve)
		return false;

	/*
	 * NMIs and machine checks are suppressed. Before this point any
	 * #VE is fatal. After this point (TDGETVEINFO call), NMIs and
	 * additional #VEs are permitted (but it is expected not to
	 * happen unless kernel panics).
	 */
	ret = __trace_tdx_module_call(TDX_GET_VEINFO, 0, 0, 0, 0, &out);
	if (ret)
		return false;

	ve->exit_reason = out.rcx;
	ve->exit_qual   = out.rdx;
	ve->gla         = out.r8;
	ve->gpa         = out.r9;
	ve->instr_len   = out.r10 & UINT_MAX;
	ve->instr_info  = out.r10 >> 32;

	return true;
}

bool tdx_handle_virtualization_exception(struct pt_regs *regs,
					 struct ve_info *ve)
{
	bool ret = true;
	u64 val;

	trace_tdx_virtualization_exception_rcuidle(regs->ip, ve->exit_reason,
						   ve->exit_qual, ve->gpa,
						   ve->instr_len,
						   ve->instr_info, regs->cx,
						   regs->ax, regs->dx);
	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		tdx_halt();
		break;
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
	case EXIT_REASON_IO_INSTRUCTION:
		ret = tdx_handle_io(regs, ve->exit_qual);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		/* Currently only MMIO triggers EPT violation */
		ve->instr_len = tdx_handle_mmio(regs, ve);
		if (ve->instr_len < 0) {
			pr_warn_once("MMIO failed\n");
			ret = false;
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
		return false;
	}

	/* After successful #VE handling, move the IP */
	if (ret)
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
static __init bool tdx_early_io(struct pt_regs *regs, u32 exit_qual)
{
	struct tdx_hypercall_output outh;
	int out, size, port, ret;
	bool string;
	u64 mask;

	string = VE_IS_IO_STRING(exit_qual);

	/* I/O strings ops are unrolled at build time. */
	if (string)
		return 0;

	out = VE_IS_IO_OUT(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);
	mask = GENMASK(8 * size, 0);

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
__init bool tdx_early_handle_ve(struct pt_regs *regs)
{
	struct ve_info ve;

	if (tdx_get_ve_info(&ve))
		return false;

	if (ve.exit_reason == EXIT_REASON_IO_INSTRUCTION)
		return tdx_early_io(regs, ve.exit_qual);

	return false;
}

void __init tdx_early_init(void)
{
	if (!is_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	tdx_get_info();

	pv_ops.irq.safe_halt = tdx_safe_halt;
	pv_ops.irq.halt = tdx_halt;

	legacy_pic = &null_legacy_pic;
	swiotlb_force = SWIOTLB_FORCE;

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "tdx:cpu_hotplug",
			  NULL, tdx_cpu_offline_prepare);

	pr_info("Guest initialized\n");
}
