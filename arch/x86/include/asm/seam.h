/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Secure Arbitration Mode (SEAM) support
 */
#ifndef _ASM_X86_SEAM_H
#define _ASM_X86_SEAM_H

#ifdef CONFIG_INTEL_TDX_HOST

/*
 * SEAMCALL instruction is essentially a VMExit from VMX root to SEAM
 * VMX root, and it can fail with VMfailInvalid when P-SEAMLDR or the
 * TDX module is not loaded/enabled, or when SEAMCALLs are made into
 * P-SEAMLDR in parallel.  Use a special value which doesn't conflict
 * with any valid error code of SEAMCALLs to distinguish.
 */
#define VMFAILINVALID	(-1ULL)

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/bits.h>
#include <linux/bug.h>
#include <linux/spinlock.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>

void detect_seam(struct cpuinfo_x86 *c);
bool seamrr_enabled(void);

/*
 * All SEAMCALLs use %rax to indicate the leaf function number, with
 * bit 63 indicating whether the call is for P-SEAMLDR or the TDX
 * module.  The completion status is also returned in %rax.
 *
 * Additional GPRs may be further used as input/output for specific
 * leaf functions.  Introduce two structures (seamcall_regs_in and
 * seamcall_regs_out) to encapsulate all possible GPRs for the common
 * SEAMCALL wrapper.
 *
 * The only exception not covered here is TDENTER leaf function, which
 * takes all GPRs and XMM0-XMM15 as both input/output. The caller of
 * TDENTER should implement its own logic directly instead of calling
 * the wrapper function defined in this file.
 */
struct seamcall_regs_in {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
};

struct seamcall_regs_out {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

/**
 * samcall - C function of SEAMCALL instruction.
 *
 * @op:	Leaf number for specific SEAMCALL
 * @in: Additional input operands (can be NULL).
 * @out: Additional output operands (can be NULL).
 *
 * This function must be called when SEAMRR is enabled and CPU is
 * already in VMX operation.  Otherwise #UD is generated.
 *
 * Return: -1 if SEAMCALL instruction failed with VMfailInvalid, or
 *	   the SEAMCALL completion status (0 or actual error code).
 */
asmlinkage u64 __seamcall(u64 op, struct seamcall_regs_in *in,
			  struct seamcall_regs_out *out);

/*
 * All error codes of both P-SEAMLDR and TDX module SEAMCALLs
 * have bit 63 set if SEAMCALL fails.
 */
#define SEAMCALL_LEAF_ERROR(_ret)	((_ret) & BIT_ULL(63))

/*
 * Wrapper of __seamcall() to convert SEAMCALL error code to kernel
 * error code.  Don't use this function directly, but always use
 * p_seamldr_seamcall() or tdx_seamcall() instead.
 */
static inline int seamcall(u64 op, struct seamcall_regs_in *in,
			   u64 *seamcall_ret,
			   struct seamcall_regs_out *out)
{
	u64 ret;

	if (!seamrr_enabled())
		return -ENODEV;

	/*
	 * SEAMCALL instruction requires CPU being already in VMX
	 * operation (VMXON has been done).  Sanity check whether
	 * VMX has been enabled in CR4 here.
	 *
	 * Note VMX being enabled in CR4 doesn't mean CPU is already
	 * in VMX operation, but unfortunately there's no way to do
	 * such check.  However in practice enabling VMX in CR4 and
	 * doing VMXON are done together (for now) so in practice it
	 * checks whether VMXON has been done.
	 */
	if (!(cr4_read_shadow() & X86_CR4_VMXE))
		return -EPERM;

	ret = __seamcall(op, in, out);

	/*
	 * Convert SEAMCALL error code to kernel error code:
	 *  - -ENODEV:	VMfailInvalid
	 *  - -EFAULT:	SEAMCALL failed
	 *  - 0:	SEAMCALL was successful
	 */
	if (ret == VMFAILINVALID)
		return -ENODEV;

	/*
	 * Save the completion status of the SEAMCALL if caller
	 * wants to use it.
	 */
	if (seamcall_ret)
		*seamcall_ret = ret;

	return SEAMCALL_LEAF_ERROR(ret) ? -EFAULT : 0;
}

/* All P-SEAMLDR SEAMCALLs have bit 63 set */
#define P_SEAMLDR_SEAMCALL_BASE		BIT_ULL(63)
extern spinlock_t p_seamldr_lock;

/**
 * p_seamldr_seamcall - C function of P-SEAMLDR SEAMCALL
 *
 * @op:	Leaf number for specific P-SEAMLDR SEAMCALL
 * @in: Additional input operands (can be NULL).
 * @seamcall_ret: Completion status of the SEAMCALL (can be NULL).
 * @out: Additional output operands (can be NULL).
 *
 * Return:
 *
 * * -EINVAL: Leaf is not a valid P-SEAMLDR SEAMCALL
 * * -EPERM: CPU is not in VMX operation
 * * -ENODEV: P-SEAMLDR is not loaded or is disabled
 * * -EFAULT: SEAMCALL failed
 * * 0: SEAMCALL was successful
 */
static inline int p_seamldr_seamcall(u64 op, struct seamcall_regs_in *in,
				     u64 *seamcall_ret,
				     struct seamcall_regs_out *out)
{
	int ret;

	if (WARN_ON_ONCE(op < P_SEAMLDR_SEAMCALL_BASE))
		return -EINVAL;

	/*
	 * SEAMCALL instruction also fails with VMfailInvalid if
	 * SEAMCALLs are made into P-SEAMLDR in parallel.  Use lock
	 * to avoid such case so that -ENODEV can be uniquely used
	 * to represent the case that P-SEAMLDR is not loaded.
	 */
	spin_lock(&p_seamldr_lock);
	ret = seamcall(op, in, seamcall_ret, out);
	spin_unlock(&p_seamldr_lock);

	return ret;
}

/**
 * tdx_seamcall - C function of TDX module SEAMCALL
 *
 * @op:	Leaf number for specific TDX SEAMCALL
 * @in: Additional input operands (can be NULL).
 * @out: Additional output operands (can be NULL).
 * @seamcall_ret: Completion status of the SEAMCALL (can be NULL).
 *
 * Return:
 *
 * * -EINVAL: Leaf is not a valid TDX module SEAMCALL
 * * -EPERM: CPU is not in VMX operation
 * * -ENODEV: TDX module is not loaded or is disabled.
 * * -EFAULT: SEAMCALL failed
 * * 0: SEAMCALL was successful
 */
static inline int tdx_seamcall(u64 op, struct seamcall_regs_in *in,
			       u64 *seamcall_ret,
			       struct seamcall_regs_out *out)
{
	if (WARN_ON_ONCE(op >= P_SEAMLDR_SEAMCALL_BASE))
		return -EINVAL;

	return seamcall(op, in, seamcall_ret, out);
}
#endif	/* !__ASSEMBLY__ */

#else

#include <asm/processor.h>

static inline void detect_seam(struct cpuinfo_x86 *c) { }
static inline bool seamrr_enabled(void) { return false; }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* _ASM_X86_SEAM_H */
