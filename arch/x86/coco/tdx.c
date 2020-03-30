// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2022 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/cpufeature.h>
#include <asm/coco.h>
#include <asm/tdx.h>

/* TDX module Call Leaf IDs */
#define TDX_GET_INFO			1

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

/*
 * Wrapper for standard use of __tdx_hypercall with no output aside from
 * return code.
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

	return __tdx_hypercall(&args, 0);
}

static inline void tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
				   struct tdx_module_output *out)
{
	if (__tdx_module_call(fn, rcx, rdx, r8, r9, out))
		panic("TDCALL %lld failed (Buggy TDX module!)\n", fn);
}

static void get_info(void)
{
	struct tdx_module_output out;

	/*
	 * TDINFO TDX module call is used to get the TD execution environment
	 * information like GPA width, number of available vcpus, debug mode
	 * information, etc. More details about the ABI can be found in TDX
	 * Guest-Host-Communication Interface (GHCI), section 2.4.2 TDCALL
	 * [TDG.VP.INFO].
	 */
	tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out);

	td_info.gpa_width = out.rcx & GENMASK(5, 0);
	td_info.attributes = out.rdx;
}

void __init tdx_early_init(void)
{
	u32 eax, sig[3];
	u64 mask;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, 12))
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	get_info();

	/*
	 * All bits above GPA width are reserved and kernel treats shared bit
	 * as flag, not as part of physical address.
	 *
	 * Adjust physical mask to only cover valid GPA bits.
	 */
	physical_mask &= GENMASK_ULL(td_info.gpa_width - 2, 0);

	/*
	 * The highest bit of a guest physical address is the "sharing" bit.
	 * Set it for shared pages and clear it for private pages.
	 */
	mask = BIT_ULL(td_info.gpa_width - 1);

	cc_init(CC_VENDOR_INTEL, mask);

	pr_info("Guest detected\n");
}
