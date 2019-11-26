// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "x86/tdx: " fmt

#include <linux/protected_guest.h>

#include <asm/tdx.h>

/* TDX Module call Leaf IDs */
#define TDINFO				1

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

void __init tdx_early_init(void)
{
	if (!cpuid_has_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	tdg_get_info();

	pr_info("Guest initialized\n");
}
