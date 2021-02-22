// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2020 Intel Corporation */

#include <asm/tdx.h>

/*
 * Wrapper for the common case with standard output value (R10).
 */
static inline u64 tdvmcall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	u64 err;

	err = __tdvmcall(fn, r12, r13, r14, r15, NULL);

	WARN_ON(err);

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

	WARN_ON(err);

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

void __init tdx_early_init(void)
{
	if (!cpuid_has_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	pr_info("TDX guest is initialized\n");
}
