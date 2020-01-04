// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2020 Intel Corporation */

#include <asm/tdx.h>

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
