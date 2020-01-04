/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <asm/cpufeature.h>

#ifdef CONFIG_INTEL_TDX_GUEST

/* TDX support often needs to be queried before CPU caps is populated. */
static inline bool __is_tdx_guest(void)
{
	return cpuid_edx(1) & (1 << (X86_FEATURE_TDX_GUEST & 31));
}

static inline bool is_tdx_guest(void)
{
	return static_cpu_has(X86_FEATURE_TDX_GUEST);
}

#else // !CONFIG_INTEL_TDX_GUEST
static inline bool __is_tdx_guest(void)
{
	return false;
}

static inline bool is_tdx_guest(void)
{
	return false;
}
#endif /* CONFIG_INTEL_TDX_GUEST */

#endif /* _ASM_X86_TDX_H */
