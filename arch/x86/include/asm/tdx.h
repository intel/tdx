/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#define TDX_CPUID_LEAF_ID	0x21

#include <asm/cpufeature.h>

#ifdef CONFIG_INTEL_TDX_GUEST

static inline bool cpuid_has_tdx_guest(void)
{
	uint32_t eax, signature[3];

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &signature[0],
			&signature[1], &signature[2]);

	if (memcmp("IntelTDX    ", signature, 12))
		return false;

	return true;
}

/* Common API to check TDX support in decompression and common kernel code. */
bool is_tdx_guest(void);

void __init tdx_early_init(void);

#else // !CONFIG_INTEL_TDX_GUEST

static inline bool is_tdx_guest(void)
{
	return false;
}

static inline void tdx_early_init(void) { };

#endif /* CONFIG_INTEL_TDX_GUEST */

#endif /* _ASM_X86_TDX_H */
