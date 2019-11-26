/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#define TDX_CPUID_LEAF_ID	0x21

#ifdef CONFIG_INTEL_TDX_GUEST

/*
 * TDCALL instruction is newly added in TDX architecture,
 * used by TD for requesting the host VMM to provide
 * (untrusted) services. Supported in Binutils >= 2.36
 */
#define TDCALL	".byte 0x66,0x0f,0x01,0xcc"

#define TDINFO		1

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
