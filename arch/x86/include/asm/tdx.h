/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/init.h>

#define TDX_CPUID_LEAF_ID	0x21
#define TDX_IDENT		"IntelTDX    "

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);
bool is_tdx_guest(void);

#else

static inline void tdx_early_init(void) { };
static inline bool is_tdx_guest(void) { return false; }

#endif /* CONFIG_INTEL_TDX_GUEST */

#endif /* _ASM_X86_TDX_H */
