/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/cpufeature.h>

#define TDX_CPUID_LEAF_ID	0x21

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);

#else

static inline void tdx_early_init(void) { };

#endif /* CONFIG_INTEL_TDX_GUEST */

#endif /* _ASM_X86_TDX_H */
