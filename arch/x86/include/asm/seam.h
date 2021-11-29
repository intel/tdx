/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Secure Arbitration Mode (SEAM) support
 */
#ifndef _ASM_X86_SEAM_H
#define _ASM_X86_SEAM_H

#include <asm/processor.h>

#ifdef CONFIG_INTEL_TDX_HOST
void detect_seam(struct cpuinfo_x86 *c);
bool seamrr_enabled(void);
#else
static inline void detect_seam(struct cpuinfo_x86 *c) { }
static inline bool seamrr_enabled(void) { return false; }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* _ASM_X86_SEAM_H */
