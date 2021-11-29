/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) host kernel support
 */
#ifndef _ASM_X86_TDX_HOST_H
#define _ASM_X86_TDX_HOST_H

#ifdef CONFIG_INTEL_TDX_HOST
void detect_tdx_keyids(struct cpuinfo_x86 *c);
#else
static inline void detect_tdx_keyids(struct cpuinfo_x86 *c) { }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* _ASM_X86_TDX_HOST_H */
