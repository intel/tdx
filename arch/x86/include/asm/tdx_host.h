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
int detect_tdx(void);
int init_tdx(void);
#else
static inline void detect_tdx_keyids(struct cpuinfo_x86 *c) { }
static inline int detect_tdx(void) { return -ENODEV; }
static inline int init_tdx(void) { return -ENODEV; }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* _ASM_X86_TDX_HOST_H */
