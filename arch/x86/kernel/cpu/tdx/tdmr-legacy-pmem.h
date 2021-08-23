/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_TDMR_LEGACY_PMEM_H
#define _X86_TDMR_LEGACY_PMEM_H

#include "tdmr-common.h"

extern struct tdx_memory tmem_legacy_pmem __initdata;

#ifdef CONFIG_ENABLE_TDX_FOR_X86_PMEM_LEGACY
int __init tdx_legacy_pmem_build(void);
void __init tdx_legacy_pmem_cleanup(void);
#else
static inline int tdx_legacy_pmem_build(void) { return -EFAULT; }
static inline void tdx_legacy_pmem_cleanup(void) { }
#endif

#endif
