/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_TDX_TDMR_H
#define _X86_TDX_TDMR_H

#include "tdmr-sysmem.h"
#include "tdmr-legacy-pmem.h"

extern struct tdx_memory tmem_all __initdata;

/* Build final TDX memory with all TDX capable memory blocks */
int __init build_final_tdx_memory(void);

/* Clean up TDX memory in case of any error before build_final_tdx_memory(). */
void __init cleanup_subtype_tdx_memory(void);

#endif
