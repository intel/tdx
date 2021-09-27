/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_TDX_TDMR_H
#define _X86_TDX_TDMR_H

#include "tdmr-sysmem.h"
#include "tdmr-legacy-pmem.h"

extern struct tdx_memory tmem_all __initdata;

/* Build TDX memory with all TDX capable memory blocks */
int __init build_tdx_memory(void);

/* Clean up TDX memory in case of any error before build_tdx_memory(). */
void __init cleanup_subtype_tdx_memory(void);

/*
 * Construct final TDMRs based on CMR info and TDX module info, to cover
 * final TDX memory @tmem_all (built by build_tdx_memory()).
 */
int __init construct_tdx_tdmrs(struct cmr_info *cmr_array, int cmr_num,
		struct tdx_module_descriptor *desc,
		struct tdmr_info *tdmr_info_array, int *tdmr_num);

#endif
