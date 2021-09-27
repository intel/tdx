/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_TDX_TDMR_H
#define _X86_TDX_TDMR_H

/* Build TDX memory with all TDX capable memory blocks */
int __init build_tdx_memory(void);

/* Clean up TDX memory in case of any error before build_tdx_memory(). */
void __init cleanup_subtype_tdx_memory(void);

#endif
