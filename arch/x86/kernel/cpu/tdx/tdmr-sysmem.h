/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_TDMR_SYSMEM_H
#define _X86_TDMR_SYSMEM_H

#include "tdmr-common.h"

extern struct tdx_memory tmem_sysmem __initdata;

int __init tdx_sysmem_build(void);
void __init tdx_sysmem_cleanup(void);

#endif
