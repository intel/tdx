/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_TDMR_SYSMEM_H
#define _X86_TDMR_SYSMEM_H

#include "tdmr-common.h"

extern struct tdx_memory tmem_sysmem __initdata;

int __init tdx_sysmem_build(void);
void __init tdx_sysmem_cleanup(void);

unsigned long __init sysmem_pamt_alloc(struct tdx_memblock *tmb,
				unsigned long nr_pages);
void __init sysmem_pamt_free(struct tdx_memblock *tmb,
			unsigned long pamt_pfn, unsigned long nr_pages);

#endif
