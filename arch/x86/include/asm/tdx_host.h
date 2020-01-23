/* SPDX-License-Identifier: GPL-2.0 */
/* constants/data definitions for TDX host */

#ifndef __ASM_X86_TDX_HOST_H
#define __ASM_X86_TDX_HOST_H

#ifdef CONFIG_INTEL_TDX_HOST

#include <linux/cache.h>

void tdx_early_init(void);

struct tdsysinfo_struct;
const struct tdsysinfo_struct *tdx_get_sysinfo(void);

bool range_is_tdx_memory(phys_addr_t start, phys_addr_t end);

#else
static inline void tdx_early_init(void)
{
}

struct tdsysinfo_struct;
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	return NULL;
}

static inline bool range_is_tdx_memory(phys_addr_t start, phys_addr_t end)
{
	return false;
}
#endif

#endif /* __ASM_X86_TDX_HOST_H */
