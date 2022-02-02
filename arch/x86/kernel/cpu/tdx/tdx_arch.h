/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) architectural data structures
 */

#ifndef _X86_TDX_ARCH_H
#define _X86_TDX_ARCH_H

#include <linux/types.h>
#include <linux/compiler.h>

struct cmr_info {
	u64 base;
	u64 size;
} __packed;

#define MAX_CMRS			32
#define CMR_INFO_ARRAY_ALIGNMENT	512

struct tdmr_reserved_area {
	u64 offset;
	u64 size;
} __packed;

#define TDMR_INFO_ALIGNMENT	512
#define TDMR_INFO_PA_ARRAY_ALIGNMENT	512
struct tdmr_info {
	u64 base;
	u64 size;
	u64 pamt_1g_base;
	u64 pamt_1g_size;
	u64 pamt_2m_base;
	u64 pamt_2m_size;
	u64 pamt_4k_base;
	u64 pamt_4k_size;
	/*
	 * Actual number of reserved areas depends on
	 * 'struct tdsysinfo_struct'::max_reserved_per_tdmr.
	 */
	struct tdmr_reserved_area reserved_areas[0];
} __packed __aligned(TDMR_INFO_ALIGNMENT);

#endif	/* _X86_TDX_ARCH_H */
