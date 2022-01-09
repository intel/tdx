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

struct cpuid_config {
	u32 leaf;
	u32 sub_leaf;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
} __packed;

#define TDSYSINFO_STRUCT_ALIGNMENT	1024
struct tdsysinfo_struct {
	/* TDX-SEAM Module Info */
	u32 attributes;
	u32 vendor_id;
	u32 build_date;
	u16 build_num;
	u16 minor_version;
	u16 major_version;
	u8 reserved0[14];
	/* Memory Info */
	u16 max_tdmrs;
	u16 max_reserved_per_tdmr;
	u16 pamt_entry_size;
	u8 reserved1[10];
	/* Control Struct Info */
	u16 tdcs_base_size;
	u8 reserved2[2];
	u16 tdvps_base_size;
	u8 tdvps_xfam_dependent_size;
	u8 reserved3[9];
	/* TD Capabilities */
	u64 attributes_fixed0;
	u64 attributes_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;
	u8 reserved4[32];
	u32 num_cpuid_config;
	union {
		struct cpuid_config cpuid_configs[0];
		u8 reserved5[892];
	};
} __packed __aligned(TDSYSINFO_STRUCT_ALIGNMENT);

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
	struct tdmr_reserved_area reserved_areas[0];
} __packed __aligned(TDMR_INFO_ALIGNMENT);

#endif	/* _X86_TDX_ARCH_H */
