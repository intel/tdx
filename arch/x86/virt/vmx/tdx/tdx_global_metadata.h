/* SPDX-License-Identifier: GPL-2.0 */
/* Automatically generated TDX global metadata structures. */
#ifndef _X86_VIRT_TDX_AUTO_GENERATED_TDX_GLOBAL_METADATA_H
#define _X86_VIRT_TDX_AUTO_GENERATED_TDX_GLOBAL_METADATA_H

#include <linux/types.h>

struct tdx_sys_info_version {
	u32 build_date;
	u16 build_num;
	u16 minor_version;
	u16 major_version;
	u16 update_version;
	u16 internal_version;
};

struct tdx_sys_info_features {
	u64 tdx_features0;
};

struct tdx_sys_info_tdmr {
	u16 max_tdmrs;
	u16 max_reserved_per_tdmr;
	u16 pamt_4k_entry_size;
	u16 pamt_2m_entry_size;
	u16 pamt_1g_entry_size;
};

struct tdx_sys_info_cmr {
	u16 num_cmrs;
	u64 cmr_base[32];
	u64 cmr_size[32];
};

struct tdx_sys_info {
	struct tdx_sys_info_version version;
	struct tdx_sys_info_features features;
	struct tdx_sys_info_tdmr tdmr;
	struct tdx_sys_info_cmr cmr;
};

#endif
