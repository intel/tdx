/* SPDX-License-Identifier: GPL-2.0 */
/* architectural constants/data definitions for TDX SEAMCALLs */

#ifndef __ASM_X86_TDX_ARCH_H
#define __ASM_X86_TDX_ARCH_H

#include <linux/types.h>

/*
 * TDX SEAMCALL API function leaves
 */
#define SEAMCALL_TDH_SYS_KEY_CONFIG		31
#define SEAMCALL_TDH_SYS_INFO			32
#define SEAMCALL_TDH_SYS_INIT			33
#define SEAMCALL_TDH_SYS_LP_INIT		35
#define SEAMCALL_TDH_SYS_TDMR_INIT		36
#define SEAMCALL_TDH_SYS_LP_SHUTDOWN		44
#define SEAMCALL_TDH_SYS_CONFIG			45

#define TDX_SEAMCALL(name)	{ SEAMCALL_##name, #name }

#define TDX_SEAMCALLS				\
	TDX_SEAMCALL(TDH_SYS_KEY_CONFIG),	\
	TDX_SEAMCALL(TDH_SYS_INFO),		\
	TDX_SEAMCALL(TDH_SYS_INIT),		\
	TDX_SEAMCALL(TDH_SYS_LP_INIT),		\
	TDX_SEAMCALL(TDH_SYS_TDMR_INIT),	\
	TDX_SEAMCALL(TDH_SYS_LP_SHUTDOWN),	\
	TDX_SEAMCALL(TDH_SYS_CONFIG)

#define TDX_MAX_NR_CMRS			32
#define TDX_MAX_NR_TDMRS		64
#define TDX_MAX_NR_RSVD_AREAS		16
#define TDX_PAMT_ENTRY_SIZE		16
#define TDX_EXTENDMR_CHUNKSIZE		256

struct tdx_cpuid_config {
	u32 leaf;
	u32 sub_leaf;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
} __packed;

struct tdmr_reserved_area {
	u64 offset;
	u64 size;
} __packed;

#define TDX_TDMR_ADDR_ALIGNMENT	512
#define TDX_TDMR_INFO_ALIGNMENT	512
struct tdmr_info {
	u64 base;
	u64 size;
	u64 pamt_1g_base;
	u64 pamt_1g_size;
	u64 pamt_2m_base;
	u64 pamt_2m_size;
	u64 pamt_4k_base;
	u64 pamt_4k_size;
	struct tdmr_reserved_area reserved_areas[TDX_MAX_NR_RSVD_AREAS];
} __packed __aligned(TDX_TDMR_INFO_ALIGNMENT);

#define TDX_CMR_INFO_ARRAY_ALIGNMENT	512
struct cmr_info {
	u64 base;
	u64 size;
} __packed;

#define TDX_TDSYSINFO_STRUCT_ALIGNEMNT	1024
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
		struct tdx_cpuid_config cpuid_configs[0];
		u8 reserved5[892];
	};
} __packed __aligned(TDX_TDSYSINFO_STRUCT_ALIGNEMNT);

struct tdx_ex_ret {
	union {
		/* Used to retrieve values from hardware. */
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
			u64 r11;
		};
		/*
		 * TDH_SYS_INFO returns the buffer address and its size, and the
		 * CMR_INFO address and its number of entries.
		 */
		struct {
			u64 buffer;
			u64 nr_bytes;
			u64 cmr_info;
			u64 nr_cmr_entries;
		};
		/* TDH_SYS_TDMR_INIT returns the input PA and next PA. */
		struct {
			u64 prev;
			u64 next;
		};
	};
};

#endif /* __ASM_X86_TDX_ARCH_H */
