/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) host kernel support
 */
#ifndef _ASM_X86_TDX_HOST_H
#define _ASM_X86_TDX_HOST_H

#ifdef CONFIG_INTEL_TDX_HOST
struct tdx_cpuid_config {
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

	/* CPUID */
	union {
		struct tdx_cpuid_config cpuid_configs[0];
		u8 reserved5[892];
	};
} __packed __aligned(TDSYSINFO_STRUCT_ALIGNMENT);

void detect_tdx_keyids(struct cpuinfo_x86 *c);
int detect_tdx(void);
int init_tdx(void);
const struct tdsysinfo_struct *tdx_get_sysinfo(void);
u32 tdx_get_global_keyid(void);
int tdx_keyid_alloc(void);
void tdx_keyid_free(int keyid);
#else
static inline void detect_tdx_keyids(struct cpuinfo_x86 *c) { }
static inline int detect_tdx(void) { return -ENODEV; }
static inline int init_tdx(void) { return -ENODEV; }
struct tdsysinfo_struct;
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void) { return NULL; }
static inline u32 tdx_get_global_keyid(void) { return 0; };
static inline int tdx_keyid_alloc(void) { return -EOPNOTSUPP; }
static inline void tdx_keyid_free(int keyid) { }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* _ASM_X86_TDX_HOST_H */
