/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

#include <linux/types.h>
#include <linux/compiler.h>

/*
 * TDX architectural data structures
 */

#define P_SEAMLDR_INFO_ALIGNMENT	256

struct p_seamldr_info {
	u32	version;
	u32	attributes;
	u32	vendor_id;
	u32	build_date;
	u16	build_num;
	u16	minor;
	u16	major;
	u8	reserved0[2];
	u32	acm_x2apicid;
	u8	reserved1[4];
	u8	seaminfo[128];
	u8	seam_ready;
	u8	seam_debug;
	u8	p_seamldr_ready;
	u8	reserved2[88];
} __packed __aligned(P_SEAMLDR_INFO_ALIGNMENT);

struct cmr_info {
	u64	base;
	u64	size;
} __packed;

#define MAX_CMRS			32
#define CMR_INFO_ARRAY_ALIGNMENT	512

struct cpuid_config {
	u32	leaf;
	u32	sub_leaf;
	u32	eax;
	u32	ebx;
	u32	ecx;
	u32	edx;
} __packed;

#define TDSYSINFO_STRUCT_SIZE		1024
#define TDSYSINFO_STRUCT_ALIGNMENT	1024

struct tdsysinfo_struct {
	/* TDX-SEAM Module Info */
	u32	attributes;
	u32	vendor_id;
	u32	build_date;
	u16	build_num;
	u16	minor_version;
	u16	major_version;
	u8	reserved0[14];
	/* Memory Info */
	u16	max_tdmrs;
	u16	max_reserved_per_tdmr;
	u16	pamt_entry_size;
	u8	reserved1[10];
	/* Control Struct Info */
	u16	tdcs_base_size;
	u8	reserved2[2];
	u16	tdvps_base_size;
	u8	tdvps_xfam_dependent_size;
	u8	reserved3[9];
	/* TD Capabilities */
	u64	attributes_fixed0;
	u64	attributes_fixed1;
	u64	xfam_fixed0;
	u64	xfam_fixed1;
	u8	reserved4[32];
	u32	num_cpuid_config;
	/*
	 * The actual number of CPUID_CONFIG depends on above
	 * 'num_cpuid_config'.  The size of 'struct tdsysinfo_struct'
	 * is 1024B defined by TDX architecture.  Use a union with
	 * specific padding to make 'sizeof(struct tdsysinfo_struct)'
	 * equal to 1024.
	 */
	union {
		struct cpuid_config	cpuid_configs[0];
		u8			reserved5[892];
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
	/*
	 * Actual number of reserved areas depends on
	 * 'struct tdsysinfo_struct'::max_reserved_per_tdmr.
	 */
	struct tdmr_reserved_area reserved_areas[0];
} __packed __aligned(TDMR_INFO_ALIGNMENT);

/*
 * P-SEAMLDR SEAMCALL leaf function
 */
#define P_SEAMLDR_SEAMCALL_BASE		BIT_ULL(63)
#define P_SEAMCALL_SEAMLDR_INFO		(P_SEAMLDR_SEAMCALL_BASE | 0x0)

/*
 * TDX module SEAMCALL leaf functions
 */
#define TDH_SYS_INFO		32
#define TDH_SYS_INIT		33
#define TDH_SYS_LP_INIT		35
#define TDH_SYS_LP_SHUTDOWN	44
#define TDH_SYS_CONFIG		45

struct tdx_module_output;
u64 __seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
	       struct tdx_module_output *out);

#endif
