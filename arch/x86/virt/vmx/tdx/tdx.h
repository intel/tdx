/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

#include <linux/types.h>
#include <linux/bits.h>

/*
 * This file contains both macros and data structures defined by the TDX
 * architecture and Linux defined software data structures and functions.
 * The two should not be mixed together for better readability.  The
 * architectural definitions come first.
 */

/*
 * Intel Trusted Domain CPU Architecture Extension spec:
 *
 * IA32_MTRRCAP:
 *   Bit 15:	The support of SEAMRR
 *
 * IA32_SEAMRR_PHYS_MASK (core-scope):
 *   Bit 10:	Lock bit
 *   Bit 11:	Enable bit
 */
#define MTRR_CAP_SEAMRR			BIT_ULL(15)

#define MSR_IA32_SEAMRR_PHYS_MASK	0x00001401

#define SEAMRR_PHYS_MASK_ENABLED	BIT_ULL(11)
#define SEAMRR_PHYS_MASK_LOCKED		BIT_ULL(10)
#define SEAMRR_ENABLED_BITS	\
	(SEAMRR_PHYS_MASK_ENABLED | SEAMRR_PHYS_MASK_LOCKED)

/*
 * IA32_MKTME_KEYID_PARTIONING:
 *   Bit [31:0]:	Number of MKTME KeyIDs.
 *   Bit [63:32]:	Number of TDX private KeyIDs.
 *
 * MKTME KeyIDs start from KeyID 1. TDX private KeyIDs start
 * after the last MKTME KeyID.
 */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

#define TDX_KEYID_START(_keyid_part)	\
		((u32)(((_keyid_part) & 0xffffffffull) + 1))
#define TDX_KEYID_NUM(_keyid_part)	((u32)((_keyid_part) >> 32))


/*
 * TDX module SEAMCALL leaf functions
 */
#define TDH_SYS_INFO		32
#define TDH_SYS_INIT		33
#define TDH_SYS_LP_INIT		35
#define TDH_SYS_LP_SHUTDOWN	44
#define TDH_SYS_CONFIG		45

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
 * Do not put any hardware-defined TDX structure representations below this
 * comment!
 */

struct tdx_module_output;
u64 __seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
	       struct tdx_module_output *out);

#endif
