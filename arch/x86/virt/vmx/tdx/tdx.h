/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/compiler_attributes.h>

/*
 * This file contains both macros and data structures defined by the TDX
 * architecture and Linux defined software data structures and functions.
 * The two should not be mixed together for better readability.  The
 * architectural definitions come first.
 */

/*
 * TDX SEAMCALL error codes
 */
#define TDX_RND_NO_ENTROPY	0x8000020300000000ULL

/*
 * TDX module SEAMCALL leaf functions
 */
#define TDH_SYS_INFO		32
#define TDH_SYS_INIT		33
#define TDH_SYS_LP_INIT		35

struct cmr_info {
	u64	base;
	u64	size;
} __packed;

#define MAX_CMRS	32

struct cpuid_config {
	u32	leaf;
	u32	sub_leaf;
	u32	eax;
	u32	ebx;
	u32	ecx;
	u32	edx;
} __packed;

#define TDSYSINFO_STRUCT_SIZE		1024

/*
 * The size of this structure itself is flexible.  The actual structure
 * passed to TDH.SYS.INFO must be padded to 1024 bytes and be 1204-bytes
 * aligned.
 */
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
	 * 'num_cpuid_config'.
	 */
	DECLARE_FLEX_ARRAY(struct cpuid_config, cpuid_configs);
} __packed;

struct tdmr_reserved_area {
	u64 offset;
	u64 size;
} __packed;

#define TDMR_INFO_ALIGNMENT	512

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
	DECLARE_FLEX_ARRAY(struct tdmr_reserved_area, reserved_areas);
} __packed __aligned(TDMR_INFO_ALIGNMENT);

/*
 * Do not put any hardware-defined TDX structure representations below
 * this comment!
 */

/* Kernel defined TDX module status during module initialization. */
enum tdx_module_status_t {
	TDX_MODULE_UNKNOWN,
	TDX_MODULE_INITIALIZED,
	TDX_MODULE_ERROR
};

struct tdx_memblock {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
};

/* Warn if kernel has less than TDMR_NR_WARN TDMRs after allocation */
#define TDMR_NR_WARN 4

struct tdmr_info_list {
	void *tdmrs;	/* Flexible array to hold 'tdmr_info's */
	int nr_consumed_tdmrs;	/* How many 'tdmr_info's are in use */

	/* Metadata for finding target 'tdmr_info' and freeing @tdmrs */
	int tdmr_sz;	/* Size of one 'tdmr_info' */
	int max_tdmrs;	/* How many 'tdmr_info's are allocated */
};

struct tdx_module_output;
u64 __seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
	       struct tdx_module_output *out);
#endif
