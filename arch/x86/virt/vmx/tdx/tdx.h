/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_TDX_H
#define _X86_VIRT_TDX_H

#include <linux/bits.h>

/*
 * This file contains both macros and data structures defined by the TDX
 * architecture and Linux defined software data structures and functions.
 * The two should not be mixed together for better readability.  The
 * architectural definitions come first.
 */

/*
 * TDX module SEAMCALL leaf functions
 */
#define TDH_VP_ENTER			0
#define TDH_MNG_ADDCX			1
#define TDH_MEM_PAGE_ADD		2
#define TDH_MEM_SEPT_ADD		3
#define TDH_VP_ADDCX			4
#define TDH_MEM_PAGE_AUG		6
#define TDH_MEM_RANGE_BLOCK		7
#define TDH_MNG_KEY_CONFIG		8
#define TDH_MNG_CREATE			9
#define TDH_VP_CREATE			10
#define TDH_MNG_RD			11
#define TDH_MNG_WR			13
#define TDH_MR_EXTEND			16
#define TDH_MR_FINALIZE			17
#define TDH_VP_FLUSH			18
#define TDH_MNG_VPFLUSHDONE		19
#define TDH_MNG_KEY_FREEID		20
#define TDH_MNG_INIT			21
#define TDH_VP_INIT			22
#define TDH_VP_RD			26
#define TDH_PHYMEM_PAGE_RDMD		24
#define TDH_PHYMEM_PAGE_RECLAIM		28
#define TDH_MEM_PAGE_REMOVE		29
#define TDH_MEM_SEPT_REMOVE		30
#define TDH_SYS_KEY_CONFIG		31
#define TDH_SYS_INIT			33
#define TDH_SYS_RD			34
#define TDH_MEM_TRACK			38
#define TDH_MEM_RANGE_UNBLOCK		39
#define TDH_SYS_LP_INIT			35
#define TDH_SYS_TDMR_INIT		36
#define TDH_PHYMEM_CACHE_WB		40
#define TDH_VP_WR			43
#define TDH_PHYMEM_PAGE_WBINVD		41
#define TDH_SYS_CONFIG			45

/*
 * SEAMCALL leaf:
 *
 * Bit 15:0	Leaf number
 * Bit 23:16	Version number
 */
#define TDX_VERSION_SHIFT		16

/* TDX page types */
#define	PT_NDA		0x0
#define	PT_RSVD		0x1

/*
 * Global scope metadata field ID.
 *
 * See the "global_metadata.json" in the "TDX 1.5 ABI definitions".
 */
#define MD_FIELD_ID_SYS_ATTRIBUTES		0x0A00000200000000ULL
#define MD_FIELD_ID_TDX_FEATURES0		0x0A00000300000008ULL
#define MD_FIELD_ID_BUILD_DATE			0x8800000200000001ULL
#define MD_FIELD_ID_BUILD_NUM			0x8800000100000002ULL
#define MD_FIELD_ID_MINOR_VERSION		0x0800000100000003ULL
#define MD_FIELD_ID_MAJOR_VERSION		0x0800000100000004ULL
#define MD_FIELD_ID_UPDATE_VERSION		0x0800000100000005ULL
#define MD_FIELD_ID_INTERNAL_VERSION		0x0800000100000006ULL

#define MD_FIELD_ID_NUM_CMRS			0x9000000100000000ULL
#define MD_FIELD_ID_CMR_BASE(_i)		(0x9000000300000080ULL + (u16)_i)
#define MD_FIELD_ID_CMR_SIZE(_i)		(0x9000000300000100ULL + (u16)_i)

#define MD_FIELD_ID_MAX_TDMRS			0x9100000100000008ULL
#define MD_FIELD_ID_MAX_RESERVED_PER_TDMR	0x9100000100000009ULL
#define MD_FIELD_ID_PAMT_4K_ENTRY_SIZE		0x9100000100000010ULL
#define MD_FIELD_ID_PAMT_2M_ENTRY_SIZE		0x9100000100000011ULL
#define MD_FIELD_ID_PAMT_1G_ENTRY_SIZE		0x9100000100000012ULL

#define MD_FIELD_ID_TDR_BASE_SIZE		0x9800000100000000ULL
#define MD_FIELD_ID_TDCS_BASE_SIZE		0x9800000100000100ULL
#define MD_FIELD_ID_TDVPS_BASE_SIZE		0x9800000100000200ULL

#define MD_FIELD_ID_ATTRIBUTES_FIXED0		0x1900000300000000ULL
#define MD_FIELD_ID_ATTRIBUTES_FIXED1		0x1900000300000001ULL
#define MD_FIELD_ID_XFAM_FIXED0			0x1900000300000002ULL
#define MD_FIELD_ID_XFAM_FIXED1			0x1900000300000003ULL
#define MD_FIELD_ID_NUM_CPUID_CONFIG		0x9900000100000004ULL
#define MD_FIELD_ID_MAX_VCPUS_PER_TD		0x9900000100000008ULL
#define MD_FIELD_ID_CPUID_CONFIG_LEAVES		0x9900000300000400ULL
#define MD_FIELD_ID_CPUID_CONFIG_VALUES		0x9900000300000500ULL

/*
 * Sub-field definition of metadata field ID.
 *
 * See Table "MD_FIELD_ID (Metadata Field Identifier / Sequence Header)
 * Definition", TDX module 1.5 ABI spec.
 *
 *  - Bit 33:32: ELEMENT_SIZE_CODE -- size of a single element of metadata
 *
 *	0: 8 bits
 *	1: 16 bits
 *	2: 32 bits
 *	3: 64 bits
 */
#define MD_FIELD_ID_ELE_SIZE_CODE(_field_id)	\
		(((_field_id) & GENMASK_ULL(33, 32)) >> 32)

#define MD_FIELD_ELE_SIZE(_field_id)	\
	(1 << MD_FIELD_ID_ELE_SIZE_CODE(_field_id))

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
	 * The actual number of reserved areas depends on the value of
	 * field MD_FIELD_ID_MAX_RESERVED_PER_TDMR in the TDX module
	 * global metadata.
	 */
	DECLARE_FLEX_ARRAY(struct tdmr_reserved_area, reserved_areas);
} __packed __aligned(TDMR_INFO_ALIGNMENT);

/*
 * Do not put any hardware-defined TDX structure representations below
 * this comment!
 */

/* Kernel defined TDX module status during module initialization. */
enum tdx_module_status_t {
	TDX_MODULE_UNINITIALIZED,
	TDX_MODULE_INITIALIZED,
	TDX_MODULE_ERROR
};

struct tdx_memblock {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
	int nid;
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

#endif
