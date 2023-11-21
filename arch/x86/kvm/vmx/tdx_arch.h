/* SPDX-License-Identifier: GPL-2.0 */
/* architectural constants/data definitions for TDX SEAMCALLs */

#ifndef __KVM_X86_TDX_ARCH_H
#define __KVM_X86_TDX_ARCH_H

#include <linux/types.h>

/*
 * TDX SEAMCALL API function leaves
 */
#define TDH_VP_ENTER			0
#define TDH_MNG_ADDCX			1
#define TDH_MEM_PAGE_ADD		2
#define TDH_MEM_SEPT_ADD		3
#define TDH_VP_ADDCX			4
#define TDH_MEM_PAGE_RELOCATE		5
#define TDH_MEM_PAGE_AUG		6
#define TDH_MEM_RANGE_BLOCK		7
#define TDH_MNG_KEY_CONFIG		8
#define TDH_MNG_CREATE			9
#define TDH_VP_CREATE			10
#define TDH_MNG_RD			11
#define TDH_MR_EXTEND			16
#define TDH_MR_FINALIZE			17
#define TDH_VP_FLUSH			18
#define TDH_MNG_VPFLUSHDONE		19
#define TDH_MNG_KEY_FREEID		20
#define TDH_MNG_INIT			21
#define TDH_VP_INIT			22
#define TDH_MEM_SEPT_RD			25
#define TDH_VP_RD			26
#define TDH_MNG_KEY_RECLAIMID		27
#define TDH_PHYMEM_PAGE_RECLAIM		28
#define TDH_MEM_PAGE_REMOVE		29
#define TDH_MEM_SEPT_REMOVE		30
#define TDH_SYS_RD			34
#define TDH_MEM_TRACK			38
#define TDH_MEM_RANGE_UNBLOCK		39
#define TDH_PHYMEM_CACHE_WB		40
#define TDH_PHYMEM_PAGE_WBINVD		41
#define TDH_VP_WR			43
#define TDH_SYS_LP_SHUTDOWN		44

#define TD_EXIT_OTHER_SMI_IS_MSMI	BIT(1)

/* TDX control structure (TDR/TDCS/TDVPS) field access codes */
#define TDX_NON_ARCH			BIT_ULL(63)
#define TDX_CLASS_SHIFT			56
#define TDX_FIELD_MASK			GENMASK_ULL(31, 0)

#define __BUILD_TDX_FIELD(non_arch, class, field)	\
	(((non_arch) ? TDX_NON_ARCH : 0) |		\
	 ((u64)(class) << TDX_CLASS_SHIFT) |		\
	 ((u64)(field) & TDX_FIELD_MASK))

#define BUILD_TDX_FIELD(class, field)			\
	__BUILD_TDX_FIELD(false, (class), (field))

#define BUILD_TDX_FIELD_NON_ARCH(class, field)		\
	__BUILD_TDX_FIELD(true, (class), (field))


/* Class code for TD */
#define TD_CLASS_EXECUTION_CONTROLS	17ULL

/* Class code for TDVPS */
#define TDVPS_CLASS_VMCS		0ULL
#define TDVPS_CLASS_GUEST_GPR		16ULL
#define TDVPS_CLASS_OTHER_GUEST		17ULL
#define TDVPS_CLASS_MANAGEMENT		32ULL

enum tdx_tdcs_execution_control {
	TD_TDCS_EXEC_TSC_OFFSET = 10,
};

/* @field is any of enum tdx_tdcs_execution_control */
#define TDCS_EXEC(field)		BUILD_TDX_FIELD(TD_CLASS_EXECUTION_CONTROLS, (field))

/* @field is the VMCS field encoding */
#define TDVPS_VMCS(field)		BUILD_TDX_FIELD(TDVPS_CLASS_VMCS, (field))

enum tdx_vcpu_guest_other_state {
	TD_VCPU_STATE_DETAILS_NON_ARCH = 0x100,
};

union tdx_vcpu_state_details {
	struct {
		u64 vmxip	: 1;
		u64 reserved	: 63;
	};
	u64 full;
};

/* @field is any of enum tdx_guest_other_state */
#define TDVPS_STATE(field)		BUILD_TDX_FIELD(TDVPS_CLASS_OTHER_GUEST, (field))
#define TDVPS_STATE_NON_ARCH(field)	BUILD_TDX_FIELD_NON_ARCH(TDVPS_CLASS_OTHER_GUEST, (field))

/* Management class fields */
enum tdx_vcpu_guest_management {
	TD_VCPU_PEND_NMI = 11,
};

/* @field is any of enum tdx_vcpu_guest_management */
#define TDVPS_MANAGEMENT(field)		BUILD_TDX_FIELD(TDVPS_CLASS_MANAGEMENT, (field))

#define TDX_EXTENDMR_CHUNKSIZE		256

struct tdx_cpuid_value {
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
} __packed;

#define TDX_TD_ATTRIBUTE_DEBUG		BIT_ULL(0)
#define TDX_TD_ATTR_SEPT_VE_DISABLE	BIT_ULL(28)
#define TDX_TD_ATTRIBUTE_PKS		BIT_ULL(30)
#define TDX_TD_ATTRIBUTE_KL		BIT_ULL(31)
#define TDX_TD_ATTRIBUTE_PERFMON	BIT_ULL(63)

/*
 * TODO: Once XFEATURE_CET_{U, S} in arch/x86/include/asm/fpu/types.h is
 * defined, Replace these with define ones.
 */
#define TDX_TD_XFAM_CET	(BIT(11) | BIT(12))

/*
 * TD_PARAMS is provided as an input to TDH_MNG_INIT, the size of which is 1024B.
 */
#define TDX_MAX_VCPUS	(~(u16)0)

struct td_params {
	u64 attributes;
	u64 xfam;
	u16 max_vcpus;
	u8 reserved0[6];

	u64 eptp_controls;
	u64 exec_controls;
	u16 tsc_frequency;
	u8  reserved1[38];

	u64 mrconfigid[6];
	u64 mrowner[6];
	u64 mrownerconfig[6];
	u64 reserved2[4];

	union {
		DECLARE_FLEX_ARRAY(struct tdx_cpuid_value, cpuid_values);
		u8 reserved3[768];
	};
} __packed __aligned(1024);

/*
 * Guest uses MAX_PA for GPAW when set.
 * 0: GPA.SHARED bit is GPA[47]
 * 1: GPA.SHARED bit is GPA[51]
 */
#define TDX_EXEC_CONTROL_MAX_GPAW      BIT_ULL(0)

/*
 * TDH.VP.ENTER, TDG.VP.VMCALL preserves RBP
 * 0: RBP can be used for TDG.VP.VMCALL input. RBP is clobbered.
 * 1: RBP can't be used for TDG.VP.VMCALL input. RBP is preserved.
 */
#define TDX_CONTROL_FLAG_NO_RBP_MOD	BIT_ULL(2)


/*
 * TDX requires the frequency to be defined in units of 25MHz, which is the
 * frequency of the core crystal clock on TDX-capable platforms, i.e. the TDX
 * module can only program frequencies that are multiples of 25MHz.  The
 * frequency must be between 100mhz and 10ghz (inclusive).
 */
#define TDX_TSC_KHZ_TO_25MHZ(tsc_in_khz)	((tsc_in_khz) / (25 * 1000))
#define TDX_TSC_25MHZ_TO_KHZ(tsc_in_25mhz)	((tsc_in_25mhz) * (25 * 1000))
#define TDX_MIN_TSC_FREQUENCY_KHZ		(100 * 1000)
#define TDX_MAX_TSC_FREQUENCY_KHZ		(10 * 1000 * 1000)

union tdx_sept_entry {
	struct {
		u64 r		:  1;
		u64 w		:  1;
		u64 x		:  1;
		u64 mt		:  3;
		u64 ipat	:  1;
		u64 leaf	:  1;
		u64 a		:  1;
		u64 d		:  1;
		u64 xu		:  1;
		u64 ignored0	:  1;
		u64 pfn		: 40;
		u64 reserved	:  5;
		u64 vgp		:  1;
		u64 pwa		:  1;
		u64 ignored1	:  1;
		u64 sss		:  1;
		u64 spp		:  1;
		u64 ignored2	:  1;
		u64 sve		:  1;
	};
	u64 raw;
};

enum tdx_sept_entry_state {
	TDX_SEPT_FREE = 0,
	TDX_SEPT_BLOCKED = 1,
	TDX_SEPT_PENDING = 2,
	TDX_SEPT_PENDING_BLOCKED = 3,
	TDX_SEPT_PRESENT = 4,
};

union tdx_sept_level_state {
	struct {
		u64 level	:  3;
		u64 reserved0	:  5;
		u64 state	:  8;
		u64 reserved1	: 48;
	};
	u64 raw;
};

union tdx_ext_exit_qualification {
	struct {
		u64 type		:  4;
		u64 reserved0		: 28;
		u64 req_sept_level	:  3;
		u64 err_sept_level	:  3;
		u64 err_sept_state	:  8;
		u64 err_sept_is_leaf	:  1;
		u64 reserved1		: 17;
	};
	u64 full;
};

enum tdx_ext_exit_qualification_type {
	EXT_EXIT_QUAL_NONE = 0,
	EXT_EXIT_QUAL_ACCEPT = 1,
	NUM_EXT_EXIT_QUAL,
};

/*
 * Global scope metadata field ID.
 * See Table "Global Scope Metadata", TDX module 1.5 ABI spec.
 */
#define MD_FIELD_ID_SYS_ATTRIBUTES		0x0A00000200000000ULL
#define MD_FIELD_ID_FEATURES0			0x0A00000300000008ULL
#define MD_FIELD_ID_ATTRS_FIXED0		0x1900000300000000ULL
#define MD_FIELD_ID_ATTRS_FIXED1		0x1900000300000001ULL
#define MD_FIELD_ID_XFAM_FIXED0			0x1900000300000002ULL
#define MD_FIELD_ID_XFAM_FIXED1			0x1900000300000003ULL

#define MD_FIELD_ID_TDCS_BASE_SIZE		0x9800000100000100ULL
#define MD_FIELD_ID_TDVPS_BASE_SIZE		0x9800000100000200ULL

#define MD_FIELD_ID_NUM_CPUID_CONFIG		0x9900000100000004ULL
#define MD_FIELD_ID_CPUID_CONFIG_LEAVES		0x9900000300000400ULL
#define MD_FIELD_ID_CPUID_CONFIG_VALUES		0x9900000300000500ULL

#define MD_FIELD_ID_FEATURES0_NO_RBP_MOD	BIT_ULL(18)

#define TDX_MAX_NR_CPUID_CONFIGS       37

#define TDX_MD_ELEMENT_SIZE_8BITS      0
#define TDX_MD_ELEMENT_SIZE_16BITS     1
#define TDX_MD_ELEMENT_SIZE_32BITS     2
#define TDX_MD_ELEMENT_SIZE_64BITS     3

union tdx_md_field_id {
	struct {
		u64 field                       : 24;
		u64 reserved0                   : 8;
		u64 element_size_code           : 2;
		u64 last_element_in_field       : 4;
		u64 reserved1                   : 3;
		u64 inc_size                    : 1;
		u64 write_mask_valid            : 1;
		u64 context                     : 3;
		u64 reserved2                   : 1;
		u64 class                       : 6;
		u64 reserved3                   : 1;
		u64 non_arch                    : 1;
	};
	u64 raw;
};

#define TDX_MD_ELEMENT_SIZE_CODE(_field_id)			\
	({ union tdx_md_field_id _fid = { .raw = (_field_id)};  \
		_fid.element_size_code; })

#endif /* __KVM_X86_TDX_ARCH_H */
