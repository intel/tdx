// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include <linux/kernel.h>
#include <linux/bug.h>

#include "tdx_ops.h"

struct tdx_name {
	u64 value;
	const char *name;
};

static const char *tdx_find_name(u64 value, const struct tdx_name *names,
				int size, const char *not_found)
{
	int i;

	for (i = 0; i < size; i++) {
		if (value == names[i].value)
			return names[i].name;
	}
	return not_found;
}

#define BUILD_NAME(name) { name, #name }

static const char *tdx_seamcall_name(u64 op)
{
	static const struct tdx_name names[] = {
		BUILD_NAME(TDH_VP_ENTER),
		BUILD_NAME(TDH_MNG_ADDCX),
		BUILD_NAME(TDH_MEM_PAGE_ADD),
		BUILD_NAME(TDH_MEM_SEPT_ADD),
		BUILD_NAME(TDH_VP_ADDCX),
		BUILD_NAME(TDH_MEM_PAGE_RELOCATE),
		BUILD_NAME(TDH_MEM_PAGE_AUG),
		BUILD_NAME(TDH_MEM_RANGE_BLOCK),
		BUILD_NAME(TDH_MNG_KEY_CONFIG),
		BUILD_NAME(TDH_MNG_CREATE),
		BUILD_NAME(TDH_VP_CREATE),
		BUILD_NAME(TDH_MNG_RD),
		BUILD_NAME(TDH_MEM_RD),
		BUILD_NAME(TDH_MEM_WR),
		BUILD_NAME(TDH_MEM_PAGE_DEMOTE),
		BUILD_NAME(TDH_MR_EXTEND),
		BUILD_NAME(TDH_MR_FINALIZE),
		BUILD_NAME(TDH_VP_FLUSH),
		BUILD_NAME(TDH_MNG_VPFLUSHDONE),
		BUILD_NAME(TDH_MNG_KEY_FREEID),
		BUILD_NAME(TDH_MNG_INIT),
		BUILD_NAME(TDH_VP_INIT),
		BUILD_NAME(TDH_MEM_PAGE_PROMOTE),
		BUILD_NAME(TDH_VP_RD),
		BUILD_NAME(TDH_MNG_KEY_RECLAIMID),
		BUILD_NAME(TDH_PHYMEM_PAGE_RECLAIM),
		BUILD_NAME(TDH_MEM_PAGE_REMOVE),
		BUILD_NAME(TDH_MEM_SEPT_REMOVE),
		BUILD_NAME(TDH_MEM_TRACK),
		BUILD_NAME(TDH_MEM_RANGE_UNBLOCK),
		BUILD_NAME(TDH_PHYMEM_CACHE_WB),
		BUILD_NAME(TDH_PHYMEM_PAGE_WBINVD),
		BUILD_NAME(TDH_VP_WR),
		BUILD_NAME(TDH_SYS_LP_SHUTDOWN),
	};

	return tdx_find_name(op, names, ARRAY_SIZE(names),
			"Unknown TDX SEAMCALL op");
}

static const char *tdx_error_name(u64 error_code)
{
	static const struct tdx_name names[] = {
		BUILD_NAME(TDX_SEAMCALL_VMFAILINVALID),
		BUILD_NAME(TDX_SEAMCALL_STATUS_MASK),
		BUILD_NAME(TDX_SUCCESS),
		BUILD_NAME(TDX_NON_RECOVERABLE_VCPU),
		BUILD_NAME(TDX_NON_RECOVERABLE_TD),
		BUILD_NAME(TDX_INTERRUPTED_RESUMABLE),
		BUILD_NAME(TDX_INTERRUPTED_RESTARTABLE),
		BUILD_NAME(TDX_NON_RECOVERABLE_FATAL),
		BUILD_NAME(TDX_INVALID_RESUMPTION),
		BUILD_NAME(TDX_NON_RECOVERABLE_TD_NO_APIC),
		BUILD_NAME(TDX_OPERAND_INVALID),
		BUILD_NAME(TDX_OPERAND_ADDR_RANGE_ERROR),
		BUILD_NAME(TDX_OPERAND_BUSY),
		BUILD_NAME(TDX_PREVIOUS_TLB_EPOCH_BUSY),
		BUILD_NAME(TDX_SYS_BUSY),
		BUILD_NAME(TDX_PAGE_METADATA_INCORRECT),
		BUILD_NAME(TDX_PAGE_ALREADY_FREE),
		BUILD_NAME(TDX_PAGE_NOT_OWNED_BY_TD),
		BUILD_NAME(TDX_PAGE_NOT_FREE),
		BUILD_NAME(TDX_TD_ASSOCIATED_PAGES_EXIST),
		BUILD_NAME(TDX_SYSINIT_NOT_PENDING),
		BUILD_NAME(TDX_SYSINIT_NOT_DONE),
		BUILD_NAME(TDX_SYSINITLP_NOT_DONE),
		BUILD_NAME(TDX_SYSINITLP_DONE),
		BUILD_NAME(TDX_SYS_NOT_READY),
		BUILD_NAME(TDX_SYS_SHUTDOWN),
		BUILD_NAME(TDX_SYSCONFIG_NOT_DONE),
		BUILD_NAME(TDX_TD_NOT_INITIALIZED),
		BUILD_NAME(TDX_TD_INITIALIZED),
		BUILD_NAME(TDX_TD_NOT_FINALIZED),
		BUILD_NAME(TDX_TD_FINALIZED),
		BUILD_NAME(TDX_TD_FATAL),
		BUILD_NAME(TDX_TD_NON_DEBUG),
		BUILD_NAME(TDX_LIFECYCLE_STATE_INCORRECT),
		BUILD_NAME(TDX_TDCX_NUM_INCORRECT),
		BUILD_NAME(TDX_VCPU_STATE_INCORRECT),
		BUILD_NAME(TDX_VCPU_ASSOCIATED),
		BUILD_NAME(TDX_VCPU_NOT_ASSOCIATED),
		BUILD_NAME(TDX_TDVPX_NUM_INCORRECT),
		BUILD_NAME(TDX_NO_VALID_VE_INFO),
		BUILD_NAME(TDX_MAX_VCPUS_EXCEEDED),
		BUILD_NAME(TDX_TSC_ROLLBACK),
		BUILD_NAME(TDX_FIELD_NOT_WRITABLE),
		BUILD_NAME(TDX_FIELD_NOT_READABLE),
		BUILD_NAME(TDX_TD_VMCS_FIELD_NOT_INITIALIZED),
		BUILD_NAME(TDX_KEY_GENERATION_FAILED),
		BUILD_NAME(TDX_TD_KEYS_NOT_CONFIGURED),
		BUILD_NAME(TDX_KEY_STATE_INCORRECT),
		BUILD_NAME(TDX_KEY_CONFIGURED),
		BUILD_NAME(TDX_WBCACHE_NOT_COMPLETE),
		BUILD_NAME(TDX_HKID_NOT_FREE),
		BUILD_NAME(TDX_NO_HKID_READY_TO_WBCACHE),
		BUILD_NAME(TDX_WBCACHE_RESUME_ERROR),
		BUILD_NAME(TDX_FLUSHVP_NOT_DONE),
		BUILD_NAME(TDX_NUM_ACTIVATED_HKIDS_NOT_SUPPORRTED),
		BUILD_NAME(TDX_INCORRECT_CPUID_VALUE),
		BUILD_NAME(TDX_BOOT_NT4_SET),
		BUILD_NAME(TDX_INCONSISTENT_CPUID_FIELD),
		BUILD_NAME(TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED),
		BUILD_NAME(TDX_INVALID_WBINVD_SCOPE),
		BUILD_NAME(TDX_INVALID_PKG_ID),
		BUILD_NAME(TDX_CPUID_LEAF_NOT_SUPPORTED),
		BUILD_NAME(TDX_SMRR_NOT_LOCKED),
		BUILD_NAME(TDX_INVALID_SMRR_CONFIGURATION),
		BUILD_NAME(TDX_SMRR_OVERLAPS_CMR),
		BUILD_NAME(TDX_SMRR_LOCK_NOT_SUPPORTED),
		BUILD_NAME(TDX_SMRR_NOT_SUPPORTED),
		BUILD_NAME(TDX_INCONSISTENT_MSR),
		BUILD_NAME(TDX_INCORRECT_MSR_VALUE),
		BUILD_NAME(TDX_SEAMREPORT_NOT_AVAILABLE),
		BUILD_NAME(TDX_PERF_COUNTERS_ARE_PEBS_ENABLED),
		BUILD_NAME(TDX_INVALID_TDMR),
		BUILD_NAME(TDX_NON_ORDERED_TDMR),
		BUILD_NAME(TDX_TDMR_OUTSIDE_CMRS),
		BUILD_NAME(TDX_TDMR_ALREADY_INITIALIZED),
		BUILD_NAME(TDX_INVALID_PAMT),
		BUILD_NAME(TDX_PAMT_OUTSIDE_CMRS),
		BUILD_NAME(TDX_PAMT_OVERLAP),
		BUILD_NAME(TDX_INVALID_RESERVED_IN_TDMR),
		BUILD_NAME(TDX_NON_ORDERED_RESERVED_IN_TDMR),
		BUILD_NAME(TDX_CMR_LIST_INVALID),
		BUILD_NAME(TDX_EPT_WALK_FAILED),
		BUILD_NAME(TDX_EPT_ENTRY_FREE),
		BUILD_NAME(TDX_EPT_ENTRY_NOT_FREE),
		BUILD_NAME(TDX_EPT_ENTRY_NOT_PRESENT),
		BUILD_NAME(TDX_EPT_ENTRY_NOT_LEAF),
		BUILD_NAME(TDX_EPT_ENTRY_LEAF),
		BUILD_NAME(TDX_GPA_RANGE_NOT_BLOCKED),
		BUILD_NAME(TDX_GPA_RANGE_ALREADY_BLOCKED),
		BUILD_NAME(TDX_TLB_TRACKING_NOT_DONE),
		BUILD_NAME(TDX_EPT_INVALID_PROMOTE_CONDITIONS),
		BUILD_NAME(TDX_PAGE_ALREADY_ACCEPTED),
		BUILD_NAME(TDX_PAGE_SIZE_MISMATCH),
		BUILD_NAME(TDX_EPT_ENTRY_STATE_INCORRECT),
	};

	return tdx_find_name(error_code & TDX_SEAMCALL_STATUS_MASK,
			names, ARRAY_SIZE(names),
			"Unknown SEAMCALL status code");
}

static bool tdx_has_operand_id(u64 error_code)
{
	switch (error_code & TDX_SEAMCALL_STATUS_MASK) {
	case TDX_OPERAND_INVALID:
	case TDX_OPERAND_ADDR_RANGE_ERROR:
	case TDX_OPERAND_BUSY:
	case TDX_PAGE_METADATA_INCORRECT:
	case TDX_PAGE_ALREADY_FREE:
	case TDX_PAGE_NOT_OWNED_BY_TD:
	case TDX_PAGE_NOT_FREE:
	case TDX_EPT_WALK_FAILED:
	case TDX_EPT_ENTRY_FREE:
	case TDX_EPT_ENTRY_NOT_FREE:
	case TDX_EPT_ENTRY_NOT_PRESENT:
	case TDX_EPT_ENTRY_NOT_LEAF:
	case TDX_EPT_ENTRY_LEAF:
	case TDX_GPA_RANGE_NOT_BLOCKED:
	case TDX_GPA_RANGE_ALREADY_BLOCKED:
	case TDX_TLB_TRACKING_NOT_DONE:
	case TDX_EPT_INVALID_PROMOTE_CONDITIONS:
		return true;
	default:
		return false;
	}
}

#define TDX_STATUS_CODE_OPERAND_ID_MASK	0xffffffffULL

static const char *tdx_operand_id(u64 error_code)
{
	static const struct tdx_name names[] = {
		{ 0, "RAX" },
		{ 1, "RCX" },
		{ 2, "RDX" },
		{ 3, "RBX" },
		{ 4, "Reserved_RSP" },
		{ 5, "RBP" },
		{ 6, "RSI" },
		{ 7, "RDI" },
		{ 8, "R8" },
		{ 9, "R9" },
		{ 10, "R10" },
		{ 11, "R11" },
		{ 12, "R12" },
		{ 13, "R13" },
		{ 14, "R14" },
		{ 15, "R15" },
		{ 64, "ATTRIBUTES" },
		{ 65, "XFAM" },
		{ 66, "EXEC_CONTROLS" },
		{ 67, "EPTP_CONTROLS" },
		{ 68, "MAX_VCPUS" },
		{ 69, "CPUID_CONFIG" },
		{ 70, "TSC_FREQUENCY" },
		{ 96, "TDMR_INFO_PA" },
		{ 128, "TDR" },
		{ 129, "TDCX" },
		{ 130, "TDVPR" },
		{ 131, "TDVPX" },
		{ 144, "TDCS" },
		{ 145, "TDVPS" },
		{ 146, "SEPT" },
		{ 168, "RTMR" },
		{ 169, "TD_EPOCH" },
		{ 184, "SYS" },
		{ 185, "TDMR" },
		{ 186, "KOT" },
		{ 187, "KET" },
		{ 188, "WBCACHE" },
	};
	u64 operand_id = error_code & TDX_STATUS_CODE_OPERAND_ID_MASK;

	return tdx_find_name(operand_id, names, ARRAY_SIZE(names),
			"Unknown operand id");
}

static const char *tdx_spte_entry_state(u64 state)
{
	static const struct tdx_name names[] = {
		{0, "SEPT_FREE"},
		{1, "SEPT_BLOCKED"},
		{2, "SEPT_PENDING"},
		{3, "SEPT_PENDING_BLOCKED"},
		{4, "SEPT_PRESENT"},
	};

	return tdx_find_name(state, names, ARRAY_SIZE(names), "Invalid");
}

union tdx_ex_ret {
	struct tdx_module_output regs;
	/* Functions that walk SEPT */
	struct {
		u64 septe;
		struct {
			u64 level		:3;
			u64 sept_reserved_0	:5;
			u64 state		:8;
			u64 sept_reserved_1	:48;
		};
	} sept_walk;
};

void pr_tdx_error(u64 op, u64 error_code, const struct tdx_module_output *out)
{
	union tdx_ex_ret ex;
	bool has_operand_id = tdx_has_operand_id(error_code);
	u64 operand_id = error_code & TDX_STATUS_CODE_OPERAND_ID_MASK;

	if (!out) {
		pr_err_ratelimited("SEAMCALL[%s(%lld)] failed: %s(0x%llx)\n",
				   tdx_seamcall_name(op), op,
				   tdx_error_name(error_code), error_code);
		return;
	}

	ex.regs = *out;
	switch (error_code & TDX_SEAMCALL_STATUS_MASK) {
	case TDX_EPT_WALK_FAILED:
	case TDX_EPT_ENTRY_STATE_INCORRECT: {
		pr_err("SEAMCALL[%s(%lld)] %s(0x%llx) Secure EPT walk error: "
		       "SEPTE 0x%llx, level %d, %s\n",
		       tdx_seamcall_name(op), op, tdx_error_name(error_code), error_code,
		       ex.sept_walk.septe, ex.sept_walk.level,
		       tdx_spte_entry_state(ex.sept_walk.state));
		break;
	}
	default:
		pr_err_ratelimited("SEAMCALL[%s(%lld)] failed: %s(0x%llx) operand %s(0x%llx) "
				   "RCX 0x%llx, RDX 0x%llx, R8 0x%llx, R9 0x%llx, R10 0x%llx, "
				   "R11 0x%llx\n",
				   tdx_seamcall_name(op), op, tdx_error_name(error_code),
				   error_code,
				   has_operand_id ?  tdx_operand_id(operand_id) : "-",
				   has_operand_id ? operand_id : 0,
				   ex.regs.rcx, ex.regs.rdx, ex.regs.r8,
				   ex.regs.r9, ex.regs.r10, ex.regs.r11);
		break;
	}
}
