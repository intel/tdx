/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_H
#define __KVM_X86_TDX_H

#include <linux/list.h>
#include <linux/kvm_host.h>

#include "tdx_errno.h"
#include "tdx_arch.h"
#include "tdx_ops.h"
#include "posted_intr.h"

#ifdef CONFIG_INTEL_TDX_HOST

struct tdx_td_page {
	unsigned long va;
	hpa_t pa;
	bool added;
};

struct kvm_tdx {
	struct kvm kvm;

	struct tdx_td_page tdr;
	struct tdx_td_page tdcs[TDX_NR_TDCX_PAGES];

	u64 attributes;
	u64 xfam;
	int hkid;

	int cpuid_nent;
	struct kvm_cpuid_entry2 cpuid_entries[KVM_MAX_CPUID_ENTRIES];

	bool finalized;
	bool tdh_mem_track;

	hpa_t source_pa;

	u64 tsc_offset;

	/*
	 * Lock to prevent seamcalls from running concurrently
	 * when TDP MMU is enabled, because TDP fault handler
	 * runs concurrently.
	 */
	spinlock_t seamcall_lock;
};

union tdx_exit_reason {
	struct {
		/* 31:0 mirror the VMX Exit Reason format */
		u64 basic		: 16;
		u64 reserved16		: 1;
		u64 reserved17		: 1;
		u64 reserved18		: 1;
		u64 reserved19		: 1;
		u64 reserved20		: 1;
		u64 reserved21		: 1;
		u64 reserved22		: 1;
		u64 reserved23		: 1;
		u64 reserved24		: 1;
		u64 reserved25		: 1;
		u64 bus_lock_detected	: 1;
		u64 enclave_mode	: 1;
		u64 smi_pending_mtf	: 1;
		u64 smi_from_vmx_root	: 1;
		u64 reserved30		: 1;
		u64 failed_vmentry	: 1;

		/* 63:32 are TDX specific */
		u64 details_l1		: 8;
		u64 class		: 8;
		u64 reserved61_48	: 14;
		u64 non_recoverable	: 1;
		u64 error		: 1;
	};
	u64 full;
};

union tdx_ext_exit_qualification {
	struct {
		u64 type		: 4;
		u64 reserved0		: 28;
		u64 req_sept_level	: 3;
		u64 err_sept_level	: 3;
		u64 err_sept_state	: 8;
		u64 err_sept_is_leaf	: 1;
		u64 reserved1		: 17;
	};
	u64 full;
};

enum tdx_ext_exit_qualification_type {
	EXT_EXIT_QUAL_NONE,
	EXT_EXIT_QUAL_ACCEPT,
	NUM_EXT_EXIT_QUAL,
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;

	struct tdx_td_page tdvpr;
	struct tdx_td_page tdvpx[TDX_NR_TDVPX_PAGES];

	struct list_head cpu_list;

	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	union {
		struct {
			union {
				struct {
					u16 gpr_mask;
					u16 xmm_mask;
				};
				u32 regs_mask;
			};
			u32 reserved;
		};
		u64 rcx;
	} tdvmcall;

	union tdx_exit_reason exit_reason;

	bool initialized;

	bool host_state_need_save;
	bool host_state_need_restore;
	u64 msr_host_kernel_gs_base;
	u64 guest_perf_global_ctrl;
};

struct tdx_capabilities {
	u8 tdcs_nr_pages;
	u8 tdvpx_nr_pages;

	u64 attrs_fixed0;
	u64 attrs_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;

	u32 nr_cpuid_configs;
	struct tdx_cpuid_config cpuid_configs[TDX_MAX_NR_CPUID_CONFIGS];
};

static inline bool is_td(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_X86_TDX_VM;
}

static inline bool is_td_vcpu(struct kvm_vcpu *vcpu)
{
	return is_td(vcpu->kvm);
}

static inline bool is_debug_td(struct kvm_vcpu *vcpu)
{
	return !vcpu->arch.guest_state_protected;
}

static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_tdx, kvm);
}

static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_tdx, vcpu);
}

static inline bool is_td_vcpu_initialized(struct kvm_vcpu *vcpu)
{
	return to_tdx(vcpu)->initialized;
}

static __always_inline void tdvps_vmcs_check(u32 field, u8 bits)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) && (field) & 0x1,
			 "Read/Write to TD VMCS *_HIGH fields not supported");

	BUILD_BUG_ON(bits != 16 && bits != 32 && bits != 64);

	BUILD_BUG_ON_MSG(bits != 64 && __builtin_constant_p(field) &&
			 (((field) & 0x6000) == 0x2000 ||
			  ((field) & 0x6000) == 0x6000),
			 "Invalid TD VMCS access for 64-bit field");
	BUILD_BUG_ON_MSG(bits != 32 && __builtin_constant_p(field) &&
			 ((field) & 0x6000) == 0x4000,
			 "Invalid TD VMCS access for 32-bit field");
	BUILD_BUG_ON_MSG(bits != 16 && __builtin_constant_p(field) &&
			 ((field) & 0x6000) == 0x0000,
			 "Invalid TD VMCS access for 16-bit field");
}

static __always_inline void tdvps_gpr_check(u64 field, u8 bits)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) && (field) >= NR_VCPU_REGS,
			 "Invalid TD guest GPR index");
}

static __always_inline void tdvps_apic_check(u64 field, u8 bits) {}
static __always_inline void tdvps_dr_check(u64 field, u8 bits) {}
static __always_inline void tdvps_state_check(u64 field, u8 bits) {}
static __always_inline void tdvps_state_non_arch_check(u64 field, u8 bits) {}
static __always_inline void tdvps_msr_check(u64 field, u8 bits) {}
static __always_inline void tdvps_management_check(u64 field, u8 bits) {}

#define TDX_BUILD_TDVPS_ACCESSORS(bits, uclass, lclass)			       \
static __always_inline u##bits td_##lclass##_read##bits(struct vcpu_tdx *tdx,  \
							u32 field)	       \
{									       \
	struct tdx_ex_ret ex_ret;					       \
	u64 err;							       \
									       \
	tdvps_##lclass##_check(field, bits);				       \
	err = tdh_vp_rd(tdx->tdvpr.pa, TDVPS_##uclass(field), &ex_ret);        \
	if (unlikely(err)) {						       \
		pr_err("TDH_VP_RD["#uclass".0x%x] failed: %s (0x%llx)\n",      \
		       field, tdx_error_name(err), err);		       \
		return 0;						       \
	}								       \
	return (u##bits)ex_ret.regs.r8;					       \
}									       \
static __always_inline void td_##lclass##_write##bits(struct vcpu_tdx *tdx,    \
						      u32 field, u##bits val)  \
{									       \
	struct tdx_ex_ret ex_ret;					       \
	u64 err;							       \
									       \
	tdvps_##lclass##_check(field, bits);				       \
	err = tdh_vp_wr(tdx->tdvpr.pa, TDVPS_##uclass(field), val,	       \
		      GENMASK_ULL(bits - 1, 0), &ex_ret);		       \
	if (unlikely(err))						       \
		pr_err("TDH_VP_WR["#uclass".0x%x] = 0x%llx failed: %s (0x%llx)\n", \
		       field, (u64)val, tdx_error_name(err), err);	       \
}									       \
static __always_inline void td_##lclass##_setbit##bits(struct vcpu_tdx *tdx,   \
						       u32 field, u64 bit)     \
{									       \
	struct tdx_ex_ret ex_ret;					       \
	u64 err;							       \
									       \
	tdvps_##lclass##_check(field, bits);				       \
	err = tdh_vp_wr(tdx->tdvpr.pa, TDVPS_##uclass(field), bit, bit,        \
			&ex_ret);					       \
	if (unlikely(err))						       \
		pr_err("TDH_VP_WR["#uclass".0x%x] |= 0x%llx failed: %s (0x%llx)\n", \
		       field, bit, tdx_error_name(err), err);		       \
}									       \
static __always_inline void td_##lclass##_clearbit##bits(struct vcpu_tdx *tdx, \
							 u32 field, u64 bit)   \
{									       \
	struct tdx_ex_ret ex_ret;					       \
	u64 err;							       \
									       \
	tdvps_##lclass##_check(field, bits);				       \
	err = tdh_vp_wr(tdx->tdvpr.pa, TDVPS_##uclass(field), 0, bit,	       \
			&ex_ret);					       \
	if (unlikely(err))						       \
		pr_err("TDH_VP_WR["#uclass".0x%x] &= ~0x%llx failed: %s (0x%llx)\n", \
		       field, bit, tdx_error_name(err), err);		       \
}

TDX_BUILD_TDVPS_ACCESSORS(16, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(32, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(64, VMCS, vmcs);

TDX_BUILD_TDVPS_ACCESSORS(64, APIC, apic);
TDX_BUILD_TDVPS_ACCESSORS(64, GPR, gpr);
TDX_BUILD_TDVPS_ACCESSORS(64, DR, dr);
TDX_BUILD_TDVPS_ACCESSORS(64, STATE, state);
TDX_BUILD_TDVPS_ACCESSORS(64, STATE_NON_ARCH, state_non_arch);
TDX_BUILD_TDVPS_ACCESSORS(64, MSR, msr);
TDX_BUILD_TDVPS_ACCESSORS(8, MANAGEMENT, management);

static __always_inline u64 td_tdcs_exec_read64(struct kvm_tdx *kvm_tdx, u32 field)
{
	struct tdx_ex_ret ex_ret;
	u64 err;

	err = tdh_mng_rd(kvm_tdx->tdr.pa, TDCS_EXEC(field), &ex_ret);
	if (unlikely(err)) {
		pr_err("TDH_MNG_RD[EXEC.0x%x] failed: %s (0x%llx)\n", field,
		       tdx_error_name(err), err);
		WARN_ON(1);
		return 0;
	}
	return ex_ret.regs.r8;
}

/* Export for caller in common.h */
static __always_inline unsigned long tdexit_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rcx_read(vcpu);
}

static __always_inline int pg_level_to_tdx_sept_level(enum pg_level level)
{
	WARN_ON(level == PG_LEVEL_NONE);
	return level - 1;
}

#else
struct kvm_tdx;
struct vcpu_tdx;

static inline bool is_td(struct kvm *kvm) { return false; }
static inline bool is_td_vcpu(struct kvm_vcpu *vcpu) { return false; }
static inline bool is_debug_td(struct kvm_vcpu *vcpu) { return false; }
static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm) { return NULL; }
static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu) { return NULL; }
static inline bool is_td_vcpu_initialized(struct kvm_vcpu *vcpu) { return false; }

#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_X86_TDX_H */
