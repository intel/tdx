/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_H
#define __KVM_X86_TDX_H

#ifdef CONFIG_INTEL_TDX_HOST

#include "tdx_ops.h"

int tdx_module_setup(void);

struct tdx_td_page {
	unsigned long va;
	hpa_t pa;
	bool added;
};

struct kvm_tdx {
	struct kvm kvm;

	struct tdx_td_page tdr;
	struct tdx_td_page *tdcs;

	u64 attributes;
	u64 xfam;
	int hkid;

	int cpuid_nent;
	struct kvm_cpuid_entry2 cpuid_entries[KVM_MAX_CPUID_ENTRIES];

	u64 tsc_offset;
	unsigned long tsc_khz;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;

	struct tdx_td_page tdvpr;
	struct tdx_td_page *tdvpx;
};

static inline bool is_td(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_X86_TDX_VM;
}

static inline bool is_td_vcpu(struct kvm_vcpu *vcpu)
{
	return is_td(vcpu->kvm);
}

static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_tdx, kvm);
}

static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_tdx, vcpu);
}

static inline bool is_td_initialized(struct kvm *kvm)
{
	return !!kvm->max_vcpus;
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

static __always_inline void tdvps_state_non_arch_check(u64 field, u8 bits) {}
static __always_inline void tdvps_management_check(u64 field, u8 bits) {}

#define TDX_BUILD_TDVPS_ACCESSORS(bits, uclass, lclass)				\
static __always_inline u##bits td_##lclass##_read##bits(struct vcpu_tdx *tdx,	\
							u32 field)		\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_rd(tdx->tdvpr.pa, TDVPS_##uclass(field), &out);		\
	if (unlikely(err)) {							\
		pr_err("TDH_VP_RD["#uclass".0x%x] failed: 0x%llx\n",		\
		       field, err);						\
		return 0;							\
	}									\
	return (u##bits)out.r8;							\
}										\
static __always_inline void td_##lclass##_write##bits(struct vcpu_tdx *tdx,	\
						      u32 field, u##bits val)	\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_wr(tdx->tdvpr.pa, TDVPS_##uclass(field), val,		\
		      GENMASK_ULL(bits - 1, 0), &out);				\
	if (unlikely(err))							\
		pr_err("TDH_VP_WR["#uclass".0x%x] = 0x%llx failed: 0x%llx\n",	\
		       field, (u64)val, err);					\
}										\
static __always_inline void td_##lclass##_setbit##bits(struct vcpu_tdx *tdx,	\
						       u32 field, u64 bit)	\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_wr(tdx->tdvpr.pa, TDVPS_##uclass(field), bit, bit,		\
			&out);							\
	if (unlikely(err))							\
		pr_err("TDH_VP_WR["#uclass".0x%x] |= 0x%llx failed: 0x%llx\n",	\
		       field, bit, err);					\
}										\
static __always_inline void td_##lclass##_clearbit##bits(struct vcpu_tdx *tdx,	\
							 u32 field, u64 bit)	\
{										\
	struct tdx_module_output out;						\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_wr(tdx->tdvpr.pa, TDVPS_##uclass(field), 0, bit,		\
			&out);							\
	if (unlikely(err))							\
		pr_err("TDH_VP_WR["#uclass".0x%x] &= ~0x%llx failed: 0x%llx\n",	\
		       field, bit,  err);					\
}

TDX_BUILD_TDVPS_ACCESSORS(16, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(32, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(64, VMCS, vmcs);

TDX_BUILD_TDVPS_ACCESSORS(64, STATE_NON_ARCH, state_non_arch);
TDX_BUILD_TDVPS_ACCESSORS(8, MANAGEMENT, management);

static __always_inline u64 td_tdcs_exec_read64(struct kvm_tdx *kvm_tdx, u32 field)
{
	struct tdx_module_output out;
	u64 err;

	err = tdh_mng_rd(kvm_tdx->tdr.pa, TDCS_EXEC(field), &out);
	if (unlikely(err)) {
		pr_err("TDH_MNG_RD[EXEC.0x%x] failed: 0x%llx\n", field, err);
		return 0;
	}
	return out.r8;
}

#else
static inline int tdx_module_setup(void) { return -ENODEV; };

struct kvm_tdx;
struct vcpu_tdx;

static inline bool is_td(struct kvm *kvm) { return false; }
static inline bool is_td_vcpu(struct kvm_vcpu *vcpu) { return false; }
static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm) { return NULL; }
static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu) { return NULL; }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_X86_TDX_H */
