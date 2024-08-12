#ifndef  __KVM_X86_VMX_TDX_H
#define __KVM_X86_VMX_TDX_H

#include "tdx_arch.h"
#include "tdx_errno.h"

#ifdef CONFIG_INTEL_TDX_HOST
void tdx_bringup(void);
void tdx_cleanup(void);

extern bool enable_tdx;

#include "pmu_intel.h"

struct kvm_tdx {
	struct kvm kvm;

	unsigned long tdr_pa;
	unsigned long *tdcs_pa;

	u64 attributes;
	u64 xfam;
	int hkid;

	bool finalized;

	u64 tsc_offset;

	/* For KVM_MAP_MEMORY and KVM_TDX_INIT_MEM_REGION. */
	atomic64_t nr_premapped;

	struct kvm_cpuid2 *cpuid;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;

	unsigned long tdvpr_pa;
	unsigned long *tdcx_pa;
	bool td_vcpu_created;

	bool initialized;

	/*
	 * Dummy to make pmu_intel not corrupt memory.
	 * TODO: Support PMU for TDX.  Future work.
	 */
	struct lbr_desc lbr_desc;
};

static inline bool is_td(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_X86_TDX_VM;
}

static inline bool is_td_vcpu(struct kvm_vcpu *vcpu)
{
	return is_td(vcpu->kvm);
}

static __always_inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_tdx, kvm);
}

static __always_inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_tdx, vcpu);
}

/*
 * SEAMCALL wrappers
 *
 * Put it here as most of those wrappers need declaration of
 * 'struct kvm_tdx' and 'struct vcpu_tdx'.
 */
#include "tdx_ops.h"

#else
static inline void tdx_bringup(void) {}
static inline void tdx_cleanup(void) {}

#define enable_tdx	0

struct kvm_tdx {
	struct kvm kvm;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;
};

static inline bool is_td(struct kvm *kvm) { return false; }
static inline bool is_td_vcpu(struct kvm_vcpu *vcpu) { return false; }
static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm) { return NULL; }
static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu) { return NULL; }

#endif

#endif
