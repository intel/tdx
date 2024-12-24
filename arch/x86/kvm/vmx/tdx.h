/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_VMX_TDX_H
#define __KVM_X86_VMX_TDX_H

#include "tdx_arch.h"
#include "tdx_errno.h"

#ifdef CONFIG_INTEL_TDX_HOST
int tdx_bringup(void);
void tdx_cleanup(void);

extern bool enable_tdx;

/* TDX module hardware states. These follow the TDX module OP_STATEs. */
enum kvm_tdx_state {
	TD_STATE_UNINITIALIZED = 0,
	TD_STATE_INITIALIZED,
	TD_STATE_RUNNABLE,
};

struct kvm_tdx {
	struct kvm kvm;

	unsigned long tdr_pa;
	unsigned long *tdcs_pa;

	u64 attributes;
	u64 xfam;
	int hkid;
	u8 nr_tdcs_pages;

	u64 tsc_offset;

	enum kvm_tdx_state state;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;
	/* TDX specific members follow. */
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

static __always_inline u64 td_tdcs_exec_read64(struct kvm_tdx *kvm_tdx, u32 field)
{
	u64 err, data;

	err = tdh_mng_rd(kvm_tdx->tdr_pa, TDCS_EXEC(field), &data);
	if (unlikely(err)) {
		pr_err("TDH_MNG_RD[EXEC.0x%x] failed: 0x%llx\n", field, err);
		return 0;
	}
	return data;
}
#else
static inline int tdx_bringup(void) { return 0; }
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
