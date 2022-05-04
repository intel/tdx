#ifndef  __KVM_X86_VMX_TDX_H
#define __KVM_X86_VMX_TDX_H

#include "tdx_arch.h"
#include "tdx_errno.h"

#ifdef CONFIG_INTEL_TDX_HOST
void tdx_bringup(void);
void tdx_cleanup(void);

extern bool enable_tdx;

#include "irq.h"
#include "posted_intr.h"
#include "pmu_intel.h"

struct kvm_tdx {
	struct kvm kvm;

	unsigned long tdr_pa;
	unsigned long *tdcs_pa;

	u64 attributes;
	u64 xfam;
	int hkid;

	/*
	 * Used on each TD-exit, see tdx_user_return_msr_update_cache().
	 * TSX_CTRL value on TD exit
	 * - set 0     if guest TSX enabled
	 * - preserved if guest TSX disabled
	 */
	bool tsx_supported;

	bool finalized;
	atomic_t tdh_mem_track;

	u64 tsc_offset;

	/* For KVM_MAP_MEMORY and KVM_TDX_INIT_MEM_REGION. */
	atomic64_t nr_premapped;

	struct kvm_cpuid2 *cpuid;
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

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;

	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	/* Used if this vCPU is waiting for PI notification wakeup. */
	struct list_head pi_wakeup_list;
	/* Until here same layout to struct vcpu_pi. */

	unsigned long tdvpr_pa;
	unsigned long *tdcx_pa;
	bool td_vcpu_created;

	struct list_head cpu_list;

	union tdx_exit_reason exit_reason;

	bool initialized;

	bool host_state_need_save;
	bool host_state_need_restore;
	u64 msr_host_kernel_gs_base;

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

static __always_inline void tdvps_vmcs_check(u32 field, u8 bits)
{
#define VMCS_ENC_ACCESS_TYPE_MASK	0x1UL
#define VMCS_ENC_ACCESS_TYPE_FULL	0x0UL
#define VMCS_ENC_ACCESS_TYPE_HIGH	0x1UL
#define VMCS_ENC_ACCESS_TYPE(field)	((field) & VMCS_ENC_ACCESS_TYPE_MASK)

	/* TDX is 64bit only.  HIGH field isn't supported. */
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) &&
			 VMCS_ENC_ACCESS_TYPE(field) == VMCS_ENC_ACCESS_TYPE_HIGH,
			 "Read/Write to TD VMCS *_HIGH fields not supported");

	BUILD_BUG_ON(bits != 16 && bits != 32 && bits != 64);

#define VMCS_ENC_WIDTH_MASK	GENMASK(14, 13)
#define VMCS_ENC_WIDTH_16BIT	(0UL << 13)
#define VMCS_ENC_WIDTH_64BIT	(1UL << 13)
#define VMCS_ENC_WIDTH_32BIT	(2UL << 13)
#define VMCS_ENC_WIDTH_NATURAL	(3UL << 13)
#define VMCS_ENC_WIDTH(field)	((field) & VMCS_ENC_WIDTH_MASK)

	/* TDX is 64bit only.  i.e. natural width = 64bit. */
	BUILD_BUG_ON_MSG(bits != 64 && __builtin_constant_p(field) &&
			 (VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_64BIT ||
			  VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_NATURAL),
			 "Invalid TD VMCS access for 64-bit field");
	BUILD_BUG_ON_MSG(bits != 32 && __builtin_constant_p(field) &&
			 VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_32BIT,
			 "Invalid TD VMCS access for 32-bit field");
	BUILD_BUG_ON_MSG(bits != 16 && __builtin_constant_p(field) &&
			 VMCS_ENC_WIDTH(field) == VMCS_ENC_WIDTH_16BIT,
			 "Invalid TD VMCS access for 16-bit field");
}

static __always_inline void tdvps_management_check(u64 field, u8 bits) {}
static __always_inline void tdvps_state_non_arch_check(u64 field, u8 bits) {}

#define TDX_BUILD_TDVPS_ACCESSORS(bits, uclass, lclass)				\
static __always_inline u##bits td_##lclass##_read##bits(struct vcpu_tdx *tdx,	\
							u32 field)		\
{										\
	u64 err, data;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_rd(tdx, TDVPS_##uclass(field), &data);			\
	if (KVM_BUG_ON(err, tdx->vcpu.kvm)) {					\
		pr_err("TDH_VP_RD["#uclass".0x%x] failed: 0x%llx\n",		\
		       field, err);						\
		return 0;							\
	}									\
	return (u##bits)data;							\
}										\
static __always_inline void td_##lclass##_write##bits(struct vcpu_tdx *tdx,	\
						      u32 field, u##bits val)	\
{										\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_wr(tdx, TDVPS_##uclass(field), val,			\
		      GENMASK_ULL(bits - 1, 0));				\
	if (KVM_BUG_ON(err, tdx->vcpu.kvm))					\
		pr_err("TDH_VP_WR["#uclass".0x%x] = 0x%llx failed: 0x%llx\n",	\
		       field, (u64)val, err);					\
}										\
static __always_inline void td_##lclass##_setbit##bits(struct vcpu_tdx *tdx,	\
						       u32 field, u64 bit)	\
{										\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_wr(tdx, TDVPS_##uclass(field), bit, bit);			\
	if (KVM_BUG_ON(err, tdx->vcpu.kvm))					\
		pr_err("TDH_VP_WR["#uclass".0x%x] |= 0x%llx failed: 0x%llx\n",	\
		       field, bit, err);					\
}										\
static __always_inline void td_##lclass##_clearbit##bits(struct vcpu_tdx *tdx,	\
							 u32 field, u64 bit)	\
{										\
	u64 err;								\
										\
	tdvps_##lclass##_check(field, bits);					\
	err = tdh_vp_wr(tdx, TDVPS_##uclass(field), 0, bit);			\
	if (KVM_BUG_ON(err, tdx->vcpu.kvm))					\
		pr_err("TDH_VP_WR["#uclass".0x%x] &= ~0x%llx failed: 0x%llx\n",	\
		       field, bit,  err);					\
}


bool tdx_interrupt_allowed(struct kvm_vcpu *vcpu);

TDX_BUILD_TDVPS_ACCESSORS(16, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(32, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(64, VMCS, vmcs);

TDX_BUILD_TDVPS_ACCESSORS(8, MANAGEMENT, management);
TDX_BUILD_TDVPS_ACCESSORS(64, STATE_NON_ARCH, state_non_arch);

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
static inline bool tdx_interrupt_allowed(struct kvm_vcpu *vcpu) { return false; }

#endif

#endif
