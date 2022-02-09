// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "tdx.h"

#ifdef CONFIG_INTEL_TDX_HOST
static bool __read_mostly enable_tdx = true;
module_param_named(tdx, enable_tdx, bool, 0644);
static inline void disable_tdx(void)
{
	enable_tdx = false;
}
#else
#define enable_tdx false
static inline void disable_tdx(void) {}
#endif

/*
 * workaround to compile.
 * TODO: once the TDX module initiation code in x86 host is merged, remove this.
 */
#if __has_include(<asm/tdx_host.h>)
#include <asm/tdx_host.h>
#else
static inline int detect_tdx(void) { return -ENODEV; }
#endif

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

static u64 hkid_mask __ro_after_init;
static u8 hkid_start_pos __ro_after_init;

static int __init __tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	u32 max_pa;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (!detect_tdx())
		return -ENODEV;

	if (WARN_ON_ONCE(x86_ops->tlb_remote_flush))
		return -EIO;

	max_pa = cpuid_eax(0x80000008) & 0xff;
	hkid_start_pos = boot_cpu_data.x86_phys_bits;
	hkid_mask = GENMASK_ULL(max_pa - 1, hkid_start_pos);

	return 0;
}

void __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	/*
	 * This function is called at the initialization.  No need to protect
	 * enable_tdx.
	 */
	if (!enable_tdx)
		return;

	if (__tdx_hardware_setup(&vt_x86_ops))
		disable_tdx();
}

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size)
{
	*vcpu_size = sizeof(struct vcpu_tdx);
	*vcpu_align = __alignof__(struct vcpu_tdx);

	if (sizeof(struct kvm_tdx) > *vm_size)
		*vm_size = sizeof(struct kvm_tdx);
}
