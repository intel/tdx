// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/kvm_host.h>

#include "capabilities.h"
#include "tdx_errno.h"
#include "tdx_ops.h"
#include "x86_ops.h"
#include "cpuid.h"
#include "lapic.h"
#include "tdx.h"

#include <trace/events/kvm.h>
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

/*
 * workaround to compile.
 * TODO: once the TDX module initiation code in x86 host is merged, remove this.
 * The function returns struct tdsysinfo_struct from TDX module provides which
 * is the system wide information about the TDX module.
 * Return NULL if the TDX module is not ready for KVM to use for TDX VM guest
 * life cycle.
 */
#if __has_include(<asm/tdx_host.h>)
#include <asm/tdx_host.h>
#else
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	return NULL;
}
#endif

/* KeyID range reserved to TDX by BIOS */
static u32 tdx_keyids_start __read_mostly;
static u32 tdx_nr_keyids __read_mostly;
static u32 tdx_seam_keyid __read_mostly;

static void __init tdx_keyids_init(void)
{
	u32 nr_mktme_ids;

	rdmsr(MSR_IA32_MKTME_KEYID_PART, nr_mktme_ids, tdx_nr_keyids);

	/* KeyID 0 is reserved, i.e. KeyIDs are 1-based. */
	tdx_keyids_start = nr_mktme_ids + 1;
	tdx_seam_keyid = tdx_keyids_start;
}

/* Capabilities of KVM + the TDX module. */
struct tdx_capabilities tdx_caps;

static u64 hkid_mask __ro_after_init;
static u8 hkid_start_pos __ro_after_init;

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	u32 max_pa;
	const struct tdsysinfo_struct *tdsysinfo = tdx_get_sysinfo();

	BUILD_BUG_ON(sizeof(*tdsysinfo) != 1024);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (tdsysinfo == NULL) {
		WARN_ON_ONCE(cpu_feature_enabled(X86_FEATURE_TDX));
		return -ENODEV;
	}

	if (WARN_ON_ONCE(x86_ops->tlb_remote_flush))
		return -EIO;

	tdx_keyids_init();

	tdx_caps.tdcs_nr_pages = tdsysinfo->tdcs_base_size / PAGE_SIZE;
	tdx_caps.tdvpx_nr_pages = tdsysinfo->tdvps_base_size / PAGE_SIZE - 1;

	tdx_caps.attrs_fixed0 = tdsysinfo->attributes_fixed0;
	tdx_caps.attrs_fixed1 = tdsysinfo->attributes_fixed1;
	tdx_caps.xfam_fixed0 =	tdsysinfo->xfam_fixed0;
	tdx_caps.xfam_fixed1 = tdsysinfo->xfam_fixed1;

	tdx_caps.nr_cpuid_configs = tdsysinfo->num_cpuid_config;
	if (tdx_caps.nr_cpuid_configs > TDX_MAX_NR_CPUID_CONFIGS)
		return -EIO;

	if (!memcpy(tdx_caps.cpuid_configs, tdsysinfo->cpuid_configs,
		    tdsysinfo->num_cpuid_config * sizeof(struct tdx_cpuid_config)))
		return -EIO;

	max_pa = cpuid_eax(0x80000008) & 0xff;
	hkid_start_pos = boot_cpu_data.x86_phys_bits;
	hkid_mask = GENMASK_ULL(max_pa - 1, hkid_start_pos);

	return 0;
}

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size)
{
	*vcpu_size = sizeof(struct vcpu_tdx);
	*vcpu_align = __alignof__(struct vcpu_tdx);

	if (sizeof(struct kvm_tdx) > *vm_size)
		*vm_size = sizeof(struct kvm_tdx);
}
