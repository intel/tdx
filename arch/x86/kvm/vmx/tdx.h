/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_H
#define __KVM_X86_TDX_H

#include <linux/list.h>
#include <linux/kvm_host.h>

#include "tdx_errno.h"
#include "tdx_arch.h"
#include "tdx_ops.h"

int tdx_enable(void);

#ifdef CONFIG_INTEL_TDX_HOST
int tdx_module_setup(void);

#define TDX_MAX_NR_CPUID_CONFIGS					\
	((sizeof(struct tdsysinfo_struct) -				\
		offsetof(struct tdsysinfo_struct, cpuid_configs))	\
		/ sizeof(struct tdx_cpuid_config))

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

#else
static inline int tdx_module_setup(void) { return -ENODEV; };
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_X86_TDX_H */
