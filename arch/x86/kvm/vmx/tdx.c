// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "x86.h"
#include "tdx.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define TDX_MAX_NR_CPUID_CONFIGS					\
	((TDSYSINFO_STRUCT_SIZE -					\
		offsetof(struct tdsysinfo_struct, cpuid_configs))	\
		/ sizeof(struct tdx_cpuid_config))

int tdx_hardware_enable(void)
{
	return tdx_cpu_enable();
}

static int __init tdx_module_setup(void)
{
	const struct tdsysinfo_struct *tdsysinfo;
	int ret = 0;

	BUILD_BUG_ON(sizeof(*tdsysinfo) > TDSYSINFO_STRUCT_SIZE);
	BUILD_BUG_ON(TDX_MAX_NR_CPUID_CONFIGS != 37);

	ret = tdx_enable();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		return ret;
	}

	/* Sanitary check just in case. */
	tdsysinfo = tdx_get_sysinfo();
	WARN_ON(tdsysinfo->num_cpuid_config > TDX_MAX_NR_CPUID_CONFIGS);

	pr_info("TDX is supported.\n");
	return 0;
}

bool tdx_is_vm_type_supported(unsigned long type)
{
	/* enable_tdx check is done by the caller. */
	return type == KVM_X86_PROTECTED_VM;
}

static int __init tdx_cpu_enable_cpu(void *unused)
{
	return tdx_cpu_enable();
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int r;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	/* TDX requires VMX. */
	r = vmxon_all();
	if (!r) {
		int cpu;

		/*
		 * Because tdx_cpu_enabel() acquire spin locks, on_each_cpu()
		 * can't be used.
		 */
		for_each_online_cpu(cpu) {
			if (smp_call_on_cpu(cpu, tdx_cpu_enable_cpu, NULL, false))
				r = -EIO;
		}
		if (!r)
			r = tdx_module_setup();
	}
	vmxoff_all();
	cpus_read_unlock();

	return r;
}
