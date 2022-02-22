// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "x86.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

static int __init tdx_module_setup(void)
{
	int ret;

	ret = tdx_enable();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		return ret;
	}

	pr_info("TDX is supported.\n");
	return 0;
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
