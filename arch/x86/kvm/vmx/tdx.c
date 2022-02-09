// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "x86.h"
#include "tdx.h"

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

	return 0;
}

static void __init vmx_tdx_on(void *info)
{
	atomic_t *err = info;
	int r;

	r = vmx_hardware_enable();
	if (!r)
		r = tdx_cpu_enable();
	if (r)
		atomic_set(err, r);
}

static void __init vmx_off(void *unused)
{
	vmx_hardware_disable();
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	atomic_t err = ATOMIC_INIT(0);
	int r = 0;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	on_each_cpu(vmx_tdx_on, &err, true);	/* TDX requires vmxon. */
	r = atomic_read(&err);
	if (!r)
		r = tdx_module_setup();
	on_each_cpu(vmx_off, NULL, true);
	cpus_read_unlock();

	return r;
}
