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

	pr_info("TDX is supported.\n");
	return 0;
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	int r = 0;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	r = kvm_hardware_enable_all_nolock();
	if (!r) {
		r = tdx_module_setup();
		kvm_hardware_disable_all_nolock();
	}
	cpus_read_unlock();

	return r;
}
