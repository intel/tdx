// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "x86.h"
#include "tdx.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/*
 * Key id globally used by TDX module: TDX module maps TDR with this TDX global
 * key id.  TDR includes key id assigned to the TD.  Then TDX module maps other
 * TD-related pages with the assigned key id.  TDR requires this TDX global key
 * id for cache flush unlike other TD-related pages.
 */
/* TDX KeyID pool */
static DEFINE_IDA(tdx_guest_keyid_pool);

static int __used tdx_guest_keyid_alloc(void)
{
	if (WARN_ON_ONCE(!tdx_guest_keyid_start || !tdx_nr_guest_keyids))
		return -EINVAL;

	return ida_alloc_range(&tdx_guest_keyid_pool, tdx_guest_keyid_start,
			       tdx_guest_keyid_start + tdx_nr_guest_keyids - 1,
			       GFP_KERNEL);
}

static void __used tdx_guest_keyid_free(int keyid)
{
	if (WARN_ON_ONCE(keyid < tdx_guest_keyid_start ||
			 keyid > tdx_guest_keyid_start + tdx_nr_guest_keyids - 1))
		return;

	ida_free(&tdx_guest_keyid_pool, keyid);
}

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

bool tdx_is_vm_type_supported(unsigned long type)
{
	/* enable_tdx check is done by the caller. */
	return type == KVM_X86_TDX_VM;
}

struct tdx_enabled {
	cpumask_var_t enabled;
	atomic_t err;
};

static void __init tdx_on(void *_enable)
{
	struct tdx_enabled *enable = _enable;
	int r;

	r = vmx_hardware_enable();
	if (!r) {
		cpumask_set_cpu(smp_processor_id(), enable->enabled);
		r = tdx_cpu_enable();
	}
	if (r)
		atomic_set(&enable->err, r);
}

static void __init vmx_off(void *_enabled)
{
	cpumask_var_t *enabled = (cpumask_var_t *)_enabled;

	if (cpumask_test_cpu(smp_processor_id(), *enabled))
		vmx_hardware_disable();
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	struct tdx_enabled enable = {
		.err = ATOMIC_INIT(0),
	};
	int r = 0;

	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	if (!zalloc_cpumask_var(&enable.enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	on_each_cpu(tdx_on, &enable, true); /* TDX requires vmxon. */
	r = atomic_read(&enable.err);
	if (!r)
		r = tdx_module_setup();
	else
		r = -EIO;
	on_each_cpu(vmx_off, &enable.enabled, true);
	cpus_read_unlock();
	free_cpumask_var(enable.enabled);

out:
	return r;
}
