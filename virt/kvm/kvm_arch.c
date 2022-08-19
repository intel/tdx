// SPDX-License-Identifier: GPL-2.0-only
/*
 * kvm_arch.c: kvm default arch hooks for hardware enabling/disabling
 * Copyright (c) 2022 Intel Corporation.
 *
 * Author:
 *   Isaku Yamahata <isaku.yamahata@intel.com>
 *                  <isaku.yamahata@gmail.com>
 *
 * TODO: Delete this file once the conversion of all KVM arch is done.
 */

#include <linux/kvm_host.h>

static cpumask_t cpus_hardware_enabled = CPU_MASK_NONE;
static atomic_t hardware_enable_failed;

/*
 * Called after the VM is otherwise initialized, but just before adding it to
 * the vm_list.
 */
int __weak kvm_arch_post_init_vm(struct kvm *kvm)
{
	return 0;
}

static void hardware_enable(void *junk)
{
	int cpu = raw_smp_processor_id();
	int r;

	WARN_ON_ONCE(preemptible());

	if (cpumask_test_cpu(cpu, &cpus_hardware_enabled))
		return;

	cpumask_set_cpu(cpu, &cpus_hardware_enabled);

	r = kvm_arch_hardware_enable();

	if (r) {
		cpumask_clear_cpu(cpu, &cpus_hardware_enabled);
		atomic_inc(&hardware_enable_failed);
		pr_warn("kvm: enabling virtualization on CPU%d failed during %pSb\n",
			cpu, __builtin_return_address(0));
	}
}

static void hardware_disable(void *junk)
{
	int cpu = raw_smp_processor_id();

	WARN_ON_ONCE(preemptible());

	if (!cpumask_test_cpu(cpu, &cpus_hardware_enabled))
		return;
	cpumask_clear_cpu(cpu, &cpus_hardware_enabled);
	kvm_arch_hardware_disable();
}

/*
 * Called after the VM is otherwise initialized, but just before adding it to
 * the vm_list.
 */
int __weak kvm_arch_add_vm(struct kvm *kvm, int usage_count)
{
	int r = 0;

	if (usage_count != 1)
		return kvm_arch_post_init_vm(kvm);

	atomic_set(&hardware_enable_failed, 0);
	on_each_cpu(hardware_enable, NULL, 1);

	if (atomic_read(&hardware_enable_failed)) {
		r = -EBUSY;
		goto err;
	}

	r = kvm_arch_post_init_vm(kvm);
err:
	if (r)
		on_each_cpu(hardware_disable, NULL, 1);
	return r;
}

int __weak kvm_arch_del_vm(int usage_count)
{
	if (usage_count)
		return 0;

	on_each_cpu(hardware_disable, NULL, 1);
	return 0;
}

int __weak kvm_arch_online_cpu(unsigned int cpu, int usage_count)
{
	int ret = 0;

	ret = kvm_arch_check_processor_compat();
	if (ret)
		return ret;

	/*
	 * Abort the CPU online process if hardware virtualization cannot
	 * be enabled. Otherwise running VMs would encounter unrecoverable
	 * errors when scheduled to this CPU.
	 */
	if (usage_count) {
		WARN_ON_ONCE(atomic_read(&hardware_enable_failed));

		/*
		 * arch callback kvm_arch_hardware_eanble() assumes that
		 * preemption is disabled for historical reason.  Disable
		 * preemption until all arch callbacks are fixed.
		 */
		preempt_disable();
		hardware_enable(NULL);
		preempt_enable();
		if (atomic_read(&hardware_enable_failed)) {
			atomic_set(&hardware_enable_failed, 0);
			ret = -EIO;
		}
	}
	return ret;
}

int __weak kvm_arch_offline_cpu(unsigned int cpu, int usage_count)
{
	if (usage_count) {
		/*
		 * arch callback kvm_arch_hardware_disable() assumes that
		 * preemption is disabled for historical reason.  Disable
		 * preemption until all arch callbacks are fixed.
		 */
		preempt_disable();
		hardware_disable(NULL);
		preempt_enable();
	}
	return 0;
}

int __weak kvm_arch_reboot(int val)
{
	on_each_cpu(hardware_disable, NULL, 1);
	return NOTIFY_OK;
}

int __weak kvm_arch_suspend(int usage_count)
{
	if (usage_count)
		/*
		 * Because kvm_suspend() is called with interrupt disabled,  no
		 * need to disable preemption.
		 */
		hardware_disable(NULL);
	return 0;
}

void __weak kvm_arch_resume(int usage_count)
{
	if (usage_count)
		hardware_enable(NULL);
}
