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

/*
 * Called after the VM is otherwise initialized, but just before adding it to
 * the vm_list.
 */
int __weak kvm_arch_post_init_vm(struct kvm *kvm)
{
	return 0;
}

static int __hardware_enable(void)
{
	int cpu = raw_smp_processor_id();
	int r;

	WARN_ON_ONCE(preemptible());

	if (cpumask_test_cpu(cpu, &cpus_hardware_enabled))
		return 0;
	r = kvm_arch_hardware_enable();
	if (r)
		pr_warn("kvm: enabling virtualization on CPU%d failed during %pSb\n",
			cpu, __builtin_return_address(0));
	else
		cpumask_set_cpu(cpu, &cpus_hardware_enabled);
	return r;
}

static void hardware_enable(void *arg)
{
	atomic_t *failed = arg;

	if (__hardware_enable())
		atomic_inc(failed);
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
	atomic_t failed = ATOMIC_INIT(0);
	int r = 0;

	if (usage_count != 1)
		return kvm_arch_post_init_vm(kvm);

	on_each_cpu(hardware_enable, &failed, 1);

	if (atomic_read(&failed)) {
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

static void check_processor_compat(void *rtn)
{
	*(int *)rtn = kvm_arch_check_processor_compat();
}

int __weak kvm_arch_check_processor_compat_all(void)
{
	int cpu;
	int r;

	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, check_processor_compat, &r, 1);
		if (r < 0)
			return r;
	}
	return 0;
}

int __weak kvm_arch_online_cpu(unsigned int cpu, int usage_count)
{
	int ret;

	ret = kvm_arch_check_processor_compat();
	if (ret)
		return ret;

	if (!usage_count)
		return 0;

	/*
	 * arch callback kvm_arch_hardware_enable() assumes that
	 * preemption is disabled for historical reason.  Disable
	 * preemption until all arch callbacks are fixed.
	 */
	preempt_disable();
	/*
	 * Abort the CPU online process if hardware virtualization cannot
	 * be enabled. Otherwise running VMs would encounter unrecoverable
	 * errors when scheduled to this CPU.
	 */
	ret = __hardware_enable();
	preempt_enable();

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
		(void)__hardware_enable();
}
