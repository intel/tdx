// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) support
 */

#define pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/tdx.h>
#include "tdx.h"

static u32 tdx_global_keyid __ro_after_init;
static u32 tdx_guest_keyid_start __ro_after_init;
static u32 tdx_nr_guest_keyids __ro_after_init;

static enum tdx_module_status_t tdx_module_status;
/* Prevent concurrent attempts on TDX module initialization */
static DEFINE_MUTEX(tdx_module_lock);

/* TDX-runnable cpus.  Protected by cpu_hotplug_lock. */
static cpumask_t __cpu_tdx_mask;
static cpumask_t *cpu_tdx_mask = &__cpu_tdx_mask;

/*
 * Use tdx_global_keyid to indicate that TDX is uninitialized.
 * This is used in TDX initialization error paths to take it from
 * initialized -> uninitialized.
 */
static void __init clear_tdx(void)
{
	tdx_global_keyid = 0;
}

static int __init record_keyid_partitioning(u32 *tdx_keyid_start,
					    u32 *nr_tdx_keyids)
{
	u32 _nr_mktme_keyids, _tdx_keyid_start, _nr_tdx_keyids;
	int ret;

	/*
	 * IA32_MKTME_KEYID_PARTIONING:
	 *   Bit [31:0]:	Number of MKTME KeyIDs.
	 *   Bit [63:32]:	Number of TDX private KeyIDs.
	 */
	ret = rdmsr_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &_nr_mktme_keyids,
			&_nr_tdx_keyids);
	if (ret)
		return -ENODEV;

	if (!_nr_tdx_keyids)
		return -ENODEV;

	/* TDX KeyIDs start after the last MKTME KeyID. */
	_tdx_keyid_start = _nr_mktme_keyids + 1;

	*tdx_keyid_start = _tdx_keyid_start;
	*nr_tdx_keyids = _nr_tdx_keyids;

	return 0;
}

static int __init tdx_init(void)
{
	u32 tdx_keyid_start, nr_tdx_keyids;
	int err;

	err = record_keyid_partitioning(&tdx_keyid_start, &nr_tdx_keyids);
	if (err)
		return err;

	pr_info("BIOS enabled: private KeyID range [%u, %u)\n",
			tdx_keyid_start, tdx_keyid_start + nr_tdx_keyids);

	/*
	 * The TDX module itself requires one 'TDX global KeyID' to
	 * protect its metadata.  Just use the first one.
	 */
	tdx_global_keyid = tdx_keyid_start;
	tdx_keyid_start++;
	nr_tdx_keyids--;

	/*
	 * If there's no more TDX KeyID left, KVM won't be able to run
	 * any TDX guest.  Disable TDX in this case as initializing the
	 * TDX module alone is meaningless.
	 */
	if (!nr_tdx_keyids) {
		pr_info("initialization failed: too few private KeyIDs available.\n");
		goto no_tdx;
	}

	tdx_guest_keyid_start = tdx_keyid_start;
	tdx_nr_guest_keyids = nr_tdx_keyids;

	return 0;
no_tdx:
	clear_tdx();
	return -ENODEV;
}
early_initcall(tdx_init);

/* Return whether the BIOS has enabled TDX */
bool platform_tdx_enabled(void)
{
	return !!tdx_global_keyid;
}

/*
 * Wrapper of __seamcall() to convert SEAMCALL leaf function error code
 * to kernel error code.  @seamcall_ret and @out contain the SEAMCALL
 * leaf function return code and the additional output respectively if
 * not NULL.
 */
static int __always_unused seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
				    u64 *seamcall_ret,
				    struct tdx_module_output *out)
{
	int cpu, ret = 0;
	u64 sret;

	/* Need a stable CPU id for printing error message */
	cpu = get_cpu();

	sret = __seamcall(fn, rcx, rdx, r8, r9, out);

	/* Save SEAMCALL return code if the caller wants it */
	if (seamcall_ret)
		*seamcall_ret = sret;

	/* SEAMCALL was successful */
	if (!sret)
		goto out;

	switch (sret) {
	case TDX_SEAMCALL_GP:
		/*
		 * tdx_enable() has already checked that BIOS has
		 * enabled TDX at the very beginning before going
		 * forward.  It's likely a firmware bug if the
		 * SEAMCALL still caused #GP.
		 */
		pr_err_once("[firmware bug]: TDX is not enabled by BIOS.\n");
		ret = -ENODEV;
		break;
	case TDX_SEAMCALL_VMFAILINVALID:
		pr_err_once("TDX module is not loaded.\n");
		ret = -ENODEV;
		break;
	case TDX_SEAMCALL_UD:
		pr_err_once("SEAMCALL failed: CPU %d is not in VMX operation.\n",
				cpu);
		ret = -EINVAL;
		break;
	default:
		pr_err_once("SEAMCALL failed: CPU %d: leaf %llu, error 0x%llx.\n",
				cpu, fn, sret);
		if (out)
			pr_err_once("additional output: rcx 0x%llx, rdx 0x%llx, r8 0x%llx, r9 0x%llx, r10 0x%llx, r11 0x%llx.\n",
					out->rcx, out->rdx, out->r8,
					out->r9, out->r10, out->r11);
		ret = -EIO;
	}
out:
	put_cpu();
	return ret;
}

/*
 * Call @func on all online cpus one by one but skip those cpus
 * when @skip_func is valid and returns true for them.
 */
static int tdx_on_each_cpu_cond(int (*func)(void *), void *func_data,
				bool (*skip_func)(int cpu, void *),
				void *skip_data)
{
	int cpu;

	for_each_online_cpu(cpu) {
		int ret;

		if (skip_func && skip_func(cpu, skip_data))
			continue;

		/*
		 * SEAMCALL can be time consuming.  Call the @func on
		 * remote cpu via smp_call_on_cpu() instead of
		 * smp_call_function_single() to avoid busy waiting.
		 */
		ret = smp_call_on_cpu(cpu, func, func_data, true);
		if (ret)
			return ret;
	}

	return 0;
}

static int seamcall_lp_init(void)
{
	/* All '0's are just unused parameters */
	return seamcall(TDH_SYS_LP_INIT, 0, 0, 0, 0, NULL, NULL);
}

static int smp_func_module_lp_init(void *data)
{
	int ret, cpu = smp_processor_id();

	ret = seamcall_lp_init();
	if (!ret)
		cpumask_set_cpu(cpu, cpu_tdx_mask);

	return ret;
}

static bool skip_func_module_lp_init_done(int cpu, void *data)
{
	return cpumask_test_cpu(cpu, cpu_tdx_mask);
}

static int module_lp_init_online_cpus(void)
{
	return tdx_on_each_cpu_cond(smp_func_module_lp_init, NULL,
			skip_func_module_lp_init_done, NULL);
}

static int init_tdx_module(void)
{
	int ret;

	/*
	 * TDX module global initialization.  All '0's are just
	 * unused parameters.
	 */
	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL, NULL);
	if (ret)
		return ret;

	/*
	 * TDX module per-cpu initialization SEAMCALL must be done on
	 * one cpu before any other SEAMCALLs can be made on that cpu,
	 * including those involved in further steps to initialize the
	 * TDX module.
	 *
	 * To make sure further SEAMCALLs can be done successfully w/o
	 * having to consider preemption, disable CPU hotplug during
	 * rest of module initialization and do per-cpu initialization
	 * for all online cpus.
	 */
	cpus_read_lock();

	ret = module_lp_init_online_cpus();
	if (ret)
		goto out;

	/*
	 * TODO:
	 *
	 *  - Get TDX module information and TDX-capable memory regions.
	 *  - Build the list of TDX-usable memory regions.
	 *  - Construct a list of "TD Memory Regions" (TDMRs) to cover
	 *    all TDX-usable memory regions.
	 *  - Configure the TDMRs and the global KeyID to the TDX module.
	 *  - Configure the global KeyID on all packages.
	 *  - Initialize all TDMRs.
	 *
	 *  Return error before all steps are done.
	 */
	ret = -EINVAL;
out:
	/*
	 * Clear @cpu_tdx_mask if module initialization fails before
	 * CPU hotplug is re-enabled.  tdx_cpu_online() uses it to check
	 * whether the initialization has been successful or not.
	 */
	if (ret)
		cpumask_clear(cpu_tdx_mask);
	cpus_read_unlock();
	return ret;
}

static int __tdx_enable(void)
{
	int ret;

	ret = init_tdx_module();
	if (ret) {
		pr_err("initialization failed (%d)\n", ret);
		tdx_module_status = TDX_MODULE_ERROR;
		/*
		 * Just return one universal error code.
		 * For now the caller cannot recover anyway.
		 */
		return -EINVAL;
	}

	pr_info("TDX module initialized.\n");
	tdx_module_status = TDX_MODULE_INITIALIZED;

	return 0;
}

/*
 * Disable TDX module after it has been initialized successfully.
 */
static void disable_tdx_module(void)
{
	/*
	 * TODO: module clean up in reverse to steps in
	 * init_tdx_module().  Remove this comment after
	 * all steps are done.
	 */
	cpumask_clear(cpu_tdx_mask);
}

static int tdx_module_init_online_cpus(void)
{
	int ret;

	/*
	 * Make sure no cpu can become online to prevent
	 * race against tdx_cpu_online().
	 */
	cpus_read_lock();

	/*
	 * Do per-cpu initialization for any new online cpus.
	 * If any fails, disable TDX.
	 */
	ret = module_lp_init_online_cpus();
	if (ret)
		disable_tdx_module();

	cpus_read_unlock();

	return ret;

}
static int __tdx_enable_online_cpus(void)
{
	if (tdx_module_init_online_cpus()) {
		/*
		 * SEAMCALL failure has already printed
		 * meaningful error message.
		 */
		tdx_module_status = TDX_MODULE_ERROR;

		/*
		 * Just return one universal error code.
		 * For now the caller cannot recover anyway.
		 */
		return -EINVAL;
	}

	return 0;
}

/**
 * tdx_enable - Enable TDX to be ready to run TDX guests
 *
 * Initialize the TDX module to enable TDX.  After this function, the TDX
 * module is ready to create and run TDX guests on all online cpus.
 *
 * This function internally calls cpus_read_lock()/unlock() to prevent
 * any cpu from going online and offline.
 *
 * This function assumes all online cpus are already in VMX operation.
 *
 * This function can be called in parallel by multiple callers.
 *
 * Return 0 if TDX is enabled successfully, otherwise error.
 */
int tdx_enable(void)
{
	int ret;

	if (!platform_tdx_enabled()) {
		pr_err_once("initialization failed: TDX is disabled.\n");
		return -EINVAL;
	}

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNKNOWN:
		ret = __tdx_enable();
		break;
	case TDX_MODULE_INITIALIZED:
		/*
		 * The previous call of __tdx_enable() may only have
		 * initialized part of present cpus during module
		 * initialization, and new cpus may have become online
		 * since then.
		 *
		 * To make sure all online cpus are TDX-runnable, always
		 * do per-cpu initialization for all online cpus here
		 * even the module has been initialized.
		 */
		ret = __tdx_enable_online_cpus();
		break;
	default:
		/* Failed to initialize in the previous attempts */
		ret = -EINVAL;
		break;
	}

	mutex_unlock(&tdx_module_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tdx_enable);

/**
 * tdx_cpu_online - Enable TDX on a hotplugged local cpu
 *
 * @cpu: the cpu to be brought up.
 *
 * Do TDX module per-cpu initialization for a hotplugged cpu to make
 * it TDX-runnable.  All online cpus are initialized during module
 * initialization.
 *
 * This function must be called from CPU hotplug callback which holds
 * write lock of cpu_hotplug_lock.
 *
 * This function assumes local cpu is already in VMX operation.
 */
int tdx_cpu_online(unsigned int cpu)
{
	int ret;

	/*
	 * @cpu_tdx_mask is updated in tdx_enable() and is protected
	 * by cpus_read_lock()/unlock().  If it is empty, TDX module
	 * either hasn't been initialized, or TDX didn't get enabled
	 * successfully.
	 *
	 * In either case, do nothing but return success.
	 */
	if (cpumask_empty(cpu_tdx_mask))
		return 0;

	WARN_ON_ONCE(cpu != smp_processor_id());

	/* Already done */
	if (cpumask_test_cpu(cpu, cpu_tdx_mask))
		return 0;

	ret = seamcall_lp_init();
	if (!ret)
		cpumask_set_cpu(cpu, cpu_tdx_mask);

	return ret;
}
EXPORT_SYMBOL_GPL(tdx_cpu_online);
