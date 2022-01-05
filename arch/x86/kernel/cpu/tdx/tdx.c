// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) host kernel support
 */

#define	pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/cpu.h>
#include <linux/bug.h>
#include <asm/cpufeatures.h>
#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/tdx_host.h>
#include <asm/seam.h>
#include "p-seamldr.h"
#include "tdx_seamcall.h"

/*
 * SEAMCALL failure with unexpected error code is likely a kernel bug.
 * WARN() in this case.
 */
#define SEAMCALL_ERR_WARN(_leaf_name, _ret)	\
	WARN(1, _leaf_name " failed: 0x%llx\n", _ret)
/*
 * TDX module status during initialization
 */
enum tdx_module_status_t {
	/* TDX module status is unknown */
	TDX_MODULE_UNKNOWN,
	/* TDX module is not loaded */
	TDX_MODULE_NONE,
	/* TDX module is loaded, but not initialized */
	TDX_MODULE_LOADED,
	/* TDX module is fully initialized */
	TDX_MODULE_INITIALIZED,
	/* TDX module is shutdown due to error during initialization */
	TDX_MODULE_SHUTDOWN,
};

/* TDX module status */
static enum tdx_module_status_t tdx_module_status;
/*
 * Mutex to prevent concurrent access to TDX module status
 * during TDX module detection and initialization.
 */
static DEFINE_MUTEX(tdx_module_lock);

#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

static u64 keyid_partitioning_info;
static u32 tdx_keyid_start;
static u32 tdx_keyid_num;

static void detect_tdx_keyids_bsp(struct cpuinfo_x86 *c)
{
	u64 keyid_part;

	/* TDX is built on MKTME, which is based on TME */
	if (!boot_cpu_has(X86_FEATURE_TME))
		return;

	if (rdmsrl_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &keyid_part))
		return;

	/*
	 * Intel Trusted Domain CPU Architecture Extension spec:
	 *
	 * IA32_MKTME_KEYID_PART:
	 *
	 *   Bit [31:0]: NUM_MKTME_KIDS.
	 *   Bit [63:32]: NUM_TDX_PRIV_KIDS.  TDX KeyIDs span the range
	 *		  [NUM_MKTME_KIDS+1, NUM_MKTME_KIDS+NUM_TDX_PRIV_KIDS]
	 *
	 * If MSR value is 0, TDX is not enabled by BIOS.
	 */
	if (!keyid_part)
		return;

	tdx_keyid_start = (keyid_part & 0xfffffffful) + 1;
	tdx_keyid_num = (u32)(keyid_part >> 32);
	keyid_partitioning_info = keyid_part;
}

static void detect_tdx_keyids_ap(struct cpuinfo_x86 *c)
{
	u64 keyid_part;

	/*
	 * Don't bother to detect this AP if TDX KeyIDs are
	 * not detected or cleared after earlier detections.
	 */
	if (!keyid_partitioning_info)
		return;
	/*
	 * Check potential BIOS bug that TDX KeyIDs are not
	 * configured consistently among packages by BIOS.
	 */
	rdmsrl(MSR_IA32_MKTME_KEYID_PARTITIONING, keyid_part);

	if (keyid_part != keyid_partitioning_info) {
		pr_err("Inconsistent TDX KeyID configuration among packages by BIOS\n");
		keyid_partitioning_info = 0;
		tdx_keyid_start = 0;
		tdx_keyid_num = 0;
	}
}

void detect_tdx_keyids(struct cpuinfo_x86 *c)
{
	if (c == &boot_cpu_data)
		detect_tdx_keyids_bsp(c);
	else
		detect_tdx_keyids_ap(c);
}

/*
 * Call specific function on all online cpus concurrently via
 * on_each_cpu().  It is intended to be used to call SEAMCALL,
 * which can run concurrently, on all online cpus.
 */
static int tdx_smp_call_cpus_all(smp_call_func_t func)
{
	atomic_t err;

	atomic_set(&err, 0);
	on_each_cpu(func, &err, 1);

	/* Don't care about exactly what error happened on which cpu */
	return atomic_read(&err) ? -EFAULT : 0;
}

/* Platform level initialization */
static int init_tdx_module_platform(void)
{
	u64 ret;

	/*
	 * Platform level initialization requires calling TDH.SYS.INIT
	 * on any cpu once.
	 */
	ret = tdh_sys_init();
	if (ret) {
		SEAMCALL_ERR_WARN("TDH.SYS.INIT", ret);
		return -EFAULT;
	}

	return 0;
}

/* SMP call function to run TDH.SYS.LP.INIT */
static void smp_call_tdx_cpu_init(void *data)
{
	atomic_t *err = (atomic_t *)err;
	u64 ret;

	ret = tdh_sys_lp_init();
	if (ret) {
		SEAMCALL_ERR_WARN("TDH.SYS.LP.INIT", ret);
		atomic_set(err, -1);
	}
}

/* Logical cpu level initialization on all online cpus. */
static int init_tdx_module_cpus(void)
{
	int ret;

	/*
	 * Logical cpu level initialization requires calling
	 * TDH.SYS.LP.INIT on all cpus reported by BIOS.
	 * Prevent CPU hotplug to prevent any cpu going offline.
	 */
	cpus_read_lock();

	/*
	 * Sanity check whether all cpus are online.  Number of
	 * possible cpus has already been checked earlier against
	 * total_cpus in __detect_tdx() to make sure all cpus are
	 * in cpu_possible_mask.
	 */
	if (num_online_cpus() != num_possible_cpus())
		return -EFAULT;

	ret = tdx_smp_call_cpus_all(smp_call_tdx_cpu_init);

	cpus_read_unlock();

	return ret;
}

/* Initialize TDX module. */
static int init_tdx_module(void)
{
	int ret;

	/* Platform level initialization */
	ret = init_tdx_module_platform();
	if (ret)
		goto out;

	/* Logical cpu level initialization */
	ret = init_tdx_module_cpus();
	if (ret)
		goto out;

	ret = -EFAULT;
out:
	return ret;
}

/* SMP call function to run TDH.SYS.LP.SHUTDOWN */
static void smp_call_tdx_cpu_shutdown(void *data)
{
	atomic_t *err = (atomic_t *)data;
	u64 ret;

	ret = tdh_sys_lp_shutdown();
	if (ret) {
		SEAMCALL_ERR_WARN("TDH.SYS.LP.SHUTDOWN", ret);
		atomic_set(err, -1);
	}
}

/* Shut down TDX module */
static void shutdown_tdx_module(void)
{
	/*
	 * shutdown_tdx_module() is only supposed to be called during
	 * initializing TDX module when fatal error happens.  It's kernel
	 * bug if it is called when TDX module is not loaded, or already
	 * has been shut down.
	 */
	if (WARN_ON((tdx_module_status == TDX_MODULE_NONE ||
			tdx_module_status == TDX_MODULE_SHUTDOWN)))
		return;
	/*
	 * Prevent CPU hotplug during shutting down TDX module since it
	 * requires calling TDH.SYS.LP.SHUTDOWN on all cpus reported by
	 * BIOS.
	 */
	cpus_read_lock();

	/*
	 * TDH.SYS.LP.SHUTDOWN needs to be called on all cpus reported by
	 * BIOS.  If there's any cpu being offline, the SEAMCALL won't be
	 * called on it.  To keep it simple, require all cpus are online.
	 * WARN_ON() and give a message if not.
	 */
	if (WARN_ON(num_online_cpus() != num_possible_cpus()))
		pr_err("Unable to truly shut down TDX module as there are offline cpus.\n");

	/* TDH.SYS.LP.SHUTDOWN can run concurrently on multiple cpus */
	tdx_smp_call_cpus_all(smp_call_tdx_cpu_shutdown);

	cpus_read_unlock();

	tdx_module_status = TDX_MODULE_SHUTDOWN;
}

static int __detect_tdx(void)
{
	/* TDX module has been detected as not loaded */
	if (tdx_module_status == TDX_MODULE_NONE)
		return -ENODEV;

	/* TDX module has been detected as loaded */
	if (tdx_module_status != TDX_MODULE_UNKNOWN)
		return 0;

	if (!seamrr_enabled())
		goto no_tdx_module;

	/*
	 * One step of TDX module initialization requires to reserve
	 * one global KeyID to protect TDX metadata.  If there's only
	 * one KeyID, there will be no available KeyIDs to create any
	 * TD guest.  It's pointless to initialize TDX module in this
	 * case so just don't report TDX module as loaded.
	 */
	if (!(tdx_keyid_num > 1))
		goto no_tdx_module;

	/*
	 * One step of TDX module initialization and shutting down TDX
	 * module require calling SEAMCALL on all logical cpus reported
	 * by BIOS.  If number of possible cpus are limited by kernel
	 * command line (i.e. nr_cpus), it's not possible to initialize
	 * TDX module.  Just don't report TDX module as loaded in this
	 * case.
	 */
	if (total_cpus != num_possible_cpus())
		goto no_tdx_module;

	/* Detect TDX module via detecting P-SEAMLDR */
	if (detect_p_seamldr() || !tdx_module_ready())
		goto no_tdx_module;

	/* TDX module has been detected as loaded */
	tdx_module_status = TDX_MODULE_LOADED;
	return 0;

no_tdx_module:
	tdx_module_status = TDX_MODULE_NONE;
	return -ENODEV;
}

static int __init_tdx(void)
{
	int ret;

	/* Detect TDX module in case it has not been detected */
	__detect_tdx();

	switch (tdx_module_status) {
	case TDX_MODULE_NONE:
		ret = -ENODEV;
		break;
	case TDX_MODULE_LOADED:
		ret = init_tdx_module();
		/*
		 * In case of any fatal error during the initialization
		 * process, put TDX module to shutdown, so that no
		 * further SEAMCALLs can be made on any cpus.  It's
		 * pointless to leave the TDX module in any intermediate
		 * status during the initialization.
		 *
		 * Any error is treated as fatal error for now.
		 */
		if (ret)
			shutdown_tdx_module();
		break;
	case TDX_MODULE_INITIALIZED:
		ret = 0;
		break;
	default:
		ret = -EFAULT;
		break;
	}

	return ret;
}

/**
 * detect_tdx - Detect whether TDX module has been loaded
 *
 * Detect whether TDX module has been loaded and ready for
 * initialization.  This function can be called in parallel
 * by multiple callers.
 *
 * Note: This function must be called when cpu is already in
 * VMX operation (VMXON has been done), otherwise it may cause
 * #UD.
 *
 * Return: 0 if TDX module has been loaded, otherwise -ENODEV.
 */
int detect_tdx(void)
{
	int ret;

	mutex_lock(&tdx_module_lock);
	ret = __detect_tdx();
	mutex_unlock(&tdx_module_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(detect_tdx);

/**
 * init_tdx - Initialize TDX module
 *
 * Initialize TDX module to make it ready to run TD guests.
 * This function can be called in parallel by multiple callers.
 *
 * Note: This function must be called when all online cpus are
 * in VMX operation, otherwise it may cause #UD.
 *
 * Return: 0 if TDX module has been successfully initialized,
 *	   otherwise fatal errors.
 */
int init_tdx(void)
{
	int ret;

	mutex_lock(&tdx_module_lock);
	ret = __init_tdx();
	mutex_unlock(&tdx_module_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(init_tdx);
