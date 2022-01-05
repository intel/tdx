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

static enum tdx_module_status_t tdx_module_status;

/* Prevent concurrent attempts on TDX detection and initialization */
static DEFINE_MUTEX(tdx_module_lock);

/*
 * Intel Trusted Domain CPU Architecture Extension spec:
 *
 * IA32_MKTME_KEYID_PARTIONING:
 *
 *   Bit [31:0]: number of MKTME KeyIDs.
 *   Bit [63:32]: number of TDX private KeyIDs.
 *
 * TDX private KeyIDs start with the last MKTME KeyID.
 */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

#define TDX_KEYID_START(_keyid_part)	\
		((u32)(((_keyid_part) & 0xffffffffull) + 1))
#define TDX_KEYID_NUM(_keyid_part)	((u32)((_keyid_part) >> 32))

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

	/* If MSR value is 0, TDX is not enabled by BIOS. */
	if (!keyid_part)
		return;

	tdx_keyid_num = TDX_KEYID_NUM(keyid_part);
	if (!tdx_keyid_num)
		return;

	tdx_keyid_start = TDX_KEYID_START(keyid_part);
}

static void detect_tdx_keyids_ap(struct cpuinfo_x86 *c)
{
	u64 keyid_part;

	/*
	 * Don't bother to detect this AP if TDX KeyIDs are
	 * not detected or cleared after earlier detections.
	 */
	if (!tdx_keyid_num)
		return;
	/*
	 * Check potential BIOS bug that TDX KeyIDs are not
	 * configured consistently among packages.
	 */
	rdmsrl(MSR_IA32_MKTME_KEYID_PARTITIONING, keyid_part);

	if ((tdx_keyid_start == TDX_KEYID_START(keyid_part)) &&
			(tdx_keyid_num == TDX_KEYID_NUM(keyid_part)))
		return;

	pr_err("Inconsistent TDX KeyID configuration among packages by BIOS\n");
	tdx_keyid_start = 0;
	tdx_keyid_num = 0;
}

void detect_tdx_keyids(struct cpuinfo_x86 *c)
{
	if (c == &boot_cpu_data)
		detect_tdx_keyids_bsp(c);
	else
		detect_tdx_keyids_ap(c);
}

/*
 * Call the requested function on all online cpus concurrently.
 * Any SEAMCALL invoked in the requested function must allow
 * concurrent execution.
 *
 * Return error if requested function fails on any cpu.
 */
static int tdx_on_each_cpu(smp_call_func_t func)
{
	atomic_t err;

	atomic_set(&err, 0);
	on_each_cpu(func, &err, 1);

	/* Don't care about exactly what error happened on which cpu */
	return atomic_read(&err) ? -EFAULT : 0;
}

static int init_tdx_module_global(void)
{
	/*
	 * Platform global initialization requires calling
	 * TDH.SYS.INIT on any cpu once.
	 */
	return tdh_sys_init();
}

/* Initialize the TDX module. */
static int init_tdx_module(void)
{
	int ret;

	/* Platform global initialization */
	ret = init_tdx_module_global();
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

	if (tdh_sys_lp_shutdown())
		atomic_set(err, -1);
}

/* Shut down the TDX module */
static void shutdown_tdx_module(void)
{
	tdx_on_each_cpu(smp_call_tdx_cpu_shutdown);

	tdx_module_status = TDX_MODULE_SHUTDOWN;
}

static int __detect_tdx(void)
{
	/*
	 * TDX requires at least two KeyIDs: one global KeyID to protect
	 * the metadata of the TDX module and one or more KeyIDs to
	 * protect VMs.  It's pointless to report TDX module as present
	 * if this condition is not met.
	 */
	if (!(tdx_keyid_num > 1))
		goto no_tdx_module;

	/* P-SEAMLDR reports the presence of the TDX module */
	if (detect_p_seamldr() || !tdx_module_ready())
		goto no_tdx_module;

	tdx_module_status = TDX_MODULE_LOADED;
	return 0;

no_tdx_module:
	tdx_module_status = TDX_MODULE_NONE;
	return -ENODEV;
}

static int __init_tdx(void)
{
	int ret;

	/*
	 * Logical-cpu scope initialization requires calling one SEAMCALL
	 * on all logical cpus reported by BIOS, otherwise the SEAMCALL
	 * of the next step of the initialization fails.  Shutting down
	 * TDX module also has such requirement.  Further more,
	 * configuring the key of the global KeyID requires calling one
	 * SEAMCALL on at least one cpu for each package.
	 *
	 * For simplicity, instead of disabling CPU hotplug separately
	 * for them to prevent any cpu going offline, disable CPU hotplug
	 * during the entire TDX module initialization.
	 *
	 * Initializing TDX module could be time consuming, therefore use
	 * cpu_hotplug_disable() instead of cpus_read_lock(), so that
	 * another thread to run cpu hotplug could return -EBUSY
	 * immediately rather than busy waiting.
	 *
	 * And assume all cpus reported by BIOS are online and depend on
	 * the SEAMCALL failure to detect that this condition doesn't
	 * meet.  Ideally a pre-check could be done before starting the
	 * initialization, and return error early:
	 *
	 *	if (cpu_online_map != bios_enabled_cpu_map)
	 *		return -EFAULT;
	 *
	 * However there is no existing variable (num_processors,
	 * disabled_cpus, total_cpus, etc.) or bitmap (present, possbile,
	 * online, etc.) which describes BIOS-enabled CPUs, while
	 * cpu_online_maps can be easily changed due to various boot
	 * options and cpu hotplug events.
	 */
	cpu_hotplug_disable();

	ret = init_tdx_module();

	/*
	 * Turn off the TDX module in case of any error in the
	 * initialization process.  It's pointless to leave the
	 * module in an intermediate state.
	 */
	if (ret)
		shutdown_tdx_module();

	cpu_hotplug_enable();
	return ret;
}

/**
 * detect_tdx - Detect whether the TDX module has been loaded
 *
 * Detect whether the TDX module has been loaded and ready for
 * initialization.  This function can be called in parallel
 * by multiple callers.
 *
 * Call this function when the local cpu is already in VMX operation.
 *
 * Return: 0 if TDX module has been loaded, otherwise -ENODEV.
 */
int detect_tdx(void)
{
	int ret;

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNKNOWN:
		ret = __detect_tdx();
		break;
	case TDX_MODULE_NONE:
	case TDX_MODULE_SHUTDOWN:
		ret = -ENODEV;
		break;
	case TDX_MODULE_LOADED:
	case TDX_MODULE_INITIALIZED:
		ret = 0;
		break;
	default:
		WARN_ON(1);
		ret = -ENODEV;
	}

	mutex_unlock(&tdx_module_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(detect_tdx);

/**
 * init_tdx - Initialize the TDX module
 *
 * Initialize the TDX module to make it ready to run TD guests.
 * This function can be called in parallel by multiple callers.
 *
 * Call this function when all cpus are online and in VMX operation.
 * CPU hotplug is also temporarily disabled in this function.
 *
 * Return:
 *
 * * -0: The TDX module has been successfully initialized.
 * * -ENODEV: The TDX module is not loaded.
 * * -EFAULT: Fatal error during TDX module initialization.
 */
int init_tdx(void)
{
	int ret;

	mutex_lock(&tdx_module_lock);

	/* Detect the TDX module if it's not done yet */
	if (tdx_module_status == TDX_MODULE_UNKNOWN)
		__detect_tdx();

	switch (tdx_module_status) {
	case TDX_MODULE_NONE:
		ret = -ENODEV;
		break;
	case TDX_MODULE_LOADED:
		ret = __init_tdx();
		break;
	case TDX_MODULE_INITIALIZED:
		ret = 0;
		break;
	default:
		ret = -EFAULT;
		break;
	}
	mutex_unlock(&tdx_module_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(init_tdx);
