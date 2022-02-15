// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2022 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) support
 */

#define pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <asm/cpufeatures.h>
#include <asm/cpufeature.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/smp.h>
#include <asm/tdx.h>
#include <asm/coco.h>
#include "tdx.h"

/*
 * TDX module status during initialization
 */
enum tdx_module_status_t {
	/* TDX module hasn't been detected and initialized */
	TDX_MODULE_UNKNOWN,
	/* TDX module is not loaded */
	TDX_MODULE_NONE,
	/* TDX module is initialized */
	TDX_MODULE_INITIALIZED,
	/* TDX module is shut down due to initialization error */
	TDX_MODULE_SHUTDOWN,
};

static u32 tdx_keyid_start __ro_after_init;
static u32 tdx_keyid_num __ro_after_init;

static enum tdx_module_status_t tdx_module_status;
/* Prevent concurrent attempts on TDX detection and initialization */
static DEFINE_MUTEX(tdx_module_lock);

/* Detect whether CPU supports SEAM */
static int detect_seam(void)
{
	u64 mtrrcap, mask;

	/* SEAMRR is reported via MTRRcap */
	if (!boot_cpu_has(X86_FEATURE_MTRR))
		return -ENODEV;

	rdmsrl(MSR_MTRRcap, mtrrcap);
	if (!(mtrrcap & MTRR_CAP_SEAMRR))
		return -ENODEV;

	/* The MASK MSR reports whether SEAMRR is enabled */
	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, mask);
	if ((mask & SEAMRR_ENABLED_BITS) != SEAMRR_ENABLED_BITS)
		return -ENODEV;

	pr_info("SEAMRR enabled.\n");
	return 0;
}

static int detect_tdx_keyids(void)
{
	u64 keyid_part;

	rdmsrl(MSR_IA32_MKTME_KEYID_PARTITIONING, keyid_part);

	tdx_keyid_num = TDX_KEYID_NUM(keyid_part);
	tdx_keyid_start = TDX_KEYID_START(keyid_part);

	pr_info("TDX private KeyID range: [%u, %u).\n",
			tdx_keyid_start, tdx_keyid_start + tdx_keyid_num);

	/*
	 * TDX guarantees at least two TDX KeyIDs are configured by
	 * BIOS, otherwise SEAMRR is disabled.  Invalid TDX private
	 * range means kernel bug (TDX is broken).
	 */
	if (WARN_ON(!tdx_keyid_start || tdx_keyid_num < 2)) {
		tdx_keyid_start = tdx_keyid_num = 0;
		return -EINVAL;
	}

	return 0;
}

/*
 * Detect TDX via detecting SEAMRR during kernel boot.
 *
 * To enable TDX, BIOS must configure SEAMRR consistently across all
 * CPU cores.  TDX doesn't trust BIOS.  Instead, MCHECK verifies all
 * configurations from BIOS are correct, and if not, it disables TDX
 * (SEAMRR is disabled on all cores).  This means detecting SEAMRR on
 * BSP is enough to determine whether TDX has been enabled by BIOS.
 */
static int __init tdx_early_detect(void)
{
	int ret;

	ret = detect_seam();
	if (ret)
		return ret;

	/*
	 * TDX private KeyIDs is only accessible by SEAM software.
	 * Only detect TDX KeyIDs when SEAMRR is enabled.
	 */
	ret = detect_tdx_keyids();
	if (ret)
		return ret;

	/* Set TDX enabled platform as confidential computing platform */
	cc_set_vendor(CC_VENDOR_INTEL);

	pr_info("TDX enabled by BIOS.\n");
	return 0;
}
early_initcall(tdx_early_detect);

/*
 * Data structure to make SEAMCALL on multiple CPUs concurrently.
 * @err is set to -EFAULT when SEAMCALL fails on any cpu.
 */
struct seamcall_ctx {
	u64 fn;
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	atomic_t err;
};

/*
 * Wrapper of __seamcall().  It additionally prints out the error
 * informationi if __seamcall() fails normally.  It is useful during
 * the module initialization by providing more information to the user.
 */
static u64 seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		    struct tdx_module_output *out)
{
	u64 ret;

	ret = __seamcall(fn, rcx, rdx, r8, r9, out);
	if (ret == TDX_SEAMCALL_VMFAILINVALID || !ret)
		return ret;

	pr_err("SEAMCALL failed: leaf: 0x%llx, error: 0x%llx\n", fn, ret);
	if (out)
		pr_err("SEAMCALL additional output: rcx 0x%llx, rdx 0x%llx, r8 0x%llx, r9 0x%llx, r10 0x%llx, r11 0x%llx.\n",
			out->rcx, out->rdx, out->r8, out->r9, out->r10, out->r11);

	return ret;
}

static void seamcall_smp_call_function(void *data)
{
	struct seamcall_ctx *sc = data;
	struct tdx_module_output out;
	u64 ret;

	ret = seamcall(sc->fn, sc->rcx, sc->rdx, sc->r8, sc->r9, &out);
	if (ret)
		atomic_set(&sc->err, -EFAULT);
}

/*
 * Call the SEAMCALL on all online CPUs concurrently.  Caller to check
 * @sc->err to determine whether any SEAMCALL failed on any cpu.
 */
static void seamcall_on_each_cpu(struct seamcall_ctx *sc)
{
	on_each_cpu(seamcall_smp_call_function, sc, true);
}

/*
 * Do TDX module global initialization.  It also detects whether the
 * module has been loaded or not.
 */
static int tdx_module_init_global(void)
{
	u64 ret;

	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL);
	if (ret == TDX_SEAMCALL_VMFAILINVALID)
		return -ENODEV;

	return ret ? -EFAULT : 0;
}

static int tdx_module_init_cpus(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_INIT };

	seamcall_on_each_cpu(&sc);

	return atomic_read(&sc.err);
}

/*
 * Detect and initialize the TDX module.
 *
 * Return -ENODEV when the TDX module is not loaded, 0 when it
 * is successfully initialized, or other error when it fails to
 * initialize.
 */
static int init_tdx_module(void)
{
	int ret;

	/*
	 * Whether the TDX module is loaded is still unknown.  SEAMCALL
	 * instruction fails with VMfailInvalid if the target SEAM
	 * software module is not loaded, so it can be used to detect the
	 * module.
	 *
	 * The first step of initializing the TDX module is module global
	 * initialization.  Just use it to detect the module.
	 */
	ret = tdx_module_init_global();
	if (ret)
		goto out;

	/* Logical-cpu scope initialization */
	ret = tdx_module_init_cpus();
	if (ret)
		goto out;


	/*
	 * Return -EINVAL until all steps of TDX module initialization
	 * process are done.
	 */
	ret = -EINVAL;
out:
	return ret;
}

static void shutdown_tdx_module(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_SHUTDOWN };

	seamcall_on_each_cpu(&sc);

	tdx_module_status = TDX_MODULE_SHUTDOWN;
}

static int __tdx_init(void)
{
	int ret;

	/*
	 * Initializing the TDX module requires running some code on
	 * all MADT-enabled CPUs.  If not all MADT-enabled CPUs are
	 * online, it's not possible to initialize the TDX module.
	 *
	 * For simplicity temporarily disable CPU hotplug to prevent
	 * any CPU from going offline during the initialization.
	 */
	cpus_read_lock();

	/*
	 * Check whether all MADT-enabled CPUs are online and return
	 * early with an explicit message so the user can be aware.
	 *
	 * Note ACPI CPU hotplug is prevented when TDX is enabled, so
	 * num_processors always reflects all present MADT-enabled
	 * CPUs during boot when disabled_cpus is 0.
	 */
	if (disabled_cpus || num_online_cpus() != num_processors) {
		pr_err("Unable to initialize the TDX module when there's offline CPU(s).\n");
		ret = -EINVAL;
		goto out;
	}

	ret = init_tdx_module();
	if (ret == -ENODEV) {
		pr_info("TDX module is not loaded.\n");
		goto out;
	}

	/*
	 * Shut down the TDX module in case of any error during the
	 * initialization process.  It's meaningless to leave the TDX
	 * module in any middle state of the initialization process.
	 *
	 * Shutting down the module also requires running some code on
	 * all MADT-enabled CPUs.  Do it while CPU hotplug is disabled.
	 *
	 * Return all errors during initialization as -EFAULT as
	 * the TDX module is always shut down in such cases.
	 */
	if (ret) {
		pr_info("Failed to initialize TDX module.  Shut it down.\n");
		shutdown_tdx_module();
		ret = -EFAULT;
		goto out;
	}

	pr_info("TDX module initialized.\n");
out:
	cpus_read_unlock();

	return ret;
}

/**
 * platform_tdx_enabled() - Return whether BIOS has enabled TDX
 *
 * Return whether BIOS has enabled TDX regardless whether the TDX module
 * has been loaded or not.
 */
bool platform_tdx_enabled(void)
{
	return tdx_keyid_num >= 2;
}

/**
 * tdx_init - Initialize the TDX module
 *
 * Initialize the TDX module to make it ready to run TD guests.
 *
 * Caller to make sure all CPUs are online before calling this function.
 * CPU hotplug is temporarily disabled internally to prevent any cpu
 * from going offline.
 *
 * Caller also needs to guarantee all CPUs are in VMX operation during
 * this function, otherwise Oops may be triggered.
 *
 * This function can be called in parallel by multiple callers.
 *
 * Return:
 *
 * * 0:		The TDX module has been successfully initialized.
 * * -ENODEV:	The TDX module is not loaded, or TDX is not supported.
 * * -EINVAL:	The TDX module cannot be initialized due to certain
 *		conditions are not met (i.e. when not all MADT-enabled
 *		CPUs are not online).
 * * -EFAULT:	Other internal fatal errors, or the TDX module is in
 *		shutdown mode due to it failed to initialize in previous
 *		attempts.
 */
int tdx_init(void)
{
	int ret;

	if (!platform_tdx_enabled())
		return -ENODEV;

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNKNOWN:
		ret = __tdx_init();
		break;
	case TDX_MODULE_NONE:
		ret = -ENODEV;
		break;
	case TDX_MODULE_INITIALIZED:
		ret = 0;
		break;
	default:
		WARN_ON_ONCE(tdx_module_status != TDX_MODULE_SHUTDOWN);
		ret = -EFAULT;
		break;
	}

	mutex_unlock(&tdx_module_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tdx_init);
