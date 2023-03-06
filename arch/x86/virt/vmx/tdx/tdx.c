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
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/spinlock.h>
#include <linux/percpu-defs.h>
#include <linux/mutex.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/tdx.h>
#include "tdx.h"

static u32 tdx_global_keyid __ro_after_init;
static u32 tdx_guest_keyid_start __ro_after_init;
static u32 tdx_nr_guest_keyids __ro_after_init;

static unsigned int tdx_global_init_status;
static DEFINE_SPINLOCK(tdx_global_init_lock);
#define TDX_GLOBAL_INIT_DONE	_BITUL(0)
#define TDX_GLOBAL_INIT_FAILED	_BITUL(1)

static DEFINE_PER_CPU(unsigned int, tdx_lp_init_status);
#define TDX_LP_INIT_DONE	_BITUL(0)
#define TDX_LP_INIT_FAILED	_BITUL(1)

static enum tdx_module_status_t tdx_module_status;
static DEFINE_MUTEX(tdx_module_lock);

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

static int try_init_module_global(void)
{
	int ret;

	/*
	 * The TDX module global initialization only needs to be done
	 * once on any cpu.
	 */
	spin_lock(&tdx_global_init_lock);

	if (tdx_global_init_status & TDX_GLOBAL_INIT_DONE) {
		ret = tdx_global_init_status & TDX_GLOBAL_INIT_FAILED ?
			-EINVAL : 0;
		goto out;
	}

	/* All '0's are just unused parameters. */
	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL, NULL);

	tdx_global_init_status = TDX_GLOBAL_INIT_DONE;
	if (ret)
		tdx_global_init_status |= TDX_GLOBAL_INIT_FAILED;
out:
	spin_unlock(&tdx_global_init_lock);

	return ret;
}

/**
 * tdx_cpu_enable - Enable TDX on local cpu
 *
 * Do one-time TDX module per-cpu initialization SEAMCALL (and TDX module
 * global initialization SEAMCALL if not done) on local cpu to make this
 * cpu be ready to run any other SEAMCALLs.
 *
 * Note this function must be called when preemption is not possible
 * (i.e. via SMP call or in per-cpu thread).  It is not IRQ safe either
 * (i.e. cannot be called in per-cpu thread and via SMP call from remote
 * cpu simultaneously).
 *
 * Return 0 on success, otherwise errors.
 */
int tdx_cpu_enable(void)
{
	unsigned int lp_status;
	int ret;

	if (!platform_tdx_enabled())
		return -EINVAL;

	lp_status = __this_cpu_read(tdx_lp_init_status);

	/* Already done */
	if (lp_status & TDX_LP_INIT_DONE)
		return lp_status & TDX_LP_INIT_FAILED ? -EINVAL : 0;

	/*
	 * The TDX module global initialization is the very first step
	 * to enable TDX.  Need to do it first (if hasn't been done)
	 * before doing the per-cpu initialization.
	 */
	ret = try_init_module_global();

	/*
	 * If the module global initialization failed, there's no point
	 * to do the per-cpu initialization.  Just mark it as done but
	 * failed.
	 */
	if (ret)
		goto update_status;

	/* All '0's are just unused parameters */
	ret = seamcall(TDH_SYS_LP_INIT, 0, 0, 0, 0, NULL, NULL);

update_status:
	lp_status = TDX_LP_INIT_DONE;
	if (ret)
		lp_status |= TDX_LP_INIT_FAILED;

	this_cpu_write(tdx_lp_init_status, lp_status);

	return ret;
}
EXPORT_SYMBOL_GPL(tdx_cpu_enable);

static int init_tdx_module(void)
{
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
	return -EINVAL;
}

static int __tdx_enable(void)
{
	int ret;

	ret = init_tdx_module();
	if (ret) {
		pr_err("TDX module initialization failed (%d)\n", ret);
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

/**
 * tdx_enable - Enable TDX module to make it ready to run TDX guests
 *
 * This function assumes the caller has: 1) held read lock of CPU hotplug
 * lock to prevent any new cpu from becoming online; 2) done both VMXON
 * and tdx_cpu_enable() on all online cpus.
 *
 * This function can be called in parallel by multiple callers.
 *
 * Return 0 if TDX is enabled successfully, otherwise error.
 */
int tdx_enable(void)
{
	int ret;

	if (!platform_tdx_enabled())
		return -EINVAL;

	lockdep_assert_cpus_held();

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNKNOWN:
		ret = __tdx_enable();
		break;
	case TDX_MODULE_INITIALIZED:
		/* Already initialized, great, tell the caller. */
		ret = 0;
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
