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
#include <linux/cpu.h>
#include <linux/spinlock.h>
#include <linux/percpu-defs.h>
#include <linux/mutex.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/tdx.h>
#include "tdx.h"

#define seamcall_err(__fn, __err, __args, __prerr_func)			\
	__prerr_func("SEAMCALL (0x%llx) failed: 0x%llx\n",		\
			((u64)__fn), ((u64)__err))

#define SEAMCALL_REGS_FMT						\
	"RCX 0x%llx RDX 0x%llx R8 0x%llx R9 0x%llx R10 0x%llx R11 0x%llx\n"

#define seamcall_err_ret(__fn, __err, __args, __prerr_func)		\
({									\
	seamcall_err((__fn), (__err), (__args), __prerr_func);		\
	__prerr_func(SEAMCALL_REGS_FMT,					\
			(__args)->rcx, (__args)->rdx, (__args)->r8,	\
			(__args)->r9, (__args)->r10, (__args)->r11);	\
})

#define SEAMCALL_EXTRA_REGS_FMT	\
	"RBX 0x%llx RDI 0x%llx RSI 0x%llx R12 0x%llx R13 0x%llx R14 0x%llx R15 0x%llx"

#define seamcall_err_saved_ret(__fn, __err, __args, __prerr_func)	\
({									\
	seamcall_err_ret(__fn, __err, __args, __prerr_func);		\
	__prerr_func(SEAMCALL_EXTRA_REGS_FMT,				\
			(__args)->rbx, (__args)->rdi, (__args)->rsi,	\
			(__args)->r12, (__args)->r13, (__args)->r14,	\
			(__args)->r15);					\
})

static __always_inline bool seamcall_err_is_kernel_defined(u64 err)
{
	/* All kernel defined SEAMCALL error code have TDX_SW_ERROR set */
	return (err & TDX_SW_ERROR) == TDX_SW_ERROR;
}

#define __SEAMCALL_PRERR(__seamcall_func, __fn, __args, __seamcall_err_func,	\
			__prerr_func)						\
({										\
	u64 ___sret = __seamcall_func((__fn), (__args));			\
										\
	/* Kernel defined error code has special meaning, leave to caller */	\
	if (!seamcall_err_is_kernel_defined((___sret)) &&			\
			___sret != TDX_SUCCESS)					\
		__seamcall_err_func((__fn), (___sret), (__args), __prerr_func);	\
										\
	___sret;								\
})

#define SEAMCALL_PRERR(__seamcall_func, __fn, __args, __seamcall_err_func)	\
({										\
	u64 ___sret = __SEAMCALL_PRERR(__seamcall_func, __fn, __args,		\
			__seamcall_err_func, pr_err);				\
	int ___ret;								\
										\
	switch (___sret) {							\
	case TDX_SUCCESS:							\
		___ret = 0;							\
		break;								\
	case TDX_SEAMCALL_VMFAILINVALID:					\
		pr_err("SEAMCALL failed: TDX module not loaded.\n");		\
		___ret = -ENODEV;						\
		break;								\
	case TDX_SEAMCALL_GP:							\
		pr_err("SEAMCALL failed: TDX disabled by BIOS.\n");		\
		___ret = -EOPNOTSUPP;						\
		break;								\
	case TDX_SEAMCALL_UD:							\
		pr_err("SEAMCALL failed: CPU not in VMX operation.\n");		\
		___ret = -EACCES;						\
		break;								\
	default:								\
		___ret = -EIO;							\
	}									\
	___ret;									\
})

#define seamcall_prerr(__fn, __args)						\
	SEAMCALL_PRERR(seamcall, (__fn), (__args), seamcall_err)

#define seamcall_prerr_ret(__fn, __args)					\
	SEAMCALL_PRERR(seamcall_ret, (__fn), (__args), seamcall_err_ret)

#define seamcall_prerr_saved_ret(__fn, __args)					\
	SEAMCALL_PRERR(seamcall_saved_ret, (__fn), (__args),			\
			seamcall_err_saved_ret)

static u32 tdx_global_keyid __ro_after_init;
static u32 tdx_guest_keyid_start __ro_after_init;
static u32 tdx_nr_guest_keyids __ro_after_init;

static bool tdx_global_initialized;
static DEFINE_RAW_SPINLOCK(tdx_global_init_lock);
static DEFINE_PER_CPU(bool, tdx_lp_initialized);

static enum tdx_module_status_t tdx_module_status;
static DEFINE_MUTEX(tdx_module_lock);

/*
 * Do the module global initialization if not done yet.  It can be
 * done on any cpu.  It's always called with interrupts disabled.
 */
static int try_init_module_global(void)
{
	struct tdx_module_args args = {};
	int ret;

	raw_spin_lock(&tdx_global_init_lock);

	if (tdx_global_initialized) {
		ret = 0;
		goto out;
	}

	ret = seamcall_prerr(TDH_SYS_INIT, &args);
	if (!ret)
		tdx_global_initialized = true;
out:
	raw_spin_unlock(&tdx_global_init_lock);

	return ret;
}

/**
 * tdx_cpu_enable - Enable TDX on local cpu
 *
 * Do one-time TDX module per-cpu initialization SEAMCALL (and TDX module
 * global initialization SEAMCALL if not done) on local cpu to make this
 * cpu be ready to run any other SEAMCALLs.
 *
 * Always call this function via IPI function calls.
 *
 * Return 0 on success, otherwise errors.
 */
int tdx_cpu_enable(void)
{
	struct tdx_module_args args = {};
	int ret;

	if (!platform_tdx_enabled())
		return -ENODEV;

	lockdep_assert_irqs_disabled();

	if (__this_cpu_read(tdx_lp_initialized))
		return 0;

	/*
	 * The TDX module global initialization is the very first step
	 * to enable TDX.  Need to do it first (if hasn't been done)
	 * before the per-cpu initialization.
	 */
	ret = try_init_module_global();
	if (ret)
		return ret;

	ret = seamcall_prerr(TDH_SYS_LP_INIT, &args);
	if (ret)
		return ret;

	__this_cpu_write(tdx_lp_initialized, true);

	return 0;
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
		pr_err("module initialization failed (%d)\n", ret);
		tdx_module_status = TDX_MODULE_ERROR;
		return ret;
	}

	pr_info("module initialized.\n");
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
		return -ENODEV;

	lockdep_assert_cpus_held();

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNINITIALIZED:
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
	 * The TDX module itself requires one 'global KeyID' to protect
	 * its metadata.  If there's only one TDX KeyID, there won't be
	 * any left for TDX guests thus there's no point to enable TDX
	 * at all.
	 */
	if (nr_tdx_keyids < 2) {
		pr_err("initialization failed: too few private KeyIDs available.\n");
		return -ENODEV;
	}

	/*
	 * Just use the first TDX KeyID as the 'global KeyID' and
	 * leave the rest for TDX guests.
	 */
	tdx_global_keyid = tdx_keyid_start;
	tdx_guest_keyid_start = tdx_keyid_start + 1;
	tdx_nr_guest_keyids = nr_tdx_keyids - 1;

	return 0;
}
early_initcall(tdx_init);

/* Return whether the BIOS has enabled TDX */
bool platform_tdx_enabled(void)
{
	return !!tdx_global_keyid;
}
