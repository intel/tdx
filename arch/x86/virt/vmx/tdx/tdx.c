// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) support
 */

#define pr_fmt(fmt)	"virt/tdx: " fmt

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/cpu.h>
#include <linux/spinlock.h>
#include <linux/percpu-defs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/math.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/tdx.h>
#include "tdx.h"

static u32 tdx_global_keyid __ro_after_init;
static u32 tdx_guest_keyid_start __ro_after_init;
static u32 tdx_nr_guest_keyids __ro_after_init;

static DEFINE_PER_CPU(bool, tdx_lp_initialized);

static enum tdx_module_status_t tdx_module_status;
static DEFINE_MUTEX(tdx_module_lock);

typedef void (*sc_err_func_t)(u64 fn, u64 err, struct tdx_module_args *args);

static inline void seamcall_err(u64 fn, u64 err, struct tdx_module_args *args)
{
	pr_err("SEAMCALL (0x%llx) failed: 0x%llx\n", fn, err);
}

static inline void seamcall_err_ret(u64 fn, u64 err,
				    struct tdx_module_args *args)
{
	seamcall_err(fn, err, args);
	pr_err("RCX 0x%llx RDX 0x%llx R8 0x%llx R9 0x%llx R10 0x%llx R11 0x%llx\n",
			args->rcx, args->rdx, args->r8, args->r9,
			args->r10, args->r11);
}

static inline void seamcall_err_saved_ret(u64 fn, u64 err,
					  struct tdx_module_args *args)
{
	seamcall_err_ret(fn, err, args);
	pr_err("RBX 0x%llx RDI 0x%llx RSI 0x%llx R12 0x%llx R13 0x%llx R14 0x%llx R15 0x%llx\n",
			args->rbx, args->rdi, args->rsi, args->r12,
			args->r13, args->r14, args->r15);
}

static inline int sc_retry_prerr(sc_func_t func, sc_err_func_t err_func,
				 u64 fn, struct tdx_module_args *args)
{
	u64 sret = sc_retry(func, fn, args);

	if (sret == TDX_SUCCESS)
		return 0;

	if (sret == TDX_SEAMCALL_VMFAILINVALID)
		return -ENODEV;

	if (sret == TDX_SEAMCALL_GP)
		return -EOPNOTSUPP;

	if (sret == TDX_SEAMCALL_UD)
		return -EACCES;

	err_func(fn, sret, args);
	return -EIO;
}

#define seamcall_prerr(__fn, __args)						\
	sc_retry_prerr(__seamcall, seamcall_err, (__fn), (__args))

#define seamcall_prerr_ret(__fn, __args)					\
	sc_retry_prerr(__seamcall_ret, seamcall_err_ret, (__fn), (__args))

/*
 * Do the module global initialization once and return its result.
 * It can be done on any cpu.  It's always called with interrupts
 * disabled.
 */
static int try_init_module_global(void)
{
	struct tdx_module_args args = {};
	static DEFINE_RAW_SPINLOCK(sysinit_lock);
	static bool sysinit_done;
	static int sysinit_ret;

	lockdep_assert_irqs_disabled();

	raw_spin_lock(&sysinit_lock);

	if (sysinit_done)
		goto out;

	/* RCX is module attributes and all bits are reserved */
	args.rcx = 0;
	sysinit_ret = seamcall_prerr(TDH_SYS_INIT, &args);

	/*
	 * The first SEAMCALL also detects the TDX module, thus
	 * it can fail due to the TDX module is not loaded.
	 * Dump message to let the user know.
	 */
	if (sysinit_ret == -ENODEV)
		pr_err("module not loaded\n");

	sysinit_done = true;
out:
	raw_spin_unlock(&sysinit_lock);
	return sysinit_ret;
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

static void print_cmrs(struct cmr_info *cmr_array, int nr_cmrs)
{
	int i;

	for (i = 0; i < nr_cmrs; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		/*
		 * The array of CMRs reported via TDH.SYS.INFO can
		 * contain tail empty CMRs.  Don't print them.
		 */
		if (!cmr->size)
			break;

		pr_info("CMR: [0x%llx, 0x%llx)\n", cmr->base,
				cmr->base + cmr->size);
	}
}

static int get_tdx_sysinfo(struct tdsysinfo_struct *tdsysinfo,
			   struct cmr_info *cmr_array)
{
	struct tdx_module_args args = {};
	int ret;

	/*
	 * TDH.SYS.INFO writes the TDSYSINFO_STRUCT and the CMR array
	 * to the buffers provided by the kernel (via RCX and R8
	 * respectively).  The buffer size of the TDSYSINFO_STRUCT
	 * (via RDX) and the maximum entries of the CMR array (via R9)
	 * passed to this SEAMCALL must be at least the size of
	 * TDSYSINFO_STRUCT and MAX_CMRS respectively.
	 *
	 * Upon a successful return, R9 contains the actual entries
	 * written to the CMR array.
	 */
	args.rcx = __pa(tdsysinfo);
	args.rdx = TDSYSINFO_STRUCT_SIZE;
	args.r8 = __pa(cmr_array);
	args.r9 = MAX_CMRS;
	ret = seamcall_prerr_ret(TDH_SYS_INFO, &args);
	if (ret)
		return ret;

	pr_info("TDX module: attributes 0x%x, vendor_id 0x%x, major_version %u, minor_version %u, build_date %u, build_num %u",
		tdsysinfo->attributes,    tdsysinfo->vendor_id,
		tdsysinfo->major_version, tdsysinfo->minor_version,
		tdsysinfo->build_date,    tdsysinfo->build_num);

	print_cmrs(cmr_array, args.r9);

	return 0;
}

static int init_tdx_module(void)
{
	struct tdsysinfo_struct *tdsysinfo;
	struct cmr_info *cmr_array;
	int tdsysinfo_size;
	int cmr_array_size;
	int ret;

	tdsysinfo_size = round_up(TDSYSINFO_STRUCT_SIZE,
			TDSYSINFO_STRUCT_ALIGNMENT);
	tdsysinfo = kzalloc(tdsysinfo_size, GFP_KERNEL);
	if (!tdsysinfo)
		return -ENOMEM;

	cmr_array_size = sizeof(struct cmr_info) * MAX_CMRS;
	cmr_array_size = round_up(cmr_array_size, CMR_INFO_ARRAY_ALIGNMENT);
	cmr_array = kzalloc(cmr_array_size, GFP_KERNEL);
	if (!cmr_array) {
		kfree(tdsysinfo);
		return -ENOMEM;
	}


	/* Get the TDSYSINFO_STRUCT and CMRs from the TDX module. */
	ret = get_tdx_sysinfo(tdsysinfo, cmr_array);
	if (ret)
		goto out;

	/*
	 * TODO:
	 *
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
	 * For now both @sysinfo and @cmr_array are only used during
	 * module initialization, so always free them.
	 */
	kfree(tdsysinfo);
	kfree(cmr_array);
	return ret;
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

	pr_info("module initialized\n");
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
