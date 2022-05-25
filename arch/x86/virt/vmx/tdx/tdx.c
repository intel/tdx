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
#include <linux/slab.h>
#include <linux/math.h>
#include <linux/list.h>
#include <linux/memblock.h>
#include <linux/memory.h>
#include <linux/minmax.h>
#include <linux/sizes.h>
#include <linux/pfn.h>
#include <linux/align.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/page.h>
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

/* All TDX-usable memory regions.  Protected by mem_hotplug_lock. */
static LIST_HEAD(tdx_memlist);

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
	struct tdx_module_args args;
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

/*
 * Add a memory region as a TDX memory block.  The caller must make sure
 * all memory regions are added in address ascending order and don't
 * overlap.
 */
static int add_tdx_memblock(struct list_head *tmb_list, unsigned long start_pfn,
			    unsigned long end_pfn)
{
	struct tdx_memblock *tmb;

	tmb = kmalloc(sizeof(*tmb), GFP_KERNEL);
	if (!tmb)
		return -ENOMEM;

	INIT_LIST_HEAD(&tmb->list);
	tmb->start_pfn = start_pfn;
	tmb->end_pfn = end_pfn;

	/* @tmb_list is protected by mem_hotplug_lock */
	list_add_tail(&tmb->list, tmb_list);
	return 0;
}

static void free_tdx_memlist(struct list_head *tmb_list)
{
	/* @tmb_list is protected by mem_hotplug_lock */
	while (!list_empty(tmb_list)) {
		struct tdx_memblock *tmb = list_first_entry(tmb_list,
				struct tdx_memblock, list);

		list_del(&tmb->list);
		kfree(tmb);
	}
}

/*
 * Ensure that all memblock memory regions are convertible to TDX
 * memory.  Once this has been established, stash the memblock
 * ranges off in a secondary structure because memblock is modified
 * in memory hotplug while TDX memory regions are fixed.
 */
static int build_tdx_memlist(struct list_head *tmb_list)
{
	unsigned long start_pfn, end_pfn;
	int i, ret;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, NULL) {
		/*
		 * The first 1MB is not reported as TDX convertible memory.
		 * Although the first 1MB is always reserved and won't end up
		 * to the page allocator, it is still in memblock's memory
		 * regions.  Skip them manually to exclude them as TDX memory.
		 */
		start_pfn = max(start_pfn, PHYS_PFN(SZ_1M));
		if (start_pfn >= end_pfn)
			continue;

		/*
		 * Add the memory regions as TDX memory.  The regions in
		 * memblock has already guaranteed they are in address
		 * ascending order and don't overlap.
		 */
		ret = add_tdx_memblock(tmb_list, start_pfn, end_pfn);
		if (ret)
			goto err;
	}

	return 0;
err:
	free_tdx_memlist(tmb_list);
	return ret;
}

/* Calculate the actual TDMR size */
static int tdmr_size_single(u16 max_reserved_per_tdmr)
{
	int tdmr_sz;

	/*
	 * The actual size of TDMR depends on the maximum
	 * number of reserved areas.
	 */
	tdmr_sz = sizeof(struct tdmr_info);
	tdmr_sz += sizeof(struct tdmr_reserved_area) * max_reserved_per_tdmr;

	return ALIGN(tdmr_sz, TDMR_INFO_ALIGNMENT);
}

static int alloc_tdmr_list(struct tdmr_info_list *tdmr_list,
			   struct tdsysinfo_struct *sysinfo)
{
	size_t tdmr_sz, tdmr_array_sz;
	void *tdmr_array;

	tdmr_sz = tdmr_size_single(sysinfo->max_reserved_per_tdmr);
	tdmr_array_sz = tdmr_sz * sysinfo->max_tdmrs;

	/*
	 * To keep things simple, allocate all TDMRs together.
	 * The buffer needs to be physically contiguous to make
	 * sure each TDMR is physically contiguous.
	 */
	tdmr_array = alloc_pages_exact(tdmr_array_sz,
			GFP_KERNEL | __GFP_ZERO);
	if (!tdmr_array)
		return -ENOMEM;

	tdmr_list->tdmrs = tdmr_array;

	/*
	 * Keep the size of TDMR to find the target TDMR
	 * at a given index in the TDMR list.
	 */
	tdmr_list->tdmr_sz = tdmr_sz;
	tdmr_list->max_tdmrs = sysinfo->max_tdmrs;
	tdmr_list->nr_consumed_tdmrs = 0;

	return 0;
}

static void free_tdmr_list(struct tdmr_info_list *tdmr_list)
{
	free_pages_exact(tdmr_list->tdmrs,
			tdmr_list->max_tdmrs * tdmr_list->tdmr_sz);
}

/*
 * Construct a list of TDMRs on the preallocated space in @tdmr_list
 * to cover all TDX memory regions in @tmb_list based on the TDX module
 * information in @sysinfo.
 */
static int construct_tdmrs(struct list_head *tmb_list,
			   struct tdmr_info_list *tdmr_list,
			   struct tdsysinfo_struct *sysinfo)
{
	/*
	 * TODO:
	 *
	 *  - Fill out TDMRs to cover all TDX memory regions.
	 *  - Allocate and set up PAMTs for each TDMR.
	 *  - Designate reserved areas for each TDMR.
	 *
	 * Return -EINVAL until constructing TDMRs is done
	 */
	return -EINVAL;
}

static int init_tdx_module(void)
{
	struct tdsysinfo_struct *tdsysinfo;
	struct tdmr_info_list tdmr_list;
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
	 * To keep things simple, assume that all TDX-protected memory
	 * will come from the page allocator.  Make sure all pages in the
	 * page allocator are TDX-usable memory.
	 *
	 * Build the list of "TDX-usable" memory regions which cover all
	 * pages in the page allocator to guarantee that.  Do it while
	 * holding mem_hotplug_lock read-lock as the memory hotplug code
	 * path reads the @tdx_memlist to reject any new memory.
	 */
	get_online_mems();

	ret = build_tdx_memlist(&tdx_memlist);
	if (ret)
		goto out_put_tdxmem;

	/* Allocate enough space for constructing TDMRs */
	ret = alloc_tdmr_list(&tdmr_list, tdsysinfo);
	if (ret)
		goto out_free_tdxmem;

	/* Cover all TDX-usable memory regions in TDMRs */
	ret = construct_tdmrs(&tdx_memlist, &tdmr_list, tdsysinfo);
	if (ret)
		goto out_free_tdmrs;

	/*
	 * TODO:
	 *
	 *  - Configure the TDMRs and the global KeyID to the TDX module.
	 *  - Configure the global KeyID on all packages.
	 *  - Initialize all TDMRs.
	 *
	 *  Return error before all steps are done.
	 */
	ret = -EINVAL;
out_free_tdmrs:
	/*
	 * Always free the buffer of TDMRs as they are only used during
	 * module initialization.
	 */
	free_tdmr_list(&tdmr_list);
out_free_tdxmem:
	if (ret)
		free_tdx_memlist(&tdx_memlist);
out_put_tdxmem:
	/*
	 * @tdx_memlist is written here and read at memory hotplug time.
	 * Lock out memory hotplug code while building it.
	 */
	put_online_mems();
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

static bool is_tdx_memory(unsigned long start_pfn, unsigned long end_pfn)
{
	struct tdx_memblock *tmb;

	/*
	 * This check assumes that the start_pfn<->end_pfn range does not
	 * cross multiple @tdx_memlist entries.  A single memory online
	 * event across multiple memblocks (from which @tdx_memlist
	 * entries are derived at the time of module initialization) is
	 * not possible.  This is because memory offline/online is done
	 * on granularity of 'struct memory_block', and the hotpluggable
	 * memory region (one memblock) must be multiple of memory_block.
	 */
	list_for_each_entry(tmb, &tdx_memlist, list) {
		if (start_pfn >= tmb->start_pfn && end_pfn <= tmb->end_pfn)
			return true;
	}
	return false;
}

static int tdx_memory_notifier(struct notifier_block *nb, unsigned long action,
			       void *v)
{
	struct memory_notify *mn = v;

	if (action != MEM_GOING_ONLINE)
		return NOTIFY_OK;

	/*
	 * Empty list means TDX isn't enabled.  Allow any memory
	 * to go online.
	 */
	if (list_empty(&tdx_memlist))
		return NOTIFY_OK;

	/*
	 * The TDX memory configuration is static and can not be
	 * changed.  Reject onlining any memory which is outside of
	 * the static configuration whether it supports TDX or not.
	 */
	if (is_tdx_memory(mn->start_pfn, mn->start_pfn + mn->nr_pages))
		return NOTIFY_OK;

	return NOTIFY_BAD;
}

static struct notifier_block tdx_memory_nb = {
	.notifier_call = tdx_memory_notifier,
};

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

	err = register_memory_notifier(&tdx_memory_nb);
	if (err) {
		pr_info("initialization failed: register_memory_notifier() failed (%d)\n",
				err);
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
