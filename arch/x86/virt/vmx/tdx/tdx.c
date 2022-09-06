// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2022 Intel Corporation.
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
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/memory.h>
#include <linux/minmax.h>
#include <linux/sizes.h>
#include <linux/pfn.h>
#include <asm/pgtable_types.h>
#include <asm/msr.h>
#include <asm/tdx.h>
#include "tdx.h"

/* Kernel defined TDX module status during module initialization. */
enum tdx_module_status_t {
	TDX_MODULE_UNKNOWN,
	TDX_MODULE_INITIALIZED,
	TDX_MODULE_ERROR
};

struct tdx_memblock {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
};

static u32 tdx_keyid_start __ro_after_init;
static u32 nr_tdx_keyids __ro_after_init;

static enum tdx_module_status_t tdx_module_status;
/* Prevent concurrent attempts on TDX detection and initialization */
static DEFINE_MUTEX(tdx_module_lock);

/* All TDX-usable memory regions */
static LIST_HEAD(tdx_memlist);

/*
 * tdx_keyid_start and nr_tdx_keyids indicate that TDX is uninitialized.
 * This is used in TDX initialization error paths to take it from
 * initialized -> uninitialized.
 */
static void __init clear_tdx(void)
{
	tdx_keyid_start = nr_tdx_keyids = 0;
}

static int __init record_keyid_partitioning(void)
{
	u32 nr_mktme_keyids;
	int ret;

	/*
	 * IA32_MKTME_KEYID_PARTIONING:
	 *   Bit [31:0]:	Number of MKTME KeyIDs.
	 *   Bit [63:32]:	Number of TDX private KeyIDs.
	 */
	ret = rdmsr_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &nr_mktme_keyids,
			&nr_tdx_keyids);
	if (ret)
		return -ENODEV;

	if (!nr_tdx_keyids)
		return -ENODEV;

	/* TDX KeyIDs start after the last MKTME KeyID. */
	tdx_keyid_start = nr_mktme_keyids + 1;

	pr_info("BIOS enabled: private KeyID range [%u, %u)\n",
			tdx_keyid_start, tdx_keyid_start + nr_tdx_keyids);

	return 0;
}

static bool is_tdx_memory(unsigned long start_pfn, unsigned long end_pfn)
{
	struct tdx_memblock *tmb;

	/* Empty list means TDX isn't enabled. */
	if (list_empty(&tdx_memlist))
		return true;

	list_for_each_entry(tmb, &tdx_memlist, list) {
		/*
		 * The new range is TDX memory if it is fully covered by
		 * any TDX memory block.
		 *
		 * Note TDX memory blocks are originated from memblock
		 * memory regions, which can only be contiguous when two
		 * regions have different NUMA nodes or flags.  Therefore
		 * the new range cannot cross multiple TDX memory blocks.
		 */
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
	 * Not all memory is compatible with TDX.  Reject
	 * to online any incompatible memory.
	 */
	return is_tdx_memory(mn->start_pfn, mn->start_pfn + mn->nr_pages) ?
		NOTIFY_OK : NOTIFY_BAD;
}

static struct notifier_block tdx_memory_nb = {
	.notifier_call = tdx_memory_notifier,
};

static int __init tdx_init(void)
{
	int err;

	err = record_keyid_partitioning();
	if (err)
		return err;

	/*
	 * Initializing the TDX module requires one TDX private KeyID.
	 * If there's only one TDX KeyID then after module initialization
	 * KVM won't be able to run any TDX guest, which makes the whole
	 * thing worthless.  Just disable TDX in this case.
	 */
	if (nr_tdx_keyids < 2) {
		pr_info("initialization failed: too few private KeyIDs available (%d).\n",
				nr_tdx_keyids);
		goto no_tdx;
	}

	err = register_memory_notifier(&tdx_memory_nb);
	if (err) {
		pr_info("initialization failed: register_memory_notifier() failed (%d)\n",
				err);
		goto no_tdx;
	}

	return 0;
no_tdx:
	clear_tdx();
	return -ENODEV;
}
early_initcall(tdx_init);

/* Return whether the BIOS has enabled TDX */
bool platform_tdx_enabled(void)
{
	return !!nr_tdx_keyids;
}

/*
 * Wrapper of __seamcall() to convert SEAMCALL leaf function error code
 * to kernel error code.  @seamcall_ret and @out contain the SEAMCALL
 * leaf function return code and the additional output respectively if
 * not NULL.
 */
static int seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		    u64 *seamcall_ret, struct tdx_module_output *out)
{
	u64 sret;

	sret = __seamcall(fn, rcx, rdx, r8, r9, out);

	/* Save SEAMCALL return code if the caller wants it */
	if (seamcall_ret)
		*seamcall_ret = sret;

	/* SEAMCALL was successful */
	if (!sret)
		return 0;

	switch (sret) {
	case TDX_SEAMCALL_GP:
		/*
		 * tdx_enable() has already checked that BIOS has
		 * enabled TDX at the very beginning before going
		 * forward.  It's likely a firmware bug if the
		 * SEAMCALL still caused #GP.
		 */
		pr_err_once("[firmware bug]: TDX is not enabled by BIOS.\n");
		return -ENODEV;
	case TDX_SEAMCALL_VMFAILINVALID:
		pr_err_once("TDX module is not loaded.\n");
		return -ENODEV;
	case TDX_SEAMCALL_UD:
		pr_err_once("CPU is not in VMX operation.\n");
		return -EINVAL;
	default:
		pr_err_once("SEAMCALL failed: leaf %llu, error 0x%llx.\n",
				fn, sret);
		if (out)
			pr_err_once("additional output: rcx 0x%llx, rdx 0x%llx, r8 0x%llx, r9 0x%llx, r10 0x%llx, r11 0x%llx.\n",
					out->rcx, out->rdx, out->r8,
					out->r9, out->r10, out->r11);
		return -EIO;
	}
}

static inline bool is_cmr_empty(struct cmr_info *cmr)
{
	return !cmr->size;
}

static void print_cmrs(struct cmr_info *cmr_array, int nr_cmrs)
{
	int i;

	for (i = 0; i < nr_cmrs; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		/*
		 * The array of CMRs reported via TDH.SYS.INFO can
		 * contain tail empty CMRs.  Don't print them.
		 */
		if (is_cmr_empty(cmr))
			break;

		pr_info("CMR: [0x%llx, 0x%llx)\n", cmr->base,
				cmr->base + cmr->size);
	}
}

/*
 * Get the TDX module information (TDSYSINFO_STRUCT) and the array of
 * CMRs, and save them to @sysinfo and @cmr_array, which come from the
 * kernel stack.  @sysinfo must have been padded to have enough room
 * to save the TDSYSINFO_STRUCT.
 */
static int tdx_get_sysinfo(struct tdsysinfo_struct *sysinfo,
			   struct cmr_info *cmr_array)
{
	struct tdx_module_output out;
	u64 sysinfo_pa, cmr_array_pa;
	int ret;

	/*
	 * Cannot use __pa() directly as @sysinfo and @cmr_array
	 * come from the kernel stack.
	 */
	sysinfo_pa = slow_virt_to_phys(sysinfo);
	cmr_array_pa = slow_virt_to_phys(cmr_array);
	ret = seamcall(TDH_SYS_INFO, sysinfo_pa, TDSYSINFO_STRUCT_SIZE,
			cmr_array_pa, MAX_CMRS, NULL, &out);
	if (ret)
		return ret;

	pr_info("TDX module: atributes 0x%x, vendor_id 0x%x, major_version %u, minor_version %u, build_date %u, build_num %u",
		sysinfo->attributes,	sysinfo->vendor_id,
		sysinfo->major_version, sysinfo->minor_version,
		sysinfo->build_date,	sysinfo->build_num);

	/* R9 contains the actual entries written to the CMR array. */
	print_cmrs(cmr_array, out.r9);

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

	list_add_tail(&tmb->list, tmb_list);
	return 0;
}

static void free_tdx_memlist(struct list_head *tmb_list)
{
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

static int init_tdx_module(void)
{
	/*
	 * @tdsysinfo and @cmr_array are used in TDH.SYS.INFO SEAMCALL ABI.
	 * They are 1024 bytes and 512 bytes respectively but it's fine to
	 * keep them in the stack as this function is only called once.
	 */
	DECLARE_PADDED_STRUCT(tdsysinfo_struct, tdsysinfo,
			TDSYSINFO_STRUCT_SIZE, TDSYSINFO_STRUCT_ALIGNMENT);
	struct cmr_info cmr_array[MAX_CMRS] __aligned(CMR_INFO_ARRAY_ALIGNMENT);
	struct tdsysinfo_struct *sysinfo = &PADDED_STRUCT(tdsysinfo);
	int ret;

	ret = tdx_get_sysinfo(sysinfo, cmr_array);
	if (ret)
		goto out;

	/*
	 * The initial support of TDX guests only allocates memory from
	 * the global page allocator.  To keep things simple, just make
	 * sure all pages in the page allocator are TDX memory.
	 *
	 * Build the list of "TDX-usable" memory regions which cover all
	 * pages in the page allocator to guarantee that.  Do it while
	 * holding mem_hotplug_lock read-lock as the memory hotplug code
	 * path reads the @tdx_memlist to reject any new memory.
	 */
	get_online_mems();

	ret = build_tdx_memlist(&tdx_memlist);
	if (ret)
		goto out;

	/*
	 * TODO:
	 *
	 *  - Construct a list of TDMRs to cover all TDX-usable memory
	 *    regions.
	 *  - Pick up one TDX private KeyID as the global KeyID.
	 *  - Configure the TDMRs and the global KeyID to the TDX module.
	 *  - Configure the global KeyID on all packages.
	 *  - Initialize all TDMRs.
	 *
	 *  Return error before all steps are done.
	 */
	ret = -EINVAL;
out:
	/*
	 * @tdx_memlist is written here and read at memory hotplug time.
	 * Lock out memory hotplug code while building it.
	 */
	put_online_mems();
	return ret;
}

static int __tdx_enable(void)
{
	int ret;

	ret = init_tdx_module();
	if (ret) {
		pr_err_once("initialization failed (%d)\n", ret);
		tdx_module_status = TDX_MODULE_ERROR;
		/*
		 * Just return one universal error code.
		 * For now the caller cannot recover anyway.
		 */
		return -EINVAL;
	}

	pr_info_once("TDX module initialized.\n");
	tdx_module_status = TDX_MODULE_INITIALIZED;

	return 0;
}

/**
 * tdx_enable - Enable TDX by initializing the TDX module
 *
 * The caller must make sure all online cpus are in VMX operation before
 * calling this function.
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
