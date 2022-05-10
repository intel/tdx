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
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/memory.h>
#include <linux/minmax.h>
#include <linux/sizes.h>
#include <linux/pfn.h>
#include <linux/align.h>
#include <linux/sort.h>
#include <linux/log2.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/archrandom.h>
#include <asm/page.h>
#include <asm/special_insns.h>
#include <asm/tdx.h>
#include "tdx.h"

#ifdef CONFIG_SYSFS
static int tdx_sysfs_init(void);
#else
static inline int tdx_sysfs_init(void) { return 0; }
#endif

u32 tdx_global_keyid __ro_after_init;
EXPORT_SYMBOL_GPL(tdx_global_keyid);
static u32 tdx_guest_keyid_start __ro_after_init;
static u32 tdx_nr_guest_keyids __ro_after_init;

static bool tdx_global_initialized;
static DEFINE_RAW_SPINLOCK(tdx_global_init_lock);
static DEFINE_PER_CPU(bool, tdx_lp_initialized);

static enum tdx_module_status_t tdx_module_status;
static DEFINE_MUTEX(tdx_module_lock);

/* All TDX-usable memory regions.  Protected by mem_hotplug_lock. */
static LIST_HEAD(tdx_memlist);

static struct tdmr_info_list tdx_tdmr_list;

static atomic_t tdx_may_has_private_mem;

u32 tdx_get_nr_guest_keyids(void)
{
	return tdx_nr_guest_keyids;
}
EXPORT_SYMBOL_GPL(tdx_get_nr_guest_keyids);

/* REVERTME: tdx module debug */
/* Non-architectural debug configuration SEAMCALLs. */
#define SEAMCALL_TDDEBUGCONFIG		0xFE

#define DEBUGCONFIG_SET_TRACE_LEVEL	3

static bool trace_boot_seamcalls;

static int __init trace_seamcalls(char *s)
{
	trace_boot_seamcalls = true;
	return 1;
}
__setup("trace_boot_seamcalls", trace_seamcalls);

static u64 tdx_trace_level = DEBUGCONFIG_TRACE_CUSTOM;

static int trace_level_set(const char *val, const struct kernel_param *kp)
{
	int r;

	r = param_set_ulong(val, kp);
	if (tdx_trace_level == DEBUGCONFIG_TRACE_ALL ||
		tdx_trace_level == DEBUGCONFIG_TRACE_WARN ||
		tdx_trace_level == DEBUGCONFIG_TRACE_ERROR ||
		tdx_trace_level == DEBUGCONFIG_TRACE_CUSTOM ||
		tdx_trace_level == DEBUGCONFIG_TRACE_NONE) {
		tdx_trace_seamcalls(tdx_trace_level);
	}

	return r;
}

static const struct kernel_param_ops tdx_trace_ops = {
	.set = trace_level_set,
	.get = param_get_ulong,
};

module_param_cb(tdx_trace_level, &tdx_trace_ops, &tdx_trace_level, 0644);
MODULE_PARM_DESC(tdx_trace_level, "TDX module trace level");

/* TDX KeyID pool */
static DEFINE_IDA(tdx_guest_keyid_pool);

int tdx_guest_keyid_alloc(void)
{
	if (WARN_ON_ONCE(!tdx_guest_keyid_start || !tdx_nr_guest_keyids))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_guest_keyid_pool, tdx_guest_keyid_start + 1,
			       tdx_guest_keyid_start + tdx_nr_guest_keyids - 1,
			       GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(tdx_guest_keyid_alloc);

void tdx_guest_keyid_free(int keyid)
{
	/* keyid = 0 is reserved. */
	if (WARN_ON_ONCE(keyid <= 0))
		return;

	ida_free(&tdx_guest_keyid_pool, keyid);
}
EXPORT_SYMBOL_GPL(tdx_guest_keyid_free);

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
	int cpu, retry = RDRAND_RETRY_LOOPS;
	u64 sret;

	/* Need a stable CPU id for printing error message */
	cpu = get_cpu();

	/*
	 * Certain SEAMCALL leaf functions may return error due to
	 * running out of entropy, in which case the SEAMCALL should
	 * be retried.  Handle this in SEAMCALL common function.
	 *
	 * Mimic rdrand_long() retry behavior.
	 */
	do {
		sret = __seamcall(fn, rcx, rdx, r8, r9, out);
	} while (sret == TDX_RND_NO_ENTROPY && --retry);

	put_cpu();

	/* Save SEAMCALL return code if the caller wants it */
	if (seamcall_ret)
		*seamcall_ret = sret;

	switch (sret) {
	case 0:
		/* SEAMCALL was successful */
		return 0;
	case TDX_SEAMCALL_VMFAILINVALID:
		pr_err_once("module is not loaded.\n");
		return -ENODEV;
	case TDX_SEAMCALL_GP:
		pr_err_once("not enabled by BIOS.\n");
		return -ENODEV;
	case TDX_SEAMCALL_UD:
		pr_err_once("SEAMCALL failed: CPU %d is not in VMX operation.\n",
				cpu);
		return -EINVAL;
	case TDX_INCORRECT_CPUID_VALUE:
		pr_err_once("TDX module is outdated. Use v1.0.3 or newer.\n");
		return -ENODEV;
	default:
		pr_err_once("SEAMCALL failed: CPU %d: leaf %llu, error 0x%llx.\n",
				cpu, fn, sret);
		if (out)
			pr_err_once("additional output: rcx 0x%llx, rdx 0x%llx, r8 0x%llx, r9 0x%llx, r10 0x%llx, r11 0x%llx.\n",
					out->rcx, out->rdx, out->r8,
					out->r9, out->r10, out->r11);
		return -EIO;
	}
}

void tdx_trace_seamcalls(u64 level)
{
	static bool debugconfig_supported = true;
	int ret;

	if (debugconfig_supported) {
		ret = seamcall(SEAMCALL_TDDEBUGCONFIG,
			       DEBUGCONFIG_SET_TRACE_LEVEL, level, 0, 0, NULL, NULL);
		if (ret) {
			pr_info_once("TDDEBUGCONFIG isn't supported.\n");
			debugconfig_supported = false;
		}
	}
}
EXPORT_SYMBOL_GPL(tdx_trace_seamcalls);

/*
 * Do the module global initialization if not done yet.
 * It's always called with interrupts and preemption disabled.
 */
static int try_init_module_global(void)
{
	unsigned long flags;
	int ret;

	/*
	 * The TDX module global initialization only needs to be done
	 * once on any cpu.
	 */
	raw_spin_lock_irqsave(&tdx_global_init_lock, flags);

	if (tdx_global_initialized) {
		ret = 0;
		goto out;
	}

	/* All '0's are just unused parameters. */
	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL, NULL);
	if (!ret)
		tdx_global_initialized = true;
out:
	raw_spin_unlock_irqrestore(&tdx_global_init_lock, flags);

	if (!ret) {
		if (trace_boot_seamcalls)
			tdx_trace_seamcalls(DEBUGCONFIG_TRACE_ALL);
		else
			tdx_trace_seamcalls(tdx_trace_level);
	}

	return ret;
}

/**
 * tdx_cpu_enable - Enable TDX on local cpu
 *
 * Do one-time TDX module per-cpu initialization SEAMCALL (and TDX module
 * global initialization SEAMCALL if not done) on local cpu to make this
 * cpu be ready to run any other SEAMCALLs.
 *
 * Call this function with preemption disabled.
 *
 * Return 0 on success, otherwise errors.
 */
int tdx_cpu_enable(void)
{
	int ret;

	if (!platform_tdx_enabled())
		return -ENODEV;

	lockdep_assert_preemption_disabled();

	/* Already done */
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

	/* All '0's are just unused parameters */
	ret = seamcall(TDH_SYS_LP_INIT, 0, 0, 0, 0, NULL, NULL);
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

static int __tdx_get_sysinfo(struct tdsysinfo_struct *sysinfo,
			   struct cmr_info *cmr_array)
{
	struct tdx_module_output out;
	u64 sysinfo_pa, cmr_array_pa;
	int ret;

	sysinfo_pa = __pa(sysinfo);
	cmr_array_pa = __pa(cmr_array);
	ret = seamcall(TDH_SYS_INFO, sysinfo_pa, TDSYSINFO_STRUCT_SIZE,
			cmr_array_pa, MAX_CMRS, NULL, &out);
	if (ret)
		return ret;

	ret = tdx_sysfs_init();
	if (ret)
		return ret;

	pr_info("TDX module: attributes 0x%x, vendor_id 0x%x, major_version %u, minor_version %u, build_date %u, build_num %u",
		sysinfo->attributes,	sysinfo->vendor_id,
		sysinfo->major_version, sysinfo->minor_version,
		sysinfo->build_date,	sysinfo->build_num);

	/* R9 contains the actual entries written to the CMR array. */
	print_cmrs(cmr_array, out.r9);

	return 0;
}

static struct tdsysinfo_struct *sysinfo;

const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	const struct tdsysinfo_struct *r = NULL;

	mutex_lock(&tdx_module_lock);
	if (tdx_module_status == TDX_MODULE_INITIALIZED)
		r = sysinfo;
	mutex_unlock(&tdx_module_lock);
	return r;
}
EXPORT_SYMBOL_GPL(tdx_get_sysinfo);

/*
 * Add a memory region as a TDX memory block.  The caller must make sure
 * all memory regions are added in address ascending order and don't
 * overlap.
 */
static int add_tdx_memblock(struct list_head *tmb_list, unsigned long start_pfn,
			    unsigned long end_pfn, int nid)
{
	struct tdx_memblock *tmb;

	tmb = kmalloc(sizeof(*tmb), GFP_KERNEL);
	if (!tmb)
		return -ENOMEM;

	INIT_LIST_HEAD(&tmb->list);
	tmb->start_pfn = start_pfn;
	tmb->end_pfn = end_pfn;
	tmb->nid = nid;

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
	int i, nid, ret;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
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
		ret = add_tdx_memblock(tmb_list, start_pfn, end_pfn, nid);
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

/* Get the TDMR from the list at the given index. */
static struct tdmr_info *tdmr_entry(struct tdmr_info_list *tdmr_list,
				    int idx)
{
	int tdmr_info_offset = tdmr_list->tdmr_sz * idx;

	return (void *)tdmr_list->tdmrs + tdmr_info_offset;
}

#define TDMR_ALIGNMENT		SZ_1G
#define TDMR_ALIGN_DOWN(_addr)	ALIGN_DOWN((_addr), TDMR_ALIGNMENT)
#define TDMR_ALIGN_UP(_addr)	ALIGN((_addr), TDMR_ALIGNMENT)

static inline u64 tdmr_end(struct tdmr_info *tdmr)
{
	return tdmr->base + tdmr->size;
}

/*
 * Take the memory referenced in @tmb_list and populate the
 * preallocated @tdmr_list, following all the special alignment
 * and size rules for TDMR.
 */
static int fill_out_tdmrs(struct list_head *tmb_list,
			  struct tdmr_info_list *tdmr_list)
{
	struct tdx_memblock *tmb;
	int tdmr_idx = 0;

	/*
	 * Loop over TDX memory regions and fill out TDMRs to cover them.
	 * To keep it simple, always try to use one TDMR to cover one
	 * memory region.
	 *
	 * In practice TDX supports at least 64 TDMRs.  A 2-socket system
	 * typically only consumes less than 10 of those.  This code is
	 * dumb and simple and may use more TMDRs than is strictly
	 * required.
	 */
	list_for_each_entry(tmb, tmb_list, list) {
		struct tdmr_info *tdmr = tdmr_entry(tdmr_list, tdmr_idx);
		u64 start, end;

		start = TDMR_ALIGN_DOWN(PFN_PHYS(tmb->start_pfn));
		end   = TDMR_ALIGN_UP(PFN_PHYS(tmb->end_pfn));

		/*
		 * A valid size indicates the current TDMR has already
		 * been filled out to cover the previous memory region(s).
		 */
		if (tdmr->size) {
			/*
			 * Loop to the next if the current memory region
			 * has already been fully covered.
			 */
			if (end <= tdmr_end(tdmr))
				continue;

			/* Otherwise, skip the already covered part. */
			if (start < tdmr_end(tdmr))
				start = tdmr_end(tdmr);

			/*
			 * Create a new TDMR to cover the current memory
			 * region, or the remaining part of it.
			 */
			tdmr_idx++;
			if (tdmr_idx >= tdmr_list->max_tdmrs) {
				pr_warn("initialization failed: TDMRs exhausted.\n");
				return -ENOSPC;
			}

			tdmr = tdmr_entry(tdmr_list, tdmr_idx);
		}

		tdmr->base = start;
		tdmr->size = end - start;
	}

	/* @tdmr_idx is always the index of the last valid TDMR. */
	tdmr_list->nr_consumed_tdmrs = tdmr_idx + 1;

	/*
	 * Warn early that kernel is about to run out of TDMRs.
	 *
	 * This is an indication that TDMR allocation has to be
	 * reworked to be smarter to not run into an issue.
	 */
	if (tdmr_list->max_tdmrs - tdmr_list->nr_consumed_tdmrs < TDMR_NR_WARN)
		pr_warn("consumed TDMRs reaching limit: %d used out of %d\n",
				tdmr_list->nr_consumed_tdmrs,
				tdmr_list->max_tdmrs);

	return 0;
}

/*
 * Calculate PAMT size given a TDMR and a page size.  The returned
 * PAMT size is always aligned up to 4K page boundary.
 */
static unsigned long tdmr_get_pamt_sz(struct tdmr_info *tdmr, int pgsz,
				      u16 pamt_entry_size)
{
	unsigned long pamt_sz, nr_pamt_entries;

	switch (pgsz) {
	case TDX_PS_4K:
		nr_pamt_entries = tdmr->size >> PAGE_SHIFT;
		break;
	case TDX_PS_2M:
		nr_pamt_entries = tdmr->size >> PMD_SHIFT;
		break;
	case TDX_PS_1G:
		nr_pamt_entries = tdmr->size >> PUD_SHIFT;
		break;
	default:
		WARN_ON_ONCE(1);
		return 0;
	}

	pamt_sz = nr_pamt_entries * pamt_entry_size;
	/* TDX requires PAMT size must be 4K aligned */
	pamt_sz = ALIGN(pamt_sz, PAGE_SIZE);

	return pamt_sz;
}

/*
 * Locate a NUMA node which should hold the allocation of the @tdmr
 * PAMT.  This node will have some memory covered by the TDMR.  The
 * relative amount of memory covered is not considered.
 */
static int tdmr_get_nid(struct tdmr_info *tdmr, struct list_head *tmb_list)
{
	struct tdx_memblock *tmb;

	/*
	 * A TDMR must cover at least part of one TMB.  That TMB will end
	 * after the TDMR begins.  But, that TMB may have started before
	 * the TDMR.  Find the next 'tmb' that _ends_ after this TDMR
	 * begins.  Ignore 'tmb' start addresses.  They are irrelevant.
	 */
	list_for_each_entry(tmb, tmb_list, list) {
		if (tmb->end_pfn > PHYS_PFN(tdmr->base))
			return tmb->nid;
	}

	/*
	 * Fall back to allocating the TDMR's metadata from node 0 when
	 * no TDX memory block can be found.  This should never happen
	 * since TDMRs originate from TDX memory blocks.
	 */
	pr_warn("TDMR [0x%llx, 0x%llx): unable to find local NUMA node for PAMT allocation, fallback to use node 0.\n",
			tdmr->base, tdmr_end(tdmr));
	return 0;
}

/*
 * Allocate PAMTs from the local NUMA node of some memory in @tmb_list
 * within @tdmr, and set up PAMTs for @tdmr.
 */
static int tdmr_set_up_pamt(struct tdmr_info *tdmr,
			    struct list_head *tmb_list,
			    u16 pamt_entry_size)
{
	unsigned long pamt_base[TDX_PS_NR];
	unsigned long pamt_size[TDX_PS_NR];
	unsigned long tdmr_pamt_base;
	unsigned long tdmr_pamt_size;
	struct page *pamt;
	int pgsz, nid;

	nid = tdmr_get_nid(tdmr, tmb_list);

	/*
	 * Calculate the PAMT size for each TDX supported page size
	 * and the total PAMT size.
	 */
	tdmr_pamt_size = 0;
	for (pgsz = TDX_PS_4K; pgsz < TDX_PS_NR ; pgsz++) {
		pamt_size[pgsz] = tdmr_get_pamt_sz(tdmr, pgsz,
					pamt_entry_size);
		tdmr_pamt_size += pamt_size[pgsz];
	}

	/*
	 * Allocate one chunk of physically contiguous memory for all
	 * PAMTs.  This helps minimize the PAMT's use of reserved areas
	 * in overlapped TDMRs.
	 */
	pamt = alloc_contig_pages(tdmr_pamt_size >> PAGE_SHIFT, GFP_KERNEL,
			nid, &node_online_map);
	if (!pamt)
		return -ENOMEM;

	/*
	 * Break the contiguous allocation back up into the
	 * individual PAMTs for each page size.
	 */
	tdmr_pamt_base = page_to_pfn(pamt) << PAGE_SHIFT;
	for (pgsz = TDX_PS_4K; pgsz < TDX_PS_NR; pgsz++) {
		pamt_base[pgsz] = tdmr_pamt_base;
		tdmr_pamt_base += pamt_size[pgsz];
	}

	tdmr->pamt_4k_base = pamt_base[TDX_PS_4K];
	tdmr->pamt_4k_size = pamt_size[TDX_PS_4K];
	tdmr->pamt_2m_base = pamt_base[TDX_PS_2M];
	tdmr->pamt_2m_size = pamt_size[TDX_PS_2M];
	tdmr->pamt_1g_base = pamt_base[TDX_PS_1G];
	tdmr->pamt_1g_size = pamt_size[TDX_PS_1G];

	return 0;
}

static void tdmr_get_pamt(struct tdmr_info *tdmr, unsigned long *pamt_base,
			  unsigned long *pamt_size)
{
	unsigned long pamt_bs, pamt_sz;

	/*
	 * The PAMT was allocated in one contiguous unit.  The 4K PAMT
	 * should always point to the beginning of that allocation.
	 */
	pamt_bs = tdmr->pamt_4k_base;
	pamt_sz = tdmr->pamt_4k_size + tdmr->pamt_2m_size + tdmr->pamt_1g_size;

	WARN_ON_ONCE((pamt_bs & ~PAGE_MASK) || (pamt_sz & ~PAGE_MASK));

	*pamt_base = pamt_bs;
	*pamt_size = pamt_sz;
}

static void tdmr_do_pamt_func(struct tdmr_info *tdmr,
		void (*pamt_func)(unsigned long base, unsigned long size))
{
	unsigned long pamt_base, pamt_size;

	tdmr_get_pamt(tdmr, &pamt_base, &pamt_size);

	/* Do nothing if PAMT hasn't been allocated for this TDMR */
	if (!pamt_size)
		return;

	if (WARN_ON_ONCE(!pamt_base))
		return;

	(*pamt_func)(pamt_base, pamt_size);
}

static void free_pamt(unsigned long pamt_base, unsigned long pamt_size)
{
	free_contig_range(pamt_base >> PAGE_SHIFT, pamt_size >> PAGE_SHIFT);
}

static void tdmr_free_pamt(struct tdmr_info *tdmr)
{
	tdmr_do_pamt_func(tdmr, free_pamt);
}

static void tdmrs_free_pamt_all(struct tdmr_info_list *tdmr_list)
{
	int i;

	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++)
		tdmr_free_pamt(tdmr_entry(tdmr_list, i));
}

/* Allocate and set up PAMTs for all TDMRs */
static int tdmrs_set_up_pamt_all(struct tdmr_info_list *tdmr_list,
				 struct list_head *tmb_list,
				 u16 pamt_entry_size)
{
	int i, ret = 0;

	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++) {
		ret = tdmr_set_up_pamt(tdmr_entry(tdmr_list, i), tmb_list,
				pamt_entry_size);
		if (ret)
			goto err;
	}

	return 0;
err:
	tdmrs_free_pamt_all(tdmr_list);
	return ret;
}

/*
 * Convert TDX private pages back to normal by using MOVDIR64B to
 * clear these pages.  Note this function doesn't flush cache of
 * these TDX private pages.  The caller should make sure of that.
 */
static void reset_tdx_pages(unsigned long base, unsigned long size)
{
	const void *zero_page = (const void *)page_address(ZERO_PAGE(0));
	unsigned long phys, end;

	end = base + size;
	for (phys = base; phys < end; phys += 64)
		movdir64b(__va(phys), zero_page);

	/*
	 * MOVDIR64B uses WC protocol.  Use memory barrier to
	 * make sure any later user of these pages sees the
	 * updated data.
	 */
	mb();
}

static void tdmr_reset_pamt(struct tdmr_info *tdmr)
{
	tdmr_do_pamt_func(tdmr, reset_tdx_pages);
}

static void tdmrs_reset_pamt_all(struct tdmr_info_list *tdmr_list)
{
	int i;

	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++)
		tdmr_reset_pamt(tdmr_entry(tdmr_list, i));
}

static unsigned long tdmrs_count_pamt_kb(struct tdmr_info_list *tdmr_list)
{
	unsigned long pamt_size = 0;
	int i;

	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++) {
		unsigned long base, size;

		tdmr_get_pamt(tdmr_entry(tdmr_list, i), &base, &size);
		pamt_size += size;
	}

	return pamt_size / 1024;
}

static int tdmr_add_rsvd_area(struct tdmr_info *tdmr, int *p_idx, u64 addr,
			      u64 size, u16 max_reserved_per_tdmr)
{
	struct tdmr_reserved_area *rsvd_areas = tdmr->reserved_areas;
	int idx = *p_idx;

	/* Reserved area must be 4K aligned in offset and size */
	if (WARN_ON(addr & ~PAGE_MASK || size & ~PAGE_MASK))
		return -EINVAL;

	if (idx >= max_reserved_per_tdmr) {
		pr_warn("initialization failed: TDMR [0x%llx, 0x%llx): reserved areas exhausted.\n",
				tdmr->base, tdmr_end(tdmr));
		return -ENOSPC;
	}

	/*
	 * Consume one reserved area per call.  Make no effort to
	 * optimize or reduce the number of reserved areas which are
	 * consumed by contiguous reserved areas, for instance.
	 */
	rsvd_areas[idx].offset = addr - tdmr->base;
	rsvd_areas[idx].size = size;

	*p_idx = idx + 1;

	return 0;
}

/*
 * Go through @tmb_list to find holes between memory areas.  If any of
 * those holes fall within @tdmr, set up a TDMR reserved area to cover
 * the hole.
 */
static int tdmr_populate_rsvd_holes(struct list_head *tmb_list,
				    struct tdmr_info *tdmr,
				    int *rsvd_idx,
				    u16 max_reserved_per_tdmr)
{
	struct tdx_memblock *tmb;
	u64 prev_end;
	int ret;

	/*
	 * Start looking for reserved blocks at the
	 * beginning of the TDMR.
	 */
	prev_end = tdmr->base;
	list_for_each_entry(tmb, tmb_list, list) {
		u64 start, end;

		start = PFN_PHYS(tmb->start_pfn);
		end   = PFN_PHYS(tmb->end_pfn);

		/* Break if this region is after the TDMR */
		if (start >= tdmr_end(tdmr))
			break;

		/* Exclude regions before this TDMR */
		if (end < tdmr->base)
			continue;

		/*
		 * Skip over memory areas that
		 * have already been dealt with.
		 */
		if (start <= prev_end) {
			prev_end = end;
			continue;
		}

		/* Add the hole before this region */
		ret = tdmr_add_rsvd_area(tdmr, rsvd_idx, prev_end,
				start - prev_end,
				max_reserved_per_tdmr);
		if (ret)
			return ret;

		prev_end = end;
	}

	/* Add the hole after the last region if it exists. */
	if (prev_end < tdmr_end(tdmr)) {
		ret = tdmr_add_rsvd_area(tdmr, rsvd_idx, prev_end,
				tdmr_end(tdmr) - prev_end,
				max_reserved_per_tdmr);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Go through @tdmr_list to find all PAMTs.  If any of those PAMTs
 * overlaps with @tdmr, set up a TDMR reserved area to cover the
 * overlapping part.
 */
static int tdmr_populate_rsvd_pamts(struct tdmr_info_list *tdmr_list,
				    struct tdmr_info *tdmr,
				    int *rsvd_idx,
				    u16 max_reserved_per_tdmr)
{
	int i, ret;

	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++) {
		struct tdmr_info *tmp = tdmr_entry(tdmr_list, i);
		unsigned long pamt_base, pamt_size, pamt_end;

		tdmr_get_pamt(tmp, &pamt_base, &pamt_size);
		/* Each TDMR must already have PAMT allocated */
		WARN_ON_ONCE(!pamt_size|| !pamt_base);

		pamt_end = pamt_base + pamt_size;
		/* Skip PAMTs outside of the given TDMR */
		if ((pamt_end <= tdmr->base) ||
				(pamt_base >= tdmr_end(tdmr)))
			continue;

		/* Only mark the part within the TDMR as reserved */
		if (pamt_base < tdmr->base)
			pamt_base = tdmr->base;
		if (pamt_end > tdmr_end(tdmr))
			pamt_end = tdmr_end(tdmr);

		ret = tdmr_add_rsvd_area(tdmr, rsvd_idx, pamt_base,
				pamt_end - pamt_base,
				max_reserved_per_tdmr);
		if (ret)
			return ret;
	}

	return 0;
}

/* Compare function called by sort() for TDMR reserved areas */
static int rsvd_area_cmp_func(const void *a, const void *b)
{
	struct tdmr_reserved_area *r1 = (struct tdmr_reserved_area *)a;
	struct tdmr_reserved_area *r2 = (struct tdmr_reserved_area *)b;

	if (r1->offset + r1->size <= r2->offset)
		return -1;
	if (r1->offset >= r2->offset + r2->size)
		return 1;

	/* Reserved areas cannot overlap.  The caller must guarantee. */
	WARN_ON_ONCE(1);
	return -1;
}

/*
 * Populate reserved areas for the given @tdmr, including memory holes
 * (via @tmb_list) and PAMTs (via @tdmr_list).
 */
static int tdmr_populate_rsvd_areas(struct tdmr_info *tdmr,
				    struct list_head *tmb_list,
				    struct tdmr_info_list *tdmr_list,
				    u16 max_reserved_per_tdmr)
{
	int ret, rsvd_idx = 0;

	ret = tdmr_populate_rsvd_holes(tmb_list, tdmr, &rsvd_idx,
			max_reserved_per_tdmr);
	if (ret)
		return ret;

	ret = tdmr_populate_rsvd_pamts(tdmr_list, tdmr, &rsvd_idx,
			max_reserved_per_tdmr);
	if (ret)
		return ret;

	/* TDX requires reserved areas listed in address ascending order */
	sort(tdmr->reserved_areas, rsvd_idx, sizeof(struct tdmr_reserved_area),
			rsvd_area_cmp_func, NULL);

	return 0;
}

/*
 * Populate reserved areas for all TDMRs in @tdmr_list, including memory
 * holes (via @tmb_list) and PAMTs.
 */
static int tdmrs_populate_rsvd_areas_all(struct tdmr_info_list *tdmr_list,
					 struct list_head *tmb_list,
					 u16 max_reserved_per_tdmr)
{
	int i;

	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++) {
		int ret;

		ret = tdmr_populate_rsvd_areas(tdmr_entry(tdmr_list, i),
				tmb_list, tdmr_list, max_reserved_per_tdmr);
		if (ret)
			return ret;
	}

	return 0;
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
	int ret;

	ret = fill_out_tdmrs(tmb_list, tdmr_list);
	if (ret)
		return ret;

	ret = tdmrs_set_up_pamt_all(tdmr_list, tmb_list,
			sysinfo->pamt_entry_size);
	if (ret)
		return ret;

	ret = tdmrs_populate_rsvd_areas_all(tdmr_list, tmb_list,
			sysinfo->max_reserved_per_tdmr);
	if (ret)
		tdmrs_free_pamt_all(tdmr_list);

	return ret;
}

static int config_tdx_module(struct tdmr_info_list *tdmr_list, u64 global_keyid)
{
	u64 *tdmr_pa_array;
	size_t array_sz;
	int i, ret;

	/*
	 * TDMRs are passed to the TDX module via an array of physical
	 * addresses of each TDMR.  The array itself also has certain
	 * alignment requirement.
	 */
	array_sz = tdmr_list->nr_consumed_tdmrs * sizeof(u64);
	array_sz = roundup_pow_of_two(array_sz);
	if (array_sz < TDMR_INFO_PA_ARRAY_ALIGNMENT)
		array_sz = TDMR_INFO_PA_ARRAY_ALIGNMENT;

	tdmr_pa_array = kzalloc(array_sz, GFP_KERNEL);
	if (!tdmr_pa_array)
		return -ENOMEM;

	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++)
		tdmr_pa_array[i] = __pa(tdmr_entry(tdmr_list, i));

	ret = seamcall(TDH_SYS_CONFIG, __pa(tdmr_pa_array),
				tdmr_list->nr_consumed_tdmrs,
				global_keyid, 0, NULL, NULL);

	/* Free the array as it is not required anymore. */
	kfree(tdmr_pa_array);

	return ret;
}

static int do_global_key_config(void *data)
{
	/*
	 * TDH.SYS.KEY.CONFIG may fail with entropy error (which is a
	 * recoverable error).  Assume this is exceedingly rare and
	 * just return error if encountered instead of retrying.
	 *
	 * All '0's are just unused parameters.
	 */
	return seamcall(TDH_SYS_KEY_CONFIG, 0, 0, 0, 0, NULL, NULL);
}

/*
 * Attempt to configure the global KeyID on all physical packages.
 *
 * This requires running code on at least one CPU in each package.  If a
 * package has no online CPUs, that code will not run and TDX module
 * initialization (TDMR initialization) will fail.
 *
 * This code takes no affirmative steps to online CPUs.  Callers (aka.
 * KVM) can ensure success by ensuring sufficient CPUs are online for
 * this to succeed.
 */
static int config_global_keyid(void)
{
	cpumask_var_t packages;
	int cpu, ret = -EINVAL;

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL))
		return -ENOMEM;

	for_each_online_cpu(cpu) {
		if (cpumask_test_and_set_cpu(topology_physical_package_id(cpu),
					packages))
			continue;

		/*
		 * TDH.SYS.KEY.CONFIG cannot run concurrently on
		 * different cpus, so just do it one by one.
		 */
		ret = smp_call_on_cpu(cpu, do_global_key_config, NULL, true);
		if (ret)
			break;
	}

	free_cpumask_var(packages);
	return ret;
}

static int init_tdmr(struct tdmr_info *tdmr)
{
	u64 next;

	/*
	 * Initializing a TDMR can be time consuming.  To avoid long
	 * SEAMCALLs, the TDX module may only initialize a part of the
	 * TDMR in each call.
	 */
	do {
		struct tdx_module_output out;
		int ret;

		/* All 0's are unused parameters, they mean nothing. */
		ret = seamcall(TDH_SYS_TDMR_INIT, tdmr->base, 0, 0, 0, NULL,
				&out);
		if (ret)
			return ret;
		/*
		 * RDX contains 'next-to-initialize' address if
		 * TDH.SYS.TDMR.INIT did not fully complete and
		 * should be retried.
		 */
		next = out.rdx;
		cond_resched();
		/* Keep making SEAMCALLs until the TDMR is done */
	} while (next < tdmr->base + tdmr->size);

	return 0;
}

static int init_tdmrs(struct tdmr_info_list *tdmr_list)
{
	int i;

	/*
	 * This operation is costly.  It can be parallelized,
	 * but keep it simple for now.
	 */
	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++) {
		int ret;

		ret = init_tdmr(tdmr_entry(tdmr_list, i));
		if (ret)
			return ret;
	}

	return 0;
}

static int init_tdx_module(void)
{
	struct cmr_info *cmr_array;
	int ret;

	/*
	 * Get the TDSYSINFO_STRUCT and CMRs from the TDX module.
	 *
	 * The buffers of the TDSYSINFO_STRUCT and the CMR array passed
	 * to the TDX module must be 1024-bytes and 512-bytes aligned
	 * respectively.  Allocate one page to accommodate them both and
	 * also meet those alignment requirements.
	 */
	sysinfo = (struct tdsysinfo_struct *)__get_free_page(GFP_KERNEL);
	if (!sysinfo)
		return -ENOMEM;
	cmr_array = (struct cmr_info *)((unsigned long)sysinfo + PAGE_SIZE / 2);

	BUILD_BUG_ON(PAGE_SIZE / 2 < TDSYSINFO_STRUCT_SIZE);
	BUILD_BUG_ON(PAGE_SIZE / 2 < sizeof(struct cmr_info) * MAX_CMRS);

	ret = __tdx_get_sysinfo(sysinfo, cmr_array);
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
	ret = alloc_tdmr_list(&tdx_tdmr_list, sysinfo);
	if (ret)
		goto out_free_tdxmem;

	/* Cover all TDX-usable memory regions in TDMRs */
	ret = construct_tdmrs(&tdx_memlist, &tdx_tdmr_list, sysinfo);
	if (ret)
		goto out_free_tdmrs;

	/* Pass the TDMRs and the global KeyID to the TDX module */
	ret = config_tdx_module(&tdx_tdmr_list, tdx_global_keyid);
	if (ret)
		goto out_free_pamts;

	/*
	 * Hardware doesn't guarantee cache coherency across different
	 * KeyIDs.  The kernel needs to flush PAMT's dirty cachelines
	 * (associated with KeyID 0) before the TDX module can use the
	 * global KeyID to access the PAMT.  Given PAMTs are potentially
	 * large (~1/256th of system RAM), just use WBINVD on all cpus
	 * to flush the cache.
	 */
	wbinvd_on_all_cpus();

	/*
	 * Starting from this point the system may have TDX private
	 * memory.  Make it globally visible so tdx_reset_memory() only
	 * reads TDMRs/PAMTs when they are stable.
	 *
	 * Note using atomic_inc_return() to provide the explicit memory
	 * ordering isn't mandatory here as the WBINVD above already
	 * does that.  Compiler barrier isn't needed here either.
	 */
	atomic_inc_return(&tdx_may_has_private_mem);

	/* Config the key of global KeyID on all packages */
	ret = config_global_keyid();
	if (ret)
		goto out_reset_pamts;

	/* Initialize TDMRs to complete the TDX module initialization */
	ret = init_tdmrs(&tdx_tdmr_list);
	if (ret)
		goto out_reset_pamts;

	pr_info("%lu KBs allocated for PAMT.\n",
			tdmrs_count_pamt_kb(&tdx_tdmr_list));

	/*
	 * @tdx_memlist is written here and read at memory hotplug time.
	 * Lock out memory hotplug code while building it.
	 */
	put_online_mems();

	return 0;
out_reset_pamts:
	/*
	 * Part of PAMTs may already have been initialized by the
	 * TDX module.  Flush cache before returning PAMTs back
	 * to the kernel.
	 */
	wbinvd_on_all_cpus();
	/*
	 * According to the TDX hardware spec, if the platform
	 * doesn't have the "partial write machine check"
	 * erratum, any kernel read/write will never cause #MC
	 * in kernel space, thus it's OK to not convert PAMTs
	 * back to normal.  But do the conversion anyway here
	 * as suggested by the TDX spec.
	 */
	tdmrs_reset_pamt_all(&tdx_tdmr_list);
	/*
	 * No more TDX private pages now, and PAMTs/TDMRs are
	 * going to be freed.  Make this globally visible so
	 * tdx_reset_memory() can read stable TDMRs/PAMTs.
	 *
	 * Note atomic_dec_return(), which is an atomic RMW with
	 * return value, always enforces the memory barrier.
	 */
	atomic_dec_return(&tdx_may_has_private_mem);
out_free_pamts:
	tdmrs_free_pamt_all(&tdx_tdmr_list);
out_free_tdmrs:
	free_tdmr_list(&tdx_tdmr_list);
out_free_tdxmem:
	free_tdx_memlist(&tdx_memlist);
out_put_tdxmem:
	put_online_mems();
out:
	free_page((unsigned long)sysinfo);
	sysinfo = NULL;
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
 * This function requires there's at least one online cpu for each CPU
 * package to succeed.
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

/*
 * Convert TDX private pages back to normal on platforms with
 * "partial write machine check" erratum.
 *
 * Called from machine_kexec() before booting to the new kernel.
 */
void tdx_reset_memory(void)
{
	if (!platform_tdx_enabled())
		return;

	/*
	 * Kernel read/write to TDX private memory doesn't
	 * cause machine check on hardware w/o this erratum.
	 */
	if (!boot_cpu_has_bug(X86_BUG_TDX_PW_MCE))
		return;

	/* Called from kexec() when only rebooting cpu is alive */
	WARN_ON_ONCE(num_online_cpus() != 1);

	if (!atomic_read(&tdx_may_has_private_mem))
		return;

	/*
	 * Ideally it's better to cover all types of TDX private pages,
	 * but there's no existing infrastructure to tell whether a page
	 * is TDX private memory or not.  Using SEAMCALL to query TDX
	 * module isn't feasible either because: 1) VMX has been turned
	 * off by reaching here so SEAMCALL cannot be made; 2) Even
	 * SEAMCALL can be made the result from TDX module may not be
	 * accurate (e.g., remote CPU can be stopped while the kernel
	 * is in the middle of reclaiming one TDX private page and doing
	 * MOVDIR64B).
	 *
	 * One solution could be just converting all memory pages, but
	 * this may bring non-trivial latency on large memory systems
	 * (especially when the number of TDX private pages is small).
	 * So even with this temporary solution, eventually the kernel
	 * should only convert TDX private pages.
	 *
	 * Also, not all pages are mapped as writable in direct mapping,
	 * thus it's problematic to do so.  It can be done by switching
	 * to the identical mapping table for kexec() or a new page table
	 * which maps all pages as writable, but the complexity looks
	 * overkill.
	 *
	 * Thus instead of doing something dramatic to convert all pages,
	 * only convert PAMTs as for now TDX private pages can only be
	 * PAMT.
	 *
	 * All other cpus are already dead.  TDMRs/PAMTs are stable when
	 * @tdx_may_has_private_mem reads true.
	 */
	tdmrs_reset_pamt_all(&tdx_tdmr_list);
}

static bool is_pamt_page(unsigned long phys)
{
	struct tdmr_info_list *tdmr_list = &tdx_tdmr_list;
	int i;

	/*
	 * This function is called from #MC handler, and theoretically
	 * it could run in parallel with the TDX module initialization
	 * on other logical cpus.  But it's not OK to hold mutex here
	 * so just blindly check module status to make sure PAMTs/TDMRs
	 * are stable to access.
	 *
	 * This may return inaccurate result in rare cases, e.g., when
	 * #MC happens on a PAMT page during module initialization, but
	 * this is fine as #MC handler doesn't need a 100% accurate
	 * result.
	 */
	if (tdx_module_status != TDX_MODULE_INITIALIZED)
		return false;

	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++) {
		unsigned long base, size;

		tdmr_get_pamt(tdmr_entry(tdmr_list, i), &base, &size);

		if (phys >= base && phys < (base + size))
			return true;
	}

	return false;
}

/*
 * Return whether the memory page at the given physical address is TDX
 * private memory or not.  Called from #MC handler do_machine_check().
 *
 * Note this function may not return an accurate result in rare cases.
 * This is fine as the #MC handler doesn't need a 100% accurate result,
 * because it cannot distinguish #MC between software bug and real
 * hardware error anyway.
 */
bool tdx_is_private_mem(unsigned long phys)
{
	struct tdx_module_output out;
	u64 sret;

	if (!platform_tdx_enabled())
		return false;

	/* Get page type from the TDX module */
	sret = __seamcall(TDH_PHYMEM_PAGE_RDMD, phys & PAGE_MASK,
			0, 0, 0, &out);
	/*
	 * Handle the case that CPU isn't in VMX operation.
	 *
	 * KVM guarantees no VM is running (thus no TDX guest)
	 * when there's any online CPU isn't in VMX operation.
	 * This means there will be no TDX guest private memory
	 * and Secure-EPT pages.  However the TDX module may have
	 * been initialized and the memory page could be PAMT.
	 */
	if (sret == TDX_SEAMCALL_UD)
		return is_pamt_page(phys);

	/*
	 * Any other failure means:
	 *
	 * 1) TDX module not loaded; or
	 * 2) Memory page isn't managed by the TDX module.
	 *
	 * In either case, the memory page cannot be a TDX
	 * private page.
	 */
	if (sret)
		return false;

	/*
	 * SEAMCALL was successful -- read page type (via RCX):
	 *
	 *  - PT_NDA:	Page is not used by the TDX module
	 *  - PT_RSVD:	Reserved for Non-TDX use
	 *  - Others:	Page is used by the TDX module
	 *
	 * Note PAMT pages are marked as PT_RSVD but they are also TDX
	 * private memory.
	 *
	 * Note: Even page type is PT_NDA, the memory page could still
	 * be associated with TDX private KeyID if the kernel hasn't
	 * explicitly used MOVDIR64B to clear the page.  Assume KVM
	 * always does that after reclaiming any private page from TDX
	 * gusets.
	 */
	switch (out.rcx) {
	case PT_NDA:
		return false;
	case PT_RSVD:
		return is_pamt_page(phys);
	default:
		return true;
	}
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
	return is_tdx_memory(mn->start_pfn, mn->start_pfn + mn->nr_pages) ?
		NOTIFY_OK : NOTIFY_BAD;
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

#ifdef CONFIG_SYSFS

static struct kobject *tdx_kobj;
static struct kobject *tdx_module_kobj;
static struct kobject *tdx_metadata_kobj;

static ssize_t tdx_nr_guest_keyids_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%08x", tdx_nr_guest_keyids);
}

static struct kobj_attribute tdx_nr_guest_keyids_attr = {
	.attr = {
		.name = "nr_guest_keyids",
		.mode = 0444
	},
	.show = tdx_nr_guest_keyids_show,
};

static ssize_t tdx_module_status_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	static const char * const names[] = {
		[TDX_MODULE_UNKNOWN] = "unknown",
		[TDX_MODULE_INITIALIZED] = "initialized",
		[TDX_MODULE_ERROR] = "error",
	};
	const char *status = "unknown";

	mutex_lock(&tdx_module_lock);
	if (tdx_module_status < ARRAY_SIZE(names))
		status = names[tdx_module_status];
	mutex_unlock(&tdx_module_lock);

	return sprintf(buf, "%s", status);
}

static struct kobj_attribute tdx_module_status_attr = {
	.attr = {
		.name = "status",
		.mode = 0444
	},
	.show = tdx_module_status_show,
};

#define TDX_METADATA_ATTR(_name, field_id_name, _size)		\
static struct bin_attribute tdx_metadata_ ## _name = {		\
	.attr = {						\
		.name = field_id_name,				\
		.mode = 0444,					\
	},							\
	.size = _size,						\
	.read = tdx_metadata_ ## _name ## _show,		\
}

#define TDX_METADATA_ATTR_SHOW(_name, field_id_name)					\
static ssize_t tdx_metadata_ ## _name ## _show(struct file *filp, struct kobject *kobj,	\
					       struct bin_attribute *bin_attr,		\
					       char *buf, loff_t offset, size_t count)	\
{											\
	return memory_read_from_buffer(buf, count, &offset,				\
				       &sysinfo->_name,					\
				       sizeof(sysinfo->_name));				\
}											\
TDX_METADATA_ATTR(_name, field_id_name, sizeof_field(struct tdsysinfo_struct, _name))

TDX_METADATA_ATTR_SHOW(attributes_fixed0, TDX_METADATA_ATTRIBUTES_FIXED0_NAME);
TDX_METADATA_ATTR_SHOW(attributes_fixed1, TDX_METADATA_ATTRIBUTES_FIXED1_NAME);
TDX_METADATA_ATTR_SHOW(xfam_fixed0, TDX_METADATA_XFAM_FIXED0_NAME);
TDX_METADATA_ATTR_SHOW(xfam_fixed1, TDX_METADATA_XFAM_FIXED1_NAME);

static ssize_t tdx_metadata_num_cpuid_config_show(struct file *filp, struct kobject *kobj,
						  struct bin_attribute *bin_attr,
						  char *buf, loff_t offset, size_t count)
{
	/*
	 * Although tdsysinfo_struct.num_cpuid_config is defined as u32 for
	 * alignment, TDX 1.5 defines metadata NUM_CONFIG_CPUID as u16.
	 */
	u16 tmp = (u16)sysinfo->num_cpuid_config;

	WARN_ON_ONCE(tmp != sysinfo->num_cpuid_config);
	return memory_read_from_buffer(buf, count, &offset, &tmp, sizeof(tmp));
}
TDX_METADATA_ATTR(num_cpuid_config, TDX_METADATA_NUM_CPUID_CONFIG_NAME, sizeof(u16));

static ssize_t tdx_metadata_cpuid_leaves_show(struct file *filp, struct kobject *kobj,
					      struct bin_attribute *bin_attr, char *buf,
					      loff_t offset, size_t count)
{
	ssize_t r;
	struct tdx_cpuid_config_leaf *tmp;
	u32 i;

	tmp = kmalloc(bin_attr->size, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	for (i = 0; i < sysinfo->num_cpuid_config; i++) {
		struct tdx_cpuid_config *c = &sysinfo->cpuid_configs[i];
		struct tdx_cpuid_config_leaf *leaf = (struct tdx_cpuid_config_leaf *)c;

		memcpy(tmp + i, leaf, sizeof(*leaf));
	}

	r = memory_read_from_buffer(buf, count, &offset, tmp, bin_attr->size);
	kfree(tmp);
	return r;
}

TDX_METADATA_ATTR(cpuid_leaves, TDX_METADATA_CPUID_LEAVES_NAME, 0);

static ssize_t tdx_metadata_cpuid_values_show(struct file *filp, struct kobject *kobj,
					      struct bin_attribute *bin_attr, char *buf,
					      loff_t offset, size_t count)
{
	struct tdx_cpuid_config_value *tmp;
	ssize_t r;
	u32 i;

	tmp = kmalloc(bin_attr->size, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	for (i = 0; i < sysinfo->num_cpuid_config; i++) {
		struct tdx_cpuid_config *c = &sysinfo->cpuid_configs[i];
		struct tdx_cpuid_config_value *value = (struct tdx_cpuid_config_value *)&c->eax;

		memcpy(tmp + i, value, sizeof(*value));
	}

	r = memory_read_from_buffer(buf, count, &offset, tmp, bin_attr->size);
	kfree(tmp);
	return r;
}

TDX_METADATA_ATTR(cpuid_values, TDX_METADATA_CPUID_VALUES_NAME, 0);

static struct bin_attribute *tdx_metadata_attrs[] = {
	&tdx_metadata_attributes_fixed0,
	&tdx_metadata_attributes_fixed1,
	&tdx_metadata_xfam_fixed0,
	&tdx_metadata_xfam_fixed1,
	&tdx_metadata_num_cpuid_config,
	&tdx_metadata_cpuid_leaves,
	&tdx_metadata_cpuid_values,
	NULL,
};

static const struct attribute_group tdx_metadata_attr_group = {
	.bin_attrs = tdx_metadata_attrs,
};

#define TDX_MODULE_ATTR_SHOW(_name, fmt)				\
static ssize_t tdx_module_ ## _name ## _show(				\
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)	\
{									\
	return sprintf(buf, fmt, sysinfo->_name);			\
}									\
static struct kobj_attribute tdx_module_##_name = {			\
	.attr = { .name = __stringify(_name), .mode = 0444 },		\
	.show = tdx_module_ ## _name ## _show,				\
}

TDX_MODULE_ATTR_SHOW(attributes, "0x%08x");
TDX_MODULE_ATTR_SHOW(vendor_id, "0x%08x");
TDX_MODULE_ATTR_SHOW(build_date, "%d");
TDX_MODULE_ATTR_SHOW(build_num, "0x%08x");
TDX_MODULE_ATTR_SHOW(minor_version, "0x%08x");
TDX_MODULE_ATTR_SHOW(major_version, "0x%08x");

static struct attribute *tdx_module_attrs[] = {
	&tdx_module_attributes.attr,
	&tdx_module_vendor_id.attr,
	&tdx_module_build_date.attr,
	&tdx_module_build_num.attr,
	&tdx_module_minor_version.attr,
	&tdx_module_major_version.attr,
	NULL,
};

static const struct attribute_group tdx_module_attr_group = {
	.attrs = tdx_module_attrs,
};

static int tdx_sysfs_init(void)
{
	int ret;

	if (!sysinfo)
		return 0;

	tdx_kobj = kobject_create_and_add("tdx", firmware_kobj);
	if (!tdx_kobj) {
		pr_err("kobject_create_and_add tdx failed\n");
		return -EINVAL;
	}

	ret = sysfs_create_file(tdx_kobj, &tdx_nr_guest_keyids_attr.attr);
	if (ret) {
		pr_err("Sysfs exporting seam nr_keyids failed %d\n", ret);
		return ret;
	}

	tdx_module_kobj = kobject_create_and_add("tdx_module", tdx_kobj);
	if (!tdx_module_kobj) {
		pr_err("kobject_create_and_add tdx_module failed\n");
		return -EINVAL;
	}

	ret = sysfs_create_file(tdx_module_kobj, &tdx_module_status_attr.attr);
	if (ret) {
		pr_err("Sysfs exporting tdx module status failed %d\n", ret);
		return ret;
	}

	tdx_metadata_kobj = kobject_create_and_add("metadata", tdx_module_kobj);
	if (!tdx_metadata_kobj) {
		pr_err("Sysfs exporting tdx global metadata failed %d\n", ret);
		return -EINVAL;
	}

	ret = sysfs_create_group(tdx_module_kobj, &tdx_module_attr_group);
	if (ret) {
		pr_err("Sysfs exporting tdx module attributes failed %d\n", ret);
		return ret;
	}

	tdx_metadata_cpuid_leaves.size = sysinfo->num_cpuid_config *
		sizeof(struct tdx_cpuid_config_leaf);
	tdx_metadata_cpuid_values.size = sysinfo->num_cpuid_config *
		sizeof(struct tdx_cpuid_config_value);
	ret = sysfs_create_group(tdx_metadata_kobj, &tdx_metadata_attr_group);
	if (ret)
		pr_err("Sysfs exporting tdx module attributes failed %d\n", ret);

	return ret;
}
#endif
