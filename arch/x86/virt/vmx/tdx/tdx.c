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
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/archrandom.h>
#include <asm/page.h>
#include <asm/tdx.h>
#include "tdx.h"

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

static int tdx_get_sysinfo(struct tdsysinfo_struct *sysinfo,
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

	pr_info("TDX module: attributes 0x%x, vendor_id 0x%x, major_version %u, minor_version %u, build_date %u, build_num %u",
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

static void tdmr_free_pamt(struct tdmr_info *tdmr)
{
	unsigned long pamt_base, pamt_size;

	tdmr_get_pamt(tdmr, &pamt_base, &pamt_size);

	/* Do nothing if PAMT hasn't been allocated for this TDMR */
	if (!pamt_size)
		return;

	if (WARN_ON_ONCE(!pamt_base))
		return;

	free_contig_range(pamt_base >> PAGE_SHIFT, pamt_size >> PAGE_SHIFT);
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
	/*
	 * TODO:
	 *
	 *  - Designate reserved areas for each TDMR.
	 *
	 * Return -EINVAL until constructing TDMRs is done
	 */
	return -EINVAL;
}

static int init_tdx_module(void)
{
	struct tdsysinfo_struct *sysinfo;
	struct tdmr_info_list tdmr_list;
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

	ret = tdx_get_sysinfo(sysinfo, cmr_array);
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
	ret = alloc_tdmr_list(&tdmr_list, sysinfo);
	if (ret)
		goto out_free_tdxmem;

	/* Cover all TDX-usable memory regions in TDMRs */
	ret = construct_tdmrs(&tdx_memlist, &tdmr_list, sysinfo);
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
	if (ret)
		tdmrs_free_pamt_all(&tdmr_list);
	else
		pr_info("%lu KBs allocated for PAMT.\n",
				tdmrs_count_pamt_kb(&tdmr_list));
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
	free_page((unsigned long)sysinfo);
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
