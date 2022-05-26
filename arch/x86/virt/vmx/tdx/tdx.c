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
#include <linux/mutex.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
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
#include <asm/page.h>
#include <asm/tdx.h>
#include "tdx.h"

static u32 tdx_global_keyid __ro_after_init;
static u32 tdx_guest_keyid_start __ro_after_init;
static u32 tdx_nr_guest_keyids __ro_after_init;

static enum tdx_module_status_t tdx_module_status;
/* Prevent concurrent attempts on TDX module initialization */
static DEFINE_MUTEX(tdx_module_lock);

/* TDX-runnable cpus.  Protected by cpu_hotplug_lock. */
static cpumask_t __cpu_tdx_mask;
static cpumask_t *cpu_tdx_mask = &__cpu_tdx_mask;

/* All TDX-usable memory regions.  Protected by mem_hotplug_lock. */
static LIST_HEAD(tdx_memlist);

/* The list of TDMRs passed to TDX module */
struct tdmr_info_list tdx_tdmr_list;

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

static bool is_tdx_memory(unsigned long start_pfn, unsigned long end_pfn)
{
	struct tdx_memblock *tmb;

	/* Empty list means TDX isn't enabled. */
	if (list_empty(&tdx_memlist))
		return true;

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

	err = register_memory_notifier(&tdx_memory_nb);
	if (err) {
		pr_info("initialization failed: register_memory_notifier() failed (%d)\n",
				err);
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
		/*
		 * tdx_enable() has already checked that BIOS has
		 * enabled TDX at the very beginning before going
		 * forward.  It's likely a firmware bug if the
		 * SEAMCALL still caused #GP.
		 */
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

/*
 * Call @func on all online cpus one by one but skip those cpus
 * when @skip_func is valid and returns true for them.
 */
static int tdx_on_each_cpu_cond(int (*func)(void *), void *func_data,
				bool (*skip_func)(int cpu, void *),
				void *skip_data)
{
	int cpu;

	for_each_online_cpu(cpu) {
		int ret;

		if (skip_func && skip_func(cpu, skip_data))
			continue;

		/*
		 * SEAMCALL can be time consuming.  Call the @func on
		 * remote cpu via smp_call_on_cpu() instead of
		 * smp_call_function_single() to avoid busy waiting.
		 */
		ret = smp_call_on_cpu(cpu, func, func_data, true);
		if (ret)
			return ret;
	}

	return 0;
}

static int seamcall_lp_init(void)
{
	/* All '0's are just unused parameters */
	return seamcall(TDH_SYS_LP_INIT, 0, 0, 0, 0, NULL, NULL);
}

static int smp_func_module_lp_init(void *data)
{
	int ret, cpu = smp_processor_id();

	ret = seamcall_lp_init();
	if (!ret)
		cpumask_set_cpu(cpu, cpu_tdx_mask);

	return ret;
}

static bool skip_func_module_lp_init_done(int cpu, void *data)
{
	return cpumask_test_cpu(cpu, cpu_tdx_mask);
}

static int module_lp_init_online_cpus(void)
{
	return tdx_on_each_cpu_cond(smp_func_module_lp_init, NULL,
			skip_func_module_lp_init_done, NULL);
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
 * CMRs, and save them to @sysinfo and @cmr_array.  @sysinfo must have
 * been padded to have enough room to save the TDSYSINFO_STRUCT.
 */
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

#define TDMR_ALIGNMENT		BIT_ULL(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)
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
	 * In practice TDX1.0 supports 64 TDMRs, which is big enough to
	 * cover all memory regions in reality if the admin doesn't use
	 * 'memmap' to create a bunch of discrete memory regions.  When
	 * there's a real problem, enhancement can be done to merge TDMRs
	 * to reduce the final number of TDMRs.
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

	/* @tdmr_idx is always the index of last valid TDMR. */
	tdmr_list->nr_consumed_tdmrs = tdmr_idx + 1;

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

#define TDX_PS_NR	(TDX_PS_1G + 1)

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
	for (pgsz = TDX_PS_4K; pgsz <= TDX_PS_1G ; pgsz++) {
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
	for (pgsz = TDX_PS_4K; pgsz <= TDX_PS_1G; pgsz++) {
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

static void tdmr_get_pamt(struct tdmr_info *tdmr, unsigned long *pamt_pfn,
			  unsigned long *pamt_npages)
{
	unsigned long pamt_base, pamt_sz;

	/*
	 * The PAMT was allocated in one contiguous unit.  The 4K PAMT
	 * should always point to the beginning of that allocation.
	 */
	pamt_base = tdmr->pamt_4k_base;
	pamt_sz = tdmr->pamt_4k_size + tdmr->pamt_2m_size + tdmr->pamt_1g_size;

	*pamt_pfn = PHYS_PFN(pamt_base);
	*pamt_npages = pamt_sz >> PAGE_SHIFT;
}

static void tdmr_free_pamt(struct tdmr_info *tdmr)
{
	unsigned long pamt_pfn, pamt_npages;

	tdmr_get_pamt(tdmr, &pamt_pfn, &pamt_npages);

	/* Do nothing if PAMT hasn't been allocated for this TDMR */
	if (!pamt_npages)
		return;

	if (WARN_ON_ONCE(!pamt_pfn))
		return;

	free_contig_range(pamt_pfn, pamt_npages);
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

static unsigned long tdmrs_count_pamt_pages(struct tdmr_info_list *tdmr_list)
{
	unsigned long pamt_npages = 0;
	int i;

	for (i = 0; i < tdmr_list->nr_consumed_tdmrs; i++) {
		unsigned long pfn, npages;

		tdmr_get_pamt(tdmr_entry(tdmr_list, i), &pfn, &npages);
		pamt_npages += npages;
	}

	return pamt_npages;
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
	static DECLARE_PADDED_STRUCT(tdsysinfo_struct, tdsysinfo,
			TDSYSINFO_STRUCT_SIZE, TDSYSINFO_STRUCT_ALIGNMENT);
	static struct cmr_info cmr_array[MAX_CMRS]
			__aligned(CMR_INFO_ARRAY_ALIGNMENT);
	struct tdsysinfo_struct *sysinfo = &PADDED_STRUCT(tdsysinfo);
	int ret;

	/*
	 * TDX module global initialization.  All '0's are just
	 * unused parameters.
	 */
	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL, NULL);
	if (ret)
		return ret;

	/*
	 * TDX module per-cpu initialization SEAMCALL must be done on
	 * one cpu before any other SEAMCALLs can be made on that cpu,
	 * including those involved in further steps to initialize the
	 * TDX module.
	 *
	 * To make sure further SEAMCALLs can be done successfully w/o
	 * having to consider preemption, disable CPU hotplug during
	 * rest of module initialization and do per-cpu initialization
	 * for all online cpus.
	 */
	cpus_read_lock();

	ret = module_lp_init_online_cpus();
	if (ret)
		goto out;

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
		goto out;

	/* Allocate enough space for constructing TDMRs */
	ret = alloc_tdmr_list(&tdx_tdmr_list, sysinfo);
	if (ret)
		goto out_free_tdx_mem;

	/* Cover all TDX-usable memory regions in TDMRs */
	ret = construct_tdmrs(&tdx_memlist, &tdx_tdmr_list, sysinfo);
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
		tdmrs_free_pamt_all(&tdx_tdmr_list);
	else
		pr_info("%lu KBs allocated for PAMT.\n",
				tdmrs_count_pamt_pages(&tdx_tdmr_list) * 4);
out_free_tdmrs:
	if (ret)
		free_tdmr_list(&tdx_tdmr_list);
out_free_tdx_mem:
	if (ret)
		free_tdx_memlist(&tdx_memlist);
out:
	/*
	 * @tdx_memlist is written here and read at memory hotplug time.
	 * Lock out memory hotplug code while building it.
	 */
	put_online_mems();

	/*
	 * Clear @cpu_tdx_mask if module initialization fails before
	 * CPU hotplug is re-enabled.  tdx_cpu_online() uses it to check
	 * whether the initialization has been successful or not.
	 */
	if (ret)
		cpumask_clear(cpu_tdx_mask);
	cpus_read_unlock();
	return ret;
}

static int __tdx_enable(void)
{
	int ret;

	ret = init_tdx_module();
	if (ret) {
		pr_err("initialization failed (%d)\n", ret);
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

/*
 * Disable TDX module after it has been initialized successfully.
 */
static void disable_tdx_module(void)
{
	/*
	 * TODO: module clean up in reverse to steps in
	 * init_tdx_module().  Remove this comment after
	 * all steps are done.
	 */
	tdmrs_free_pamt_all(&tdx_tdmr_list);
	free_tdmr_list(&tdx_tdmr_list);
	free_tdx_memlist(&tdx_memlist);
	cpumask_clear(cpu_tdx_mask);
}

static int tdx_module_init_online_cpus(void)
{
	int ret;

	/*
	 * Make sure no cpu can become online to prevent
	 * race against tdx_cpu_online().
	 */
	cpus_read_lock();

	/*
	 * Do per-cpu initialization for any new online cpus.
	 * If any fails, disable TDX.
	 */
	ret = module_lp_init_online_cpus();
	if (ret)
		disable_tdx_module();

	cpus_read_unlock();

	return ret;

}
static int __tdx_enable_online_cpus(void)
{
	if (tdx_module_init_online_cpus()) {
		/*
		 * SEAMCALL failure has already printed
		 * meaningful error message.
		 */
		tdx_module_status = TDX_MODULE_ERROR;

		/*
		 * Just return one universal error code.
		 * For now the caller cannot recover anyway.
		 */
		return -EINVAL;
	}

	return 0;
}

/**
 * tdx_enable - Enable TDX to be ready to run TDX guests
 *
 * Initialize the TDX module to enable TDX.  After this function, the TDX
 * module is ready to create and run TDX guests on all online cpus.
 *
 * This function internally calls cpus_read_lock()/unlock() to prevent
 * any cpu from going online and offline.
 *
 * This function assumes all online cpus are already in VMX operation.
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
		/*
		 * The previous call of __tdx_enable() may only have
		 * initialized part of present cpus during module
		 * initialization, and new cpus may have become online
		 * since then.
		 *
		 * To make sure all online cpus are TDX-runnable, always
		 * do per-cpu initialization for all online cpus here
		 * even the module has been initialized.
		 */
		ret = __tdx_enable_online_cpus();
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

/**
 * tdx_cpu_online - Enable TDX on a hotplugged local cpu
 *
 * @cpu: the cpu to be brought up.
 *
 * Do TDX module per-cpu initialization for a hotplugged cpu to make
 * it TDX-runnable.  All online cpus are initialized during module
 * initialization.
 *
 * This function must be called from CPU hotplug callback which holds
 * write lock of cpu_hotplug_lock.
 *
 * This function assumes local cpu is already in VMX operation.
 */
int tdx_cpu_online(unsigned int cpu)
{
	int ret;

	/*
	 * @cpu_tdx_mask is updated in tdx_enable() and is protected
	 * by cpus_read_lock()/unlock().  If it is empty, TDX module
	 * either hasn't been initialized, or TDX didn't get enabled
	 * successfully.
	 *
	 * In either case, do nothing but return success.
	 */
	if (cpumask_empty(cpu_tdx_mask))
		return 0;

	WARN_ON_ONCE(cpu != smp_processor_id());

	/* Already done */
	if (cpumask_test_cpu(cpu, cpu_tdx_mask))
		return 0;

	ret = seamcall_lp_init();
	if (!ret)
		cpumask_set_cpu(cpu, cpu_tdx_mask);

	return ret;
}
EXPORT_SYMBOL_GPL(tdx_cpu_online);
