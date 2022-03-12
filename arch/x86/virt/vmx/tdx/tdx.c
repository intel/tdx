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
#include <linux/align.h>
#include <linux/sort.h>
#include <asm/pgtable_types.h>
#include <asm/msr.h>
#include <asm/cpu.h>
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
	int nid;
};

static u32 tdx_keyid_start __ro_after_init;
static u32 nr_tdx_keyids __ro_after_init;

static enum tdx_module_status_t tdx_module_status;
/* Prevent concurrent attempts on TDX detection and initialization */
static DEFINE_MUTEX(tdx_module_lock);

/* All TDX-usable memory regions */
static LIST_HEAD(tdx_memlist);

/* TDX module global KeyID.  Used in TDH.SYS.CONFIG ABI. */
u32 tdx_global_keyid __read_mostly;
EXPORT_SYMBOL_GPL(tdx_global_keyid);

/* REVERTME: tdx module debug */
/* Non-architectural debug configuration SEAMCALLs. */
#define SEAMCALL_TDDEBUGCONFIG		0xFE

#define DEBUGCONFIG_SET_TRACE_LEVEL	3
#define DEBUGCONFIG_TRACE_ALL		0
#define DEBUGCONFIG_TRACE_WARN		1
#define DEBUGCONFIG_TRACE_ERROR		2
#define DEBUGCONFIG_TRACE_CUSTOM	1000
#define DEBUGCONFIG_TRACE_NONE		-1ULL

static bool trace_boot_seamcalls;

static int __init trace_seamcalls(char *s)
{
	trace_boot_seamcalls = true;
	return 1;
}
__setup("trace_boot_seamcalls", trace_seamcalls);

static u64 tdx_trace_level = DEBUGCONFIG_TRACE_CUSTOM;

static void tdx_trace_seamcalls(u64 level);
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

/* TDX KeyID pool */
static DEFINE_IDA(tdx_keyid_pool);

int tdx_keyid_alloc(void)
{
	if (WARN_ON_ONCE(!tdx_keyid_start || !nr_tdx_keyids))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_keyid_pool, tdx_keyid_start + 1,
			       tdx_keyid_start + nr_tdx_keyids - 1,
			       GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(tdx_keyid_alloc);

void tdx_keyid_free(int keyid)
{
	/* keyid = 0 is reserved. */
	if (WARN_ON_ONCE(keyid <= 0))
		return;

	ida_free(&tdx_keyid_pool, keyid);
}
EXPORT_SYMBOL_GPL(tdx_keyid_free);

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
static int __tdx_get_sysinfo(struct tdsysinfo_struct *sysinfo,
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

static DECLARE_PADDED_STRUCT(tdsysinfo_struct, tdsysinfo,
			     TDSYSINFO_STRUCT_SIZE, TDSYSINFO_STRUCT_ALIGNMENT);

const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	const struct tdsysinfo_struct *r = NULL;

	mutex_lock(&tdx_module_lock);
	if (tdx_module_status == TDX_MODULE_INITIALIZED)
		r = &PADDED_STRUCT(tdsysinfo);
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

struct tdmr_info_list {
	struct tdmr_info *first_tdmr;
	int tdmr_sz;
	int max_tdmrs;
	int nr_tdmrs;	/* Actual number of TDMRs */
};

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

	tdmr_list->first_tdmr = tdmr_array;
	/*
	 * Keep the size of TDMR to find the target TDMR
	 * at a given index in the TDMR list.
	 */
	tdmr_list->tdmr_sz = tdmr_sz;
	tdmr_list->max_tdmrs = sysinfo->max_tdmrs;
	tdmr_list->nr_tdmrs = 0;

	return 0;
}

static void free_tdmr_list(struct tdmr_info_list *tdmr_list)
{
	free_pages_exact(tdmr_list->first_tdmr,
			tdmr_list->max_tdmrs * tdmr_list->tdmr_sz);
}

/* Get the TDMR from the list at the given index. */
static struct tdmr_info *tdmr_entry(struct tdmr_info_list *tdmr_list,
				    int idx)
{
	return (struct tdmr_info *)((unsigned long)tdmr_list->first_tdmr +
			tdmr_list->tdmr_sz * idx);
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
			if (tdmr_idx >= tdmr_list->max_tdmrs)
				return -E2BIG;

			tdmr = tdmr_entry(tdmr_list, tdmr_idx);
		}

		tdmr->base = start;
		tdmr->size = end - start;
	}

	/* @tdmr_idx is always the index of last valid TDMR. */
	tdmr_list->nr_tdmrs = tdmr_idx + 1;

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
	unsigned long pamt_base[TDX_PS_1G + 1];
	unsigned long pamt_size[TDX_PS_1G + 1];
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

	for (i = 0; i < tdmr_list->nr_tdmrs; i++)
		tdmr_free_pamt(tdmr_entry(tdmr_list, i));
}

/* Allocate and set up PAMTs for all TDMRs */
static int tdmrs_set_up_pamt_all(struct tdmr_info_list *tdmr_list,
				 struct list_head *tmb_list,
				 u16 pamt_entry_size)
{
	int i, ret = 0;

	for (i = 0; i < tdmr_list->nr_tdmrs; i++) {
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

	for (i = 0; i < tdmr_list->nr_tdmrs; i++) {
		unsigned long pfn, npages;

		tdmr_get_pamt(tdmr_entry(tdmr_list, i), &pfn, &npages);
		pamt_npages += npages;
	}

	return pamt_npages;
}

static int tdmr_add_rsvd_area(struct tdmr_info *tdmr, int *p_idx, u64 addr,
			      u64 size, u16 max_reserved_per_tdmr)
{
	struct tdmr_reserved_area *rsvd_areas = tdmr->reserved_areas;
	int idx = *p_idx;

	/* Reserved area must be 4K aligned in offset and size */
	if (WARN_ON(addr & ~PAGE_MASK || size & ~PAGE_MASK))
		return -EINVAL;

	if (idx >= max_reserved_per_tdmr)
		return -E2BIG;

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

	for (i = 0; i < tdmr_list->nr_tdmrs; i++) {
		struct tdmr_info *tmp = tdmr_entry(tdmr_list, i);
		unsigned long pamt_start_pfn, pamt_npages;
		u64 pamt_start, pamt_end;

		tdmr_get_pamt(tmp, &pamt_start_pfn, &pamt_npages);
		/* Each TDMR must already have PAMT allocated */
		WARN_ON_ONCE(!pamt_npages || !pamt_start_pfn);

		pamt_start = PFN_PHYS(pamt_start_pfn);
		pamt_end   = PFN_PHYS(pamt_start_pfn + pamt_npages);

		/* Skip PAMTs outside of the given TDMR */
		if ((pamt_end <= tdmr->base) ||
				(pamt_start >= tdmr_end(tdmr)))
			continue;

		/* Only mark the part within the TDMR as reserved */
		if (pamt_start < tdmr->base)
			pamt_start = tdmr->base;
		if (pamt_end > tdmr_end(tdmr))
			pamt_end = tdmr_end(tdmr);

		ret = tdmr_add_rsvd_area(tdmr, rsvd_idx, pamt_start,
				pamt_end - pamt_start,
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

	for (i = 0; i < tdmr_list->nr_tdmrs; i++) {
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
		goto err;

	ret = tdmrs_set_up_pamt_all(tdmr_list, tmb_list,
			sysinfo->pamt_entry_size);
	if (ret)
		goto err;

	ret = tdmrs_populate_rsvd_areas_all(tdmr_list, tmb_list,
			sysinfo->max_reserved_per_tdmr);
	if (ret)
		goto err_free_pamts;

	return 0;
err_free_pamts:
	tdmrs_free_pamt_all(tdmr_list);
err:
	return ret;
}

static int config_tdx_module(struct tdmr_info_list *tdmr_list, u64 global_keyid)
{
	u64 *tdmr_pa_array, *p;
	size_t array_sz;
	int i, ret;

	/*
	 * TDMRs are passed to the TDX module via an array of physical
	 * addresses of each TDMR.  The array itself has alignment
	 * requirement.
	 */
	array_sz = tdmr_list->nr_tdmrs * sizeof(u64) +
		TDMR_INFO_PA_ARRAY_ALIGNMENT - 1;
	p = kzalloc(array_sz, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	tdmr_pa_array = PTR_ALIGN(p, TDMR_INFO_PA_ARRAY_ALIGNMENT);
	for (i = 0; i < tdmr_list->nr_tdmrs; i++)
		tdmr_pa_array[i] = __pa(tdmr_entry(tdmr_list, i));

	ret = seamcall(TDH_SYS_CONFIG, __pa(tdmr_pa_array), tdmr_list->nr_tdmrs,
				global_keyid, 0, NULL, NULL);

	/* Free the array as it is not required anymore. */
	kfree(p);

	return ret;
}

static void do_global_key_config(void *data)
{
	int ret;

	/*
	 * TDH.SYS.KEY.CONFIG may fail with entropy error (which is a
	 * recoverable error).  Assume this is exceedingly rare and
	 * just return error if encountered instead of retrying.
	 */
	ret = seamcall(TDH_SYS_KEY_CONFIG, 0, 0, 0, 0, NULL, NULL);

	*(int *)data = ret;
}

/*
 * Configure the global KeyID on all packages by doing TDH.SYS.KEY.CONFIG
 * on one online cpu for each package.  If any package doesn't have any
 * online
 *
 * Note:
 *
 * This function neither checks whether there's at least one online cpu
 * for each package, nor explicitly prevents any cpu from going offline.
 * If any package doesn't have any online cpu then the SEAMCALL won't be
 * done on that package and the later step of TDX module initialization
 * will fail.  The caller needs to guarantee this.
 */
static int config_global_keyid(void)
{
	cpumask_var_t packages;
	int cpu, ret = 0;

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL))
		return -ENOMEM;

	for_each_online_cpu(cpu) {
		int err;

		if (cpumask_test_and_set_cpu(topology_physical_package_id(cpu),
					packages))
			continue;

		/*
		 * TDH.SYS.KEY.CONFIG cannot run concurrently on
		 * different cpus, so just do it one by one.
		 */
		ret = smp_call_function_single(cpu, do_global_key_config, &err,
				true);
		if (ret)
			break;
		if (err) {
			ret = err;
			break;
		}
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
		 * TDH.SYS.TDMR.INT succeeded.
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
	for (i = 0; i < tdmr_list->nr_tdmrs; i++) {
		int ret;

		ret = init_tdmr(tdmr_entry(tdmr_list, i));
		if (ret)
			return ret;
	}

	return 0;
}

static void do_lp_init(void *data)
{
	u64 tsx_ctrl;
	int ret;

	tsx_ctrl = tsx_ctrl_clear();
	ret = seamcall(TDH_SYS_LP_INIT, 0, 0, 0, 0, NULL, NULL);
	tsx_ctrl_restore(tsx_ctrl);

	*(int *)data = ret;
}
static int tdx_module_init_cpus(void)
{
	int cpu, ret = 0;

	for_each_online_cpu(cpu) {
		int err;

		ret = smp_call_function_single(cpu, do_lp_init, &err, true);
		if (ret)
			break;
		if (err) {
			ret = err;
			break;
		}
	}

	return ret;
}

static void tdx_trace_seamcalls(u64 level)
{
	static bool debugconfig_supported = true;
	int ret;

	if (debugconfig_supported) {
		ret = seamcall(SEAMCALL_TDDEBUGCONFIG,
			       DEBUGCONFIG_SET_TRACE_LEVEL, level, 0, 0, NULL, NULL);
		if (ret) {
			pr_info("TDDEBUGCONFIG isn't supported.\n");
			debugconfig_supported = false;
		}
	}
}

static int init_tdx_module(void)
{
	/*
	 * @tdsysinfo and @cmr_array are used in TDH.SYS.INFO SEAMCALL ABI.
	 * They are 1024 bytes and 512 bytes respectively but it's fine to
	 * keep them in the stack as this function is only called once.
	 */
	struct cmr_info cmr_array[MAX_CMRS] __aligned(CMR_INFO_ARRAY_ALIGNMENT);
	struct tdsysinfo_struct *sysinfo = &PADDED_STRUCT(tdsysinfo);
	struct tdmr_info_list tdmr_list;
	u64 tsx_ctrl;
	int ret;

	preempt_disable();
	tsx_ctrl = tsx_ctrl_clear();
	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL, NULL);
	tsx_ctrl_restore(tsx_ctrl);
	preempt_enable();
	if (ret)
		goto out;

	if (trace_boot_seamcalls)
		tdx_trace_seamcalls(DEBUGCONFIG_TRACE_ALL);
	else
		tdx_trace_seamcalls(tdx_trace_level);

	/* Logical-cpu scope initialization */
	ret = tdx_module_init_cpus();
	if (ret)
		goto out;

	ret = __tdx_get_sysinfo(sysinfo, cmr_array);
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

	/* Allocate enough space for constructing TDMRs */
	ret = alloc_tdmr_list(&tdmr_list, sysinfo);
	if (ret)
		goto out_free_tdx_mem;

	/* Cover all TDX-usable memory regions in TDMRs */
	ret = construct_tdmrs(&tdx_memlist, &tdmr_list, sysinfo);
	if (ret)
		goto out_free_tdmrs;

	/*
	 * Use the first private KeyID as the global KeyID, and pass
	 * it along with the TDMRs to the TDX module.
	 */
	ret = config_tdx_module(&tdmr_list, tdx_keyid_start);
	if (ret)
		goto out_free_pamts;

	/*
	 * Hardware doesn't guarantee cache coherency across different
	 * KeyIDs.  The kernel needs to flush PAMT's dirty cachelines
	 * (associated with KeyID 0) before the TDX module can use the
	 * global KeyID to access the PAMT.  Given PAMTs are potentially
	 * large (~1/256th of system RAM), just use WBINVD on all cpus
	 * to flush the cache.
	 *
	 * Follow the TDX spec to flush cache before configuring the
	 * global KeyID on all packages.
	 */
	wbinvd_on_all_cpus();

	/* Config the key of global KeyID on all packages */
	ret = config_global_keyid();
	if (ret)
		goto out_free_pamts;

	/*
	 * Reserve the first TDX KeyID as global KeyID to protect
	 * TDX module metadata.
	 */
	tdx_global_keyid = tdx_keyid_start;

	/* Initialize TDMRs to complete the TDX module initialization */
	ret = init_tdmrs(&tdmr_list);
	if (ret)
		goto out_free_pamts;
out_free_pamts:
	if (ret) {
		/*
		 * Part of PAMT may already have been initialized by the
		 * TDX module.  Flush cache before returning PAMT back
		 * to the kernel.
		 *
		 * No need to worry about integrity checks here.  KeyID
		 * 0 has integrity checking disabled.
		 */
		wbinvd_on_all_cpus();

		tdmrs_free_pamt_all(&tdmr_list);
	} else
		pr_info("%lu pages allocated for PAMT.\n",
				tdmrs_count_pamt_pages(&tdmr_list));
out_free_tdmrs:
	/*
	 * Free the space for the TDMRs no matter the initialization is
	 * successful or not.  They are not needed anymore after the
	 * module initialization.
	 */
	free_tdmr_list(&tdmr_list);
out_free_tdx_mem:
	if (ret)
		free_tdx_memlist(&tdx_memlist);
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
 * calling this function.  Also, the caller must make sure there is at
 * least one online cpu for each package, and to prevent any cpu from
 * going offline during this function.
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

#ifdef CONFIG_SYSFS

static struct kobject *tdx_kobj;
static struct kobject *tdx_module_kobj;

static ssize_t tdx_nr_keyids_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%08x", nr_tdx_keyids);
}

static struct kobj_attribute tdx_nr_keyids_attr = {
	.attr = { .name = "nr_keyids", .mode = 0444 },
	.show = tdx_nr_keyids_show,
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
	.attr = { .name = "status", .mode = 0444 },
	.show = tdx_module_status_show,
};

static int __init tdx_sysfs_init(void)
{
	int ret;

	tdx_kobj = kobject_create_and_add("tdx", firmware_kobj);
	if (!tdx_kobj) {
		pr_err("kobject_create_and_add tdx failed\n");
		return -EINVAL;
	}

	ret = sysfs_create_file(tdx_kobj, &tdx_nr_keyids_attr.attr);
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
	if (ret)
		pr_err("Sysfs exporting tdx module status failed %d\n", ret);

	return ret;
}
device_initcall(tdx_sysfs_init);
#endif
