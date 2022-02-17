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
#include <linux/align.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/minmax.h>
#include <linux/sizes.h>
#include <linux/sort.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/tdx.h>
#include "tdx.h"

/* TDX module status during initialization */
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

struct tdx_memblock {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
	int nid;
};

static u32 tdx_keyid_start __ro_after_init;
static u32 tdx_keyid_num __ro_after_init;

static enum tdx_module_status_t tdx_module_status;
/* Prevent concurrent attempts on TDX detection and initialization */
static DEFINE_MUTEX(tdx_module_lock);

/* Below two are used in TDH.SYS.INFO SEAMCALL ABI */
static struct tdsysinfo_struct tdx_sysinfo;
static struct cmr_info tdx_cmr_array[MAX_CMRS] __aligned(CMR_INFO_ARRAY_ALIGNMENT);
static int tdx_cmr_num;

/* All TDX-usable memory regions */
static LIST_HEAD(tdx_memlist);

/* TDX module global KeyID.  Used in TDH.SYS.CONFIG ABI. */
static u32 tdx_global_keyid;

/*
 * Detect TDX private KeyIDs to see whether TDX has been enabled by the
 * BIOS.  Both initializing the TDX module and running TDX guest require
 * TDX private KeyID.
 *
 * TDX doesn't trust BIOS.  TDX verifies all configurations from BIOS
 * are correct before enabling TDX on any core.  TDX requires the BIOS
 * to correctly and consistently program TDX private KeyIDs on all CPU
 * packages.  Unless there is a BIOS bug, detecting a valid TDX private
 * KeyID range on BSP indicates TDX has been enabled by the BIOS.  If
 * there's such BIOS bug, it will be caught later when initializing the
 * TDX module.
 */
static int __init detect_tdx(void)
{
	int ret;

	/*
	 * IA32_MKTME_KEYID_PARTIONING:
	 *   Bit [31:0]:	Number of MKTME KeyIDs.
	 *   Bit [63:32]:	Number of TDX private KeyIDs.
	 */
	ret = rdmsr_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &tdx_keyid_start,
			&tdx_keyid_num);
	if (ret)
		return -ENODEV;

	if (!tdx_keyid_num)
		return -ENODEV;

	/*
	 * KeyID 0 is for TME.  MKTME KeyIDs start from 1.  TDX private
	 * KeyIDs start after the last MKTME KeyID.
	 */
	tdx_keyid_start++;

	pr_info("TDX enabled by BIOS. TDX private KeyID range: [%u, %u)\n",
			tdx_keyid_start, tdx_keyid_start + tdx_keyid_num);

	return 0;
}

static void __init clear_tdx(void)
{
	tdx_keyid_start = tdx_keyid_num = 0;
}

static int __init tdx_init(void)
{
	if (detect_tdx())
		return -ENODEV;

	/*
	 * Initializing the TDX module requires one TDX private KeyID.
	 * If there's only one TDX KeyID then after module initialization
	 * KVM won't be able to run any TDX guest, which makes the whole
	 * thing worthless.  Just disable TDX in this case.
	 */
	if (tdx_keyid_num < 2) {
		pr_info("Disable TDX as there's only one TDX private KeyID available.\n");
		goto no_tdx;
	}

	/*
	 * TDX requires X2APIC being enabled to prevent potential data
	 * leak via APIC MMIO registers.  Just disable TDX if not using
	 * X2APIC.
	 */
	if (!x2apic_enabled()) {
		pr_info("Disable TDX as X2APIC is not enabled.\n");
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
	return !!tdx_keyid_num;
}

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

	/* Save SEAMCALL return code if caller wants it */
	if (seamcall_ret)
		*seamcall_ret = sret;

	/* SEAMCALL was successful */
	if (!sret)
		return 0;

	switch (sret) {
	case TDX_SEAMCALL_GP:
		/*
		 * platform_tdx_enabled() is checked to be true
		 * before making any SEAMCALL.
		 */
		WARN_ON_ONCE(1);
		fallthrough;
	case TDX_SEAMCALL_VMFAILINVALID:
		/* Return -ENODEV if the TDX module is not loaded. */
		return -ENODEV;
	case TDX_SEAMCALL_UD:
		/* Return -EINVAL if CPU isn't in VMX operation. */
		return -EINVAL;
	default:
		/* Return -EIO if the actual SEAMCALL leaf failed. */
		return -EIO;
	}
}

static void seamcall_smp_call_function(void *data)
{
	struct seamcall_ctx *sc = data;
	int ret;

	ret = seamcall(sc->fn, sc->rcx, sc->rdx, sc->r8, sc->r9, NULL, NULL);
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

static int tdx_module_init_cpus(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_INIT };

	seamcall_on_each_cpu(&sc);

	return atomic_read(&sc.err);
}

static inline bool is_cmr_empty(struct cmr_info *cmr)
{
	return !cmr->size;
}

static inline bool is_cmr_ok(struct cmr_info *cmr)
{
	/* CMR must be page aligned */
	return IS_ALIGNED(cmr->base, PAGE_SIZE) &&
		IS_ALIGNED(cmr->size, PAGE_SIZE);
}

static void print_cmrs(struct cmr_info *cmr_array, int cmr_num,
		       const char *name)
{
	int i;

	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		pr_info("%s : [0x%llx, 0x%llx)\n", name,
				cmr->base, cmr->base + cmr->size);
	}
}

/* Check CMRs reported by TDH.SYS.INFO, and trim tail empty CMRs. */
static int trim_empty_cmrs(struct cmr_info *cmr_array, int *actual_cmr_num)
{
	struct cmr_info *cmr;
	int i, cmr_num;

	/*
	 * Intel TDX module spec, 20.7.3 CMR_INFO:
	 *
	 *   TDH.SYS.INFO leaf function returns a MAX_CMRS (32) entry
	 *   array of CMR_INFO entries. The CMRs are sorted from the
	 *   lowest base address to the highest base address, and they
	 *   are non-overlapping.
	 *
	 * This implies that BIOS may generate invalid empty entries
	 * if total CMRs are less than 32.  Need to skip them manually.
	 *
	 * CMR also must be 4K aligned.  TDX doesn't trust BIOS.  TDX
	 * actually verifies CMRs before it gets enabled, so anything
	 * doesn't meet above means kernel bug (or TDX is broken).
	 */
	cmr = &cmr_array[0];
	/* There must be at least one valid CMR */
	if (WARN_ON_ONCE(is_cmr_empty(cmr) || !is_cmr_ok(cmr)))
		goto err;

	cmr_num = *actual_cmr_num;
	for (i = 1; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];
		struct cmr_info *prev_cmr = NULL;

		/* Skip further empty CMRs */
		if (is_cmr_empty(cmr))
			break;

		/*
		 * Do sanity check anyway to make sure CMRs:
		 *  - are 4K aligned
		 *  - don't overlap
		 *  - are in address ascending order.
		 */
		if (WARN_ON_ONCE(!is_cmr_ok(cmr)))
			goto err;

		prev_cmr = &cmr_array[i - 1];
		if (WARN_ON_ONCE((prev_cmr->base + prev_cmr->size) >
					cmr->base))
			goto err;
	}

	/* Update the actual number of CMRs */
	*actual_cmr_num = i;

	/* Print kernel checked CMRs */
	print_cmrs(cmr_array, *actual_cmr_num, "Kernel-checked-CMR");

	return 0;
err:
	pr_info("[TDX broken ?]: Invalid CMRs detected\n");
	print_cmrs(cmr_array, cmr_num, "BIOS-CMR");
	return -EINVAL;
}

static int tdx_get_sysinfo(void)
{
	struct tdx_module_output out;
	int ret;

	BUILD_BUG_ON(sizeof(struct tdsysinfo_struct) != TDSYSINFO_STRUCT_SIZE);

	ret = seamcall(TDH_SYS_INFO, __pa(&tdx_sysinfo), TDSYSINFO_STRUCT_SIZE,
			__pa(tdx_cmr_array), MAX_CMRS, NULL, &out);
	if (ret)
		return ret;

	/* R9 contains the actual entries written the CMR array. */
	tdx_cmr_num = out.r9;

	pr_info("TDX module: atributes 0x%x, vendor_id 0x%x, major_version %u, minor_version %u, build_date %u, build_num %u",
		tdx_sysinfo.attributes, tdx_sysinfo.vendor_id,
		tdx_sysinfo.major_version, tdx_sysinfo.minor_version,
		tdx_sysinfo.build_date, tdx_sysinfo.build_num);

	/*
	 * trim_empty_cmrs() updates the actual number of CMRs by
	 * dropping all tail empty CMRs.
	 */
	return trim_empty_cmrs(tdx_cmr_array, &tdx_cmr_num);
}

/* Check whether the given pfn range is covered by any CMR or not. */
static bool pfn_range_covered_by_cmr(unsigned long start_pfn,
				     unsigned long end_pfn)
{
	int i;

	for (i = 0; i < tdx_cmr_num; i++) {
		struct cmr_info *cmr = &tdx_cmr_array[i];
		unsigned long cmr_start_pfn;
		unsigned long cmr_end_pfn;

		cmr_start_pfn = cmr->base >> PAGE_SHIFT;
		cmr_end_pfn = (cmr->base + cmr->size) >> PAGE_SHIFT;

		if (start_pfn >= cmr_start_pfn && end_pfn <= cmr_end_pfn)
			return true;
	}

	return false;
}

/*
 * Add a memory region on a given node as a TDX memory block.  The caller
 * to make sure all memory regions are added in address ascending order
 * and don't overlap.
 */
static int add_tdx_memblock(unsigned long start_pfn, unsigned long end_pfn,
			    int nid)
{
	struct tdx_memblock *tmb;

	tmb = kmalloc(sizeof(*tmb), GFP_KERNEL);
	if (!tmb)
		return -ENOMEM;

	INIT_LIST_HEAD(&tmb->list);
	tmb->start_pfn = start_pfn;
	tmb->end_pfn = end_pfn;
	tmb->nid = nid;

	list_add_tail(&tmb->list, &tdx_memlist);
	return 0;
}

static void free_tdx_memory(void)
{
	while (!list_empty(&tdx_memlist)) {
		struct tdx_memblock *tmb = list_first_entry(&tdx_memlist,
				struct tdx_memblock, list);

		list_del(&tmb->list);
		kfree(tmb);
	}
}

/*
 * Add all memblock memory regions to the @tdx_memlist as TDX memory.
 * Must be called when get_online_mems() is called by the caller.
 */
static int build_tdx_memory(void)
{
	unsigned long start_pfn, end_pfn;
	int i, nid, ret;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		/*
		 * The first 1MB may not be reported as TDX convertible
		 * memory.  Manually exclude them as TDX memory.
		 *
		 * This is fine as the first 1MB is already reserved in
		 * reserve_real_mode() and won't end up to ZONE_DMA as
		 * free page anyway.
		 */
		start_pfn = max(start_pfn, (unsigned long)SZ_1M >> PAGE_SHIFT);
		if (start_pfn >= end_pfn)
			continue;

		/* Verify memory is truly TDX convertible memory */
		if (!pfn_range_covered_by_cmr(start_pfn, end_pfn)) {
			pr_info("Memory region [0x%lx, 0x%lx) is not TDX convertible memorry.\n",
					start_pfn << PAGE_SHIFT,
					end_pfn << PAGE_SHIFT);
			return -EINVAL;
		}

		/*
		 * Add the memory regions as TDX memory.  The regions in
		 * memblock has already guaranteed they are in address
		 * ascending order and don't overlap.
		 */
		ret = add_tdx_memblock(start_pfn, end_pfn, nid);
		if (ret)
			goto err;
	}

	return 0;
err:
	free_tdx_memory();
	return ret;
}

/* TDMR must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT_ULL(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

/* Align up and down the address to TDMR boundary */
#define TDMR_ALIGN_DOWN(_addr)	ALIGN_DOWN((_addr), TDMR_ALIGNMENT)
#define TDMR_ALIGN_UP(_addr)	ALIGN((_addr), TDMR_ALIGNMENT)

static inline u64 tdmr_start(struct tdmr_info *tdmr)
{
	return tdmr->base;
}

static inline u64 tdmr_end(struct tdmr_info *tdmr)
{
	return tdmr->base + tdmr->size;
}

/* Calculate the actual TDMR_INFO size */
static inline int cal_tdmr_size(void)
{
	int tdmr_sz;

	/*
	 * The actual size of TDMR_INFO depends on the maximum number
	 * of reserved areas.
	 *
	 * Note: for TDX1.0 the max_reserved_per_tdmr is 16, and
	 * TDMR_INFO size is aligned up to 512-byte.  Even it is
	 * extended in the future, it would be insane if TDMR_INFO
	 * becomes larger than 4K.  The tdmr_sz here should never
	 * overflow.
	 */
	tdmr_sz = sizeof(struct tdmr_info);
	tdmr_sz += sizeof(struct tdmr_reserved_area) *
		   tdx_sysinfo.max_reserved_per_tdmr;

	/*
	 * TDX requires each TDMR_INFO to be 512-byte aligned.  Always
	 * round up TDMR_INFO size to the 512-byte boundary.
	 */
	return ALIGN(tdmr_sz, TDMR_INFO_ALIGNMENT);
}

static struct tdmr_info *alloc_tdmr_array(int *array_sz)
{
	/*
	 * TDX requires each TDMR_INFO to be 512-byte aligned.
	 * Use alloc_pages_exact() to allocate all TDMRs at once.
	 * Each TDMR_INFO will still be 512-byte aligned since
	 * cal_tdmr_size() always returns 512-byte aligned size.
	 */
	*array_sz = cal_tdmr_size() * tdx_sysinfo.max_tdmrs;

	/*
	 * Zero the buffer so 'struct tdmr_info::size' can be
	 * used to determine whether a TDMR is valid.
	 *
	 * Note: for TDX1.0 the max_tdmrs is 64 and TDMR_INFO size
	 * is 512-byte.  Even they are extended in the future, it
	 * would be insane if the total size exceeds 4MB.
	 */
	return alloc_pages_exact(*array_sz, GFP_KERNEL | __GFP_ZERO);
}

static struct tdmr_info *tdmr_array_entry(struct tdmr_info *tdmr_array,
					  int idx)
{
	return (struct tdmr_info *)((unsigned long)tdmr_array +
			cal_tdmr_size() * idx);
}

/*
 * Create TDMRs to cover all TDX memory regions.  The actual number
 * of TDMRs is set to @tdmr_num.
 */
static int create_tdmrs(struct tdmr_info *tdmr_array, int *tdmr_num)
{
	struct tdx_memblock *tmb;
	int tdmr_idx = 0;

	/*
	 * Loop over TDX memory regions and create TDMRs to cover them.
	 * To keep it simple, always try to use one TDMR to cover
	 * one memory region.
	 */
	list_for_each_entry(tmb, &tdx_memlist, list) {
		struct tdmr_info *tdmr;
		u64 start, end;

		tdmr = tdmr_array_entry(tdmr_array, tdmr_idx);
		start = TDMR_ALIGN_DOWN(tmb->start_pfn << PAGE_SHIFT);
		end = TDMR_ALIGN_UP(tmb->end_pfn << PAGE_SHIFT);

		/*
		 * If the current TDMR's size hasn't been initialized,
		 * it is a new TDMR to cover the new memory region.
		 * Otherwise, the current TDMR has already covered the
		 * previous memory region.  In the latter case, check
		 * whether the current memory region has been fully or
		 * partially covered by the current TDMR, since TDMR is
		 * 1G aligned.
		 */
		if (tdmr->size) {
			/*
			 * Loop to the next memory region if the current
			 * block has already been fully covered by the
			 * current TDMR.
			 */
			if (end <= tdmr_end(tdmr))
				continue;

			/*
			 * If part of the current memory region has
			 * already been covered by the current TDMR,
			 * skip the already covered part.
			 */
			if (start < tdmr_end(tdmr))
				start = tdmr_end(tdmr);

			/*
			 * Create a new TDMR to cover the current memory
			 * region, or the remaining part of it.
			 */
			tdmr_idx++;
			if (tdmr_idx >= tdx_sysinfo.max_tdmrs)
				return -E2BIG;

			tdmr = tdmr_array_entry(tdmr_array, tdmr_idx);
		}

		tdmr->base = start;
		tdmr->size = end - start;
	}

	/* @tdmr_idx is always the index of last valid TDMR. */
	*tdmr_num = tdmr_idx + 1;

	return 0;
}

/*
 * Calculate PAMT size given a TDMR and a page size.  The returned
 * PAMT size is always aligned up to 4K page boundary.
 */
static unsigned long tdmr_get_pamt_sz(struct tdmr_info *tdmr, int pgsz)
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

	pamt_sz = nr_pamt_entries * tdx_sysinfo.pamt_entry_size;
	/* TDX requires PAMT size must be 4K aligned */
	pamt_sz = ALIGN(pamt_sz, PAGE_SIZE);

	return pamt_sz;
}

/*
 * Pick a NUMA node on which to allocate this TDMR's metadata.
 *
 * This is imprecise since TDMRs are 1G aligned and NUMA nodes might
 * not be.  If the TDMR covers more than one node, just use the _first_
 * one.  This can lead to small areas of off-node metadata for some
 * memory.
 */
static int tdmr_get_nid(struct tdmr_info *tdmr)
{
	struct tdx_memblock *tmb;

	/* Find the first memory region covered by the TDMR */
	list_for_each_entry(tmb, &tdx_memlist, list) {
		if (tmb->end_pfn > (tdmr_start(tdmr) >> PAGE_SHIFT))
			return tmb->nid;
	}

	/*
	 * Fall back to allocating the TDMR's metadata from node 0 when
	 * no TDX memory block can be found.  This should never happen
	 * since TDMRs originate from TDX memory blocks.
	 */
	WARN_ON_ONCE(1);
	return 0;
}

static int tdmr_set_up_pamt(struct tdmr_info *tdmr)
{
	unsigned long pamt_base[TDX_PS_1G + 1];
	unsigned long pamt_size[TDX_PS_1G + 1];
	unsigned long tdmr_pamt_base;
	unsigned long tdmr_pamt_size;
	struct page *pamt;
	int pgsz, nid;

	nid = tdmr_get_nid(tdmr);

	/*
	 * Calculate the PAMT size for each TDX supported page size
	 * and the total PAMT size.
	 */
	tdmr_pamt_size = 0;
	for (pgsz = TDX_PS_4K; pgsz <= TDX_PS_1G ; pgsz++) {
		pamt_size[pgsz] = tdmr_get_pamt_sz(tdmr, pgsz);
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

	*pamt_pfn = pamt_base >> PAGE_SHIFT;
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

static void tdmrs_free_pamt_all(struct tdmr_info *tdmr_array, int tdmr_num)
{
	int i;

	for (i = 0; i < tdmr_num; i++)
		tdmr_free_pamt(tdmr_array_entry(tdmr_array, i));
}

/* Allocate and set up PAMTs for all TDMRs */
static int tdmrs_set_up_pamt_all(struct tdmr_info *tdmr_array, int tdmr_num)
{
	int i, ret = 0;

	for (i = 0; i < tdmr_num; i++) {
		ret = tdmr_set_up_pamt(tdmr_array_entry(tdmr_array, i));
		if (ret)
			goto err;
	}

	return 0;
err:
	tdmrs_free_pamt_all(tdmr_array, tdmr_num);
	return ret;
}

static unsigned long tdmrs_count_pamt_pages(struct tdmr_info *tdmr_array,
					  int tdmr_num)
{
	unsigned long pamt_npages = 0;
	int i;

	for (i = 0; i < tdmr_num; i++) {
		unsigned long pfn, npages;

		tdmr_get_pamt(tdmr_array_entry(tdmr_array, i), &pfn, &npages);
		pamt_npages += npages;
	}

	return pamt_npages;
}

static int tdmr_add_rsvd_area(struct tdmr_info *tdmr, int *p_idx,
			      u64 addr, u64 size)
{
	struct tdmr_reserved_area *rsvd_areas = tdmr->reserved_areas;
	int idx = *p_idx;

	/* Reserved area must be 4K aligned in offset and size */
	if (WARN_ON(addr & ~PAGE_MASK || size & ~PAGE_MASK))
		return -EINVAL;

	/* Cannot exceed maximum reserved areas supported by TDX */
	if (idx >= tdx_sysinfo.max_reserved_per_tdmr)
		return -E2BIG;

	rsvd_areas[idx].offset = addr - tdmr->base;
	rsvd_areas[idx].size = size;

	*p_idx = idx + 1;

	return 0;
}

static int tdmr_set_up_memory_hole_rsvd_areas(struct tdmr_info *tdmr,
					      int *rsvd_idx)
{
	struct tdx_memblock *tmb;
	u64 prev_end;
	int ret;

	/* Mark holes between memory regions as reserved */
	prev_end = tdmr_start(tdmr);
	list_for_each_entry(tmb, &tdx_memlist, list) {
		u64 start, end;

		start = tmb->start_pfn << PAGE_SHIFT;
		end = tmb->end_pfn << PAGE_SHIFT;

		/* Break if this region is after the TDMR */
		if (start >= tdmr_end(tdmr))
			break;

		/* Exclude regions before this TDMR */
		if (end < tdmr_start(tdmr))
			continue;

		/*
		 * Skip if no hole exists before this region. "<=" is
		 * used because one memory region might span two TDMRs
		 * (when the previous TDMR covers part of this region).
		 * In this case the start address of this region is
		 * smaller than the start address of the second TDMR.
		 *
		 * Update the prev_end to the end of this region where
		 * the possible memory hole starts.
		 */
		if (start <= prev_end) {
			prev_end = end;
			continue;
		}

		/* Add the hole before this region */
		ret = tdmr_add_rsvd_area(tdmr, rsvd_idx, prev_end,
				start - prev_end);
		if (ret)
			return ret;

		prev_end = end;
	}

	/* Add the hole after the last region if it exists. */
	if (prev_end < tdmr_end(tdmr)) {
		ret = tdmr_add_rsvd_area(tdmr, rsvd_idx, prev_end,
				tdmr_end(tdmr) - prev_end);
		if (ret)
			return ret;
	}

	return 0;
}

static int tdmr_set_up_pamt_rsvd_areas(struct tdmr_info *tdmr, int *rsvd_idx,
				       struct tdmr_info *tdmr_array,
				       int tdmr_num)
{
	int i, ret;

	/*
	 * If any PAMT overlaps with this TDMR, the overlapping part
	 * must also be put to the reserved area too.  Walk over all
	 * TDMRs to find out those overlapping PAMTs and put them to
	 * reserved areas.
	 */
	for (i = 0; i < tdmr_num; i++) {
		struct tdmr_info *tmp = tdmr_array_entry(tdmr_array, i);
		unsigned long pamt_start_pfn, pamt_npages;
		u64 pamt_start, pamt_end;

		tdmr_get_pamt(tmp, &pamt_start_pfn, &pamt_npages);
		/* Each TDMR must already have PAMT allocated */
		WARN_ON_ONCE(!pamt_npages || !pamt_start_pfn);

		pamt_start = pamt_start_pfn << PAGE_SHIFT;
		pamt_end = pamt_start + (pamt_npages << PAGE_SHIFT);

		/* Skip PAMTs outside of the given TDMR */
		if ((pamt_end <= tdmr_start(tdmr)) ||
				(pamt_start >= tdmr_end(tdmr)))
			continue;

		/* Only mark the part within the TDMR as reserved */
		if (pamt_start < tdmr_start(tdmr))
			pamt_start = tdmr_start(tdmr);
		if (pamt_end > tdmr_end(tdmr))
			pamt_end = tdmr_end(tdmr);

		ret = tdmr_add_rsvd_area(tdmr, rsvd_idx, pamt_start,
				pamt_end - pamt_start);
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

	/* Reserved areas cannot overlap.  The caller should guarantee. */
	WARN_ON_ONCE(1);
	return -1;
}

/* Set up reserved areas for a TDMR, including memory holes and PAMTs */
static int tdmr_set_up_rsvd_areas(struct tdmr_info *tdmr,
				  struct tdmr_info *tdmr_array,
				  int tdmr_num)
{
	int ret, rsvd_idx = 0;

	/* Put all memory holes within the TDMR into reserved areas */
	ret = tdmr_set_up_memory_hole_rsvd_areas(tdmr, &rsvd_idx);
	if (ret)
		return ret;

	/* Put all (overlapping) PAMTs within the TDMR into reserved areas */
	ret = tdmr_set_up_pamt_rsvd_areas(tdmr, &rsvd_idx, tdmr_array, tdmr_num);
	if (ret)
		return ret;

	/* TDX requires reserved areas listed in address ascending order */
	sort(tdmr->reserved_areas, rsvd_idx, sizeof(struct tdmr_reserved_area),
			rsvd_area_cmp_func, NULL);

	return 0;
}

static int tdmrs_set_up_rsvd_areas_all(struct tdmr_info *tdmr_array,
				       int tdmr_num)
{
	int i;

	for (i = 0; i < tdmr_num; i++) {
		int ret;

		ret = tdmr_set_up_rsvd_areas(tdmr_array_entry(tdmr_array, i),
				tdmr_array, tdmr_num);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Construct an array of TDMRs to cover all TDX memory ranges.
 * The actual number of TDMRs is kept to @tdmr_num.
 */
static int construct_tdmrs(struct tdmr_info *tdmr_array, int *tdmr_num)
{
	int ret;

	ret = create_tdmrs(tdmr_array, tdmr_num);
	if (ret)
		goto err;

	ret = tdmrs_set_up_pamt_all(tdmr_array, *tdmr_num);
	if (ret)
		goto err;

	ret = tdmrs_set_up_rsvd_areas_all(tdmr_array, *tdmr_num);
	if (ret)
		goto err_free_pamts;

	return 0;
err_free_pamts:
	tdmrs_free_pamt_all(tdmr_array, *tdmr_num);
err:
	return ret;
}

static int config_tdx_module(struct tdmr_info *tdmr_array, int tdmr_num,
			     u64 global_keyid)
{
	u64 *tdmr_pa_array;
	int i, array_sz;
	u64 ret;

	/*
	 * TDMR_INFO entries are configured to the TDX module via an
	 * array of the physical address of each TDMR_INFO.  TDX module
	 * requires the array itself to be 512-byte aligned.  Round up
	 * the array size to 512-byte aligned so the buffer allocated
	 * by kzalloc() will meet the alignment requirement.
	 */
	array_sz = ALIGN(tdmr_num * sizeof(u64), TDMR_INFO_PA_ARRAY_ALIGNMENT);
	tdmr_pa_array = kzalloc(array_sz, GFP_KERNEL);
	if (!tdmr_pa_array)
		return -ENOMEM;

	for (i = 0; i < tdmr_num; i++)
		tdmr_pa_array[i] = __pa(tdmr_array_entry(tdmr_array, i));

	ret = seamcall(TDH_SYS_CONFIG, __pa(tdmr_pa_array), tdmr_num,
				global_keyid, 0, NULL, NULL);

	/* Free the array as it is not required anymore. */
	kfree(tdmr_pa_array);

	return ret;
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
	struct tdmr_info *tdmr_array;
	int tdmr_array_sz;
	int tdmr_num;
	int ret;

	/*
	 * Call TDH.SYS.INIT to do the global initialization of
	 * the TDX module.  It also detects the module.
	 */
	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL, NULL);
	if (ret)
		goto out;

	/* Logical-cpu scope initialization */
	ret = tdx_module_init_cpus();
	if (ret)
		goto out;

	ret = tdx_get_sysinfo();
	if (ret)
		goto out;

	/*
	 * All memory regions that can be used by the TDX module must be
	 * passed to the TDX module during the module initialization.
	 * Once this is done, all "TDX-usable" memory regions are fixed
	 * during module's runtime.
	 *
	 * The initial support of TDX guests only allocates memory from
	 * the global page allocator.  To keep things simple, for now
	 * just make sure all pages in the page allocator are TDX memory.
	 *
	 * To achieve this, use all system memory in the core-mm at the
	 * time of initializing the TDX module as TDX memory, and at the
	 * meantime, reject any new memory in memory hot-add.
	 *
	 * This works as in practice, all boot-time present DIMM is TDX
	 * convertible memory.  However if any new memory is hot-added
	 * before initializing the TDX module, the initialization will
	 * fail due to that memory is not covered by CMR.
	 *
	 * This can be enhanced in the future, i.e. by allowing adding or
	 * onlining non-TDX memory to a separate node, in which case the
	 * "TDX-capable" nodes and the "non-TDX-capable" nodes can exist
	 * together -- the userspace/kernel just needs to make sure pages
	 * for TDX guests must come from those "TDX-capable" nodes.
	 *
	 * Build the list of TDX memory regions as mentioned above so
	 * they can be passed to the TDX module later.
	 */
	get_online_mems();

	ret = build_tdx_memory();
	if (ret)
		goto out;

	/* Prepare enough space to construct TDMRs */
	tdmr_array = alloc_tdmr_array(&tdmr_array_sz);
	if (!tdmr_array) {
		ret = -ENOMEM;
		goto out_free_tdx_mem;
	}

	/* Construct TDMRs to cover all TDX memory ranges */
	ret = construct_tdmrs(tdmr_array, &tdmr_num);
	if (ret)
		goto out_free_tdmrs;

	/*
	 * Reserve the first TDX KeyID as global KeyID to protect
	 * TDX module metadata.
	 */
	tdx_global_keyid = tdx_keyid_start;

	/* Pass the TDMRs and the global KeyID to the TDX module */
	ret = config_tdx_module(tdmr_array, tdmr_num, tdx_global_keyid);
	if (ret)
		goto out_free_pamts;

	/*
	 * Return -EINVAL until all steps of TDX module initialization
	 * process are done.
	 */
	ret = -EINVAL;
out_free_pamts:
	if (ret)
		tdmrs_free_pamt_all(tdmr_array, tdmr_num);
	else
		pr_info("%lu pages allocated for PAMT.\n",
				tdmrs_count_pamt_pages(tdmr_array, tdmr_num));
out_free_tdmrs:
	/*
	 * The array of TDMRs is freed no matter the initialization is
	 * successful or not.  They are not needed anymore after the
	 * module initialization.
	 */
	free_pages_exact(tdmr_array, tdmr_array_sz);
out_free_tdx_mem:
	if (ret)
		free_tdx_memory();
out:
	/*
	 * Memory hotplug checks the hot-added memory region against the
	 * @tdx_memlist to see if the region is TDX memory.
	 *
	 * Do put_online_mems() here to make sure any modification to
	 * @tdx_memlist is done while holding the memory hotplug read
	 * lock, so that the memory hotplug path can just check the
	 * @tdx_memlist w/o holding the @tdx_module_lock which may cause
	 * deadlock.
	 */
	put_online_mems();
	return ret;
}

static void shutdown_tdx_module(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_SHUTDOWN };

	seamcall_on_each_cpu(&sc);
}

static int __tdx_enable(void)
{
	int ret;

	/*
	 * Initializing the TDX module requires doing SEAMCALL on all
	 * boot-time present CPUs.  For simplicity temporarily disable
	 * CPU hotplug to prevent any CPU from going offline during
	 * the initialization.
	 */
	cpus_read_lock();

	/*
	 * Check whether all boot-time present CPUs are online and
	 * return early with a message so the user can be aware.
	 *
	 * Note a non-buggy BIOS should never support physical (ACPI)
	 * CPU hotplug when TDX is enabled, and all boot-time present
	 * CPU should be enabled in MADT, so there should be no
	 * disabled_cpus and num_processors won't change at runtime
	 * either.
	 */
	if (disabled_cpus || num_online_cpus() != num_processors) {
		pr_err("Unable to initialize the TDX module when there's offline CPU(s).\n");
		ret = -EINVAL;
		goto out;
	}

	ret = init_tdx_module();
	if (ret == -ENODEV) {
		pr_info("TDX module is not loaded.\n");
		tdx_module_status = TDX_MODULE_NONE;
		goto out;
	}

	/*
	 * Shut down the TDX module in case of any error during the
	 * initialization process.  It's meaningless to leave the TDX
	 * module in any middle state of the initialization process.
	 *
	 * Shutting down the module also requires doing SEAMCALL on all
	 * MADT-enabled CPUs.  Do it while CPU hotplug is disabled.
	 *
	 * Return all errors during the initialization as -EFAULT as the
	 * module is always shut down.
	 */
	if (ret) {
		pr_info("Failed to initialize TDX module. Shut it down.\n");
		shutdown_tdx_module();
		tdx_module_status = TDX_MODULE_SHUTDOWN;
		ret = -EFAULT;
		goto out;
	}

	pr_info("TDX module initialized.\n");
	tdx_module_status = TDX_MODULE_INITIALIZED;
out:
	cpus_read_unlock();

	return ret;
}

/**
 * tdx_enable - Enable TDX by initializing the TDX module
 *
 * Caller to make sure all CPUs are online and in VMX operation before
 * calling this function.  CPU hotplug is temporarily disabled internally
 * to prevent any cpu from going offline.
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
int tdx_enable(void)
{
	int ret;

	if (!platform_tdx_enabled())
		return -ENODEV;

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNKNOWN:
		ret = __tdx_enable();
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
EXPORT_SYMBOL_GPL(tdx_enable);

/*
 * Check whether the given range is TDX memory.  Must be called between
 * mem_hotplug_begin()/mem_hotplug_done().
 */
bool tdx_cc_memory_compatible(unsigned long start_pfn, unsigned long end_pfn)
{
	struct tdx_memblock *tmb;

	/* Empty list means TDX isn't enabled successfully */
	if (list_empty(&tdx_memlist))
		return true;

	list_for_each_entry(tmb, &tdx_memlist, list) {
		/*
		 * The new range is TDX memory if it is fully covered
		 * by any TDX memory block.
		 */
		if (start_pfn >= tmb->start_pfn && end_pfn <= tmb->end_pfn)
			return true;
	}
	return false;
}
