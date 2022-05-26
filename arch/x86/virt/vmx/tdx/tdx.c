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
#include <linux/sizes.h>
#include <linux/memblock.h>
#include <linux/gfp.h>
#include <linux/align.h>
#include <asm/cpufeatures.h>
#include <asm/cpufeature.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/smp.h>
#include <asm/tdx.h>
#include <asm/coco.h>
#include "tdx.h"

/*
 * TDX module status during initialization
 */
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

static u32 tdx_keyid_start __ro_after_init;
static u32 tdx_keyid_num __ro_after_init;

static enum tdx_module_status_t tdx_module_status;
/* Prevent concurrent attempts on TDX detection and initialization */
static DEFINE_MUTEX(tdx_module_lock);

/* Below two are used in TDH.SYS.INFO SEAMCALL ABI */
static struct tdsysinfo_struct tdx_sysinfo;
static struct cmr_info tdx_cmr_array[MAX_CMRS] __aligned(CMR_INFO_ARRAY_ALIGNMENT);
static int tdx_cmr_num;

/* Detect whether CPU supports SEAM */
static int detect_seam(void)
{
	u64 mtrrcap, mask;

	/* SEAMRR is reported via MTRRcap */
	if (!boot_cpu_has(X86_FEATURE_MTRR))
		return -ENODEV;

	rdmsrl(MSR_MTRRcap, mtrrcap);
	if (!(mtrrcap & MTRR_CAP_SEAMRR))
		return -ENODEV;

	/* The MASK MSR reports whether SEAMRR is enabled */
	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, mask);
	if ((mask & SEAMRR_ENABLED_BITS) != SEAMRR_ENABLED_BITS)
		return -ENODEV;

	pr_info("SEAMRR enabled.\n");
	return 0;
}

static int detect_tdx_keyids(void)
{
	u64 keyid_part;

	rdmsrl(MSR_IA32_MKTME_KEYID_PARTITIONING, keyid_part);

	tdx_keyid_num = TDX_KEYID_NUM(keyid_part);
	tdx_keyid_start = TDX_KEYID_START(keyid_part);

	pr_info("TDX private KeyID range: [%u, %u).\n",
			tdx_keyid_start, tdx_keyid_start + tdx_keyid_num);

	/*
	 * TDX guarantees at least two TDX KeyIDs are configured by
	 * BIOS, otherwise SEAMRR is disabled.  Invalid TDX private
	 * range means kernel bug (TDX is broken).
	 */
	if (WARN_ON(!tdx_keyid_start || tdx_keyid_num < 2)) {
		tdx_keyid_start = tdx_keyid_num = 0;
		return -EINVAL;
	}

	return 0;
}

/*
 * Detect TDX via detecting SEAMRR during kernel boot.
 *
 * To enable TDX, BIOS must configure SEAMRR consistently across all
 * CPU cores.  TDX doesn't trust BIOS.  Instead, MCHECK verifies all
 * configurations from BIOS are correct, and if not, it disables TDX
 * (SEAMRR is disabled on all cores).  This means detecting SEAMRR on
 * BSP is enough to determine whether TDX has been enabled by BIOS.
 */
static int __init tdx_early_detect(void)
{
	int ret;

	ret = detect_seam();
	if (ret)
		return ret;

	/*
	 * TDX private KeyIDs is only accessible by SEAM software.
	 * Only detect TDX KeyIDs when SEAMRR is enabled.
	 */
	ret = detect_tdx_keyids();
	if (ret)
		return ret;

	/* Set TDX enabled platform as confidential computing platform */
	cc_set_vendor(CC_VENDOR_INTEL);

	pr_info("TDX enabled by BIOS.\n");
	return 0;
}
early_initcall(tdx_early_detect);

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
 * Wrapper of __seamcall().  It additionally prints out the error
 * informationi if __seamcall() fails normally.  It is useful during
 * the module initialization by providing more information to the user.
 */
static u64 seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		    struct tdx_module_output *out)
{
	u64 ret;

	ret = __seamcall(fn, rcx, rdx, r8, r9, out);
	if (ret == TDX_SEAMCALL_VMFAILINVALID || !ret)
		return ret;

	pr_err("SEAMCALL failed: leaf: 0x%llx, error: 0x%llx\n", fn, ret);
	if (out)
		pr_err("SEAMCALL additional output: rcx 0x%llx, rdx 0x%llx, r8 0x%llx, r9 0x%llx, r10 0x%llx, r11 0x%llx.\n",
			out->rcx, out->rdx, out->r8, out->r9, out->r10, out->r11);

	return ret;
}

static void seamcall_smp_call_function(void *data)
{
	struct seamcall_ctx *sc = data;
	struct tdx_module_output out;
	u64 ret;

	ret = seamcall(sc->fn, sc->rcx, sc->rdx, sc->r8, sc->r9, &out);
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

/*
 * Do TDX module global initialization.  It also detects whether the
 * module has been loaded or not.
 */
static int tdx_module_init_global(void)
{
	u64 ret;

	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL);
	if (ret == TDX_SEAMCALL_VMFAILINVALID)
		return -ENODEV;

	return ret ? -EFAULT : 0;
}

static int tdx_module_init_cpus(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_INIT };

	seamcall_on_each_cpu(&sc);

	return atomic_read(&sc.err);
}

static inline bool cmr_valid(struct cmr_info *cmr)
{
	return !!cmr->size;
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

/*
 * Check the CMRs reported by TDH.SYS.INFO and update the actual number
 * of CMRs.  The CMRs returned by the TDH.SYS.INFO may contain invalid
 * CMRs after the last valid CMR, but there should be no invalid CMRs
 * between two valid CMRs.  Check and update the actual number of CMRs
 * number by dropping all tail empty CMRs.
 */
static int check_cmrs(struct cmr_info *cmr_array, int *actual_cmr_num)
{
	int cmr_num = *actual_cmr_num;
	int i, j;

	/*
	 * Intel TDX module spec, 20.7.3 CMR_INFO:
	 *
	 *   TDH.SYS.INFO leaf function returns a MAX_CMRS (32) entry
	 *   array of CMR_INFO entries. The CMRs are sorted from the
	 *   lowest base address to the highest base address, and they
	 *   are non-overlapping.
	 *
	 * This implies that BIOS may generate invalid empty entries
	 * if total CMRs are less than 32.  Skip them manually.
	 */
	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];
		struct cmr_info *prev_cmr = NULL;

		/* Skip further invalid CMRs */
		if (!cmr_valid(cmr))
			break;

		if (i > 0)
			prev_cmr = &cmr_array[i - 1];

		/*
		 * It is a TDX firmware bug if CMRs are not
		 * in address ascending order.
		 */
		if (prev_cmr && ((prev_cmr->base + prev_cmr->size) >
					cmr->base)) {
			print_cmrs(cmr_array, cmr_num, "BIOS-CMR");
			pr_err("Firmware bug: CMRs not in address ascending order.\n");
			return -EINVAL;
		}
	}

	/*
	 * Also a sane BIOS should never generate invalid CMR(s) between
	 * two valid CMRs.  Sanity check this and simply return error in
	 * this case.
	 *
	 * By reaching here @i is the index of the first invalid CMR (or
	 * cmr_num).  Starting with next entry of @i since it has already
	 * been checked.
	 */
	for (j = i + 1; j < cmr_num; j++) {
		if (cmr_valid(&cmr_array[j])) {
			print_cmrs(cmr_array, cmr_num, "BIOS-CMR");
			pr_err("Firmware bug: invalid CMR(s) before valid CMRs.\n");
			return -EINVAL;
		}
	}

	/*
	 * Trim all tail invalid empty CMRs.  BIOS should generate at
	 * least one valid CMR, otherwise it's a TDX firmware bug.
	 */
	if (i == 0) {
		print_cmrs(cmr_array, cmr_num, "BIOS-CMR");
		pr_err("Firmware bug: No valid CMR.\n");
		return -EINVAL;
	}

	/* Update the actual number of CMRs */
	*actual_cmr_num = i;

	/* Print kernel checked CMRs */
	print_cmrs(cmr_array, *actual_cmr_num, "Kernel-checked-CMR");

	return 0;
}

static int tdx_get_sysinfo(struct tdsysinfo_struct *tdsysinfo,
			   struct cmr_info *cmr_array,
			   int *actual_cmr_num)
{
	struct tdx_module_output out;
	u64 ret;

	BUILD_BUG_ON(sizeof(struct tdsysinfo_struct) != TDSYSINFO_STRUCT_SIZE);

	ret = seamcall(TDH_SYS_INFO, __pa(tdsysinfo), TDSYSINFO_STRUCT_SIZE,
			__pa(cmr_array), MAX_CMRS, &out);
	if (ret)
		return -EFAULT;

	/* R9 contains the actual entries written the CMR array. */
	*actual_cmr_num = out.r9;

	pr_info("TDX module: vendor_id 0x%x, major_version %u, minor_version %u, build_date %u, build_num %u",
		tdsysinfo->vendor_id, tdsysinfo->major_version,
		tdsysinfo->minor_version, tdsysinfo->build_date,
		tdsysinfo->build_num);

	/*
	 * check_cmrs() updates the actual number of CMRs by dropping all
	 * tail invalid CMRs.
	 */
	return check_cmrs(cmr_array, actual_cmr_num);
}

/*
 * Skip the memory region below 1MB.  Return true if the entire
 * region is skipped.  Otherwise, the updated range is returned.
 */
static bool pfn_range_skip_lowmem(unsigned long *p_start_pfn,
				  unsigned long *p_end_pfn)
{
	u64 start, end;

	start = *p_start_pfn << PAGE_SHIFT;
	end = *p_end_pfn << PAGE_SHIFT;

	if (start < SZ_1M)
		start = SZ_1M;

	if (start >= end)
		return true;

	*p_start_pfn = (start >> PAGE_SHIFT);

	return false;
}

/*
 * Walks over all memblock memory regions that are intended to be
 * converted to TDX memory.  Essentially, it is all memblock memory
 * regions excluding the low memory below 1MB.
 *
 * This is because on some TDX platforms the low memory below 1MB is
 * not included in CMRs.  Excluding the low 1MB can still guarantee
 * that the pages managed by the page allocator are always TDX memory,
 * as the low 1MB is reserved during kernel boot and won't end up to
 * the ZONE_DMA (see reserve_real_mode()).
 */
#define memblock_for_each_tdx_mem_pfn_range(i, p_start, p_end, p_nid)	\
	for_each_mem_pfn_range(i, MAX_NUMNODES, p_start, p_end, p_nid)	\
		if (!pfn_range_skip_lowmem(p_start, p_end))

/* Check whether first range is the subrange of the second */
static bool is_subrange(u64 r1_start, u64 r1_end, u64 r2_start, u64 r2_end)
{
	return r1_start >= r2_start && r1_end <= r2_end;
}

/* Check whether address range is covered by any CMR or not. */
static bool range_covered_by_cmr(struct cmr_info *cmr_array, int cmr_num,
				 u64 start, u64 end)
{
	int i;

	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		if (is_subrange(start, end, cmr->base, cmr->base + cmr->size))
			return true;
	}

	return false;
}

/*
 * Check whether all memory regions in memblock are TDX convertible
 * memory.  Return 0 if all memory regions are convertible, or error.
 */
static int check_memblock_tdx_convertible(void)
{
	unsigned long start_pfn, end_pfn;
	int i;

	memblock_for_each_tdx_mem_pfn_range(i, &start_pfn, &end_pfn, NULL) {
		u64 start, end;

		start = start_pfn << PAGE_SHIFT;
		end = end_pfn << PAGE_SHIFT;
		if (!range_covered_by_cmr(tdx_cmr_array, tdx_cmr_num, start,
					end)) {
			pr_err("[0x%llx, 0x%llx) is not fully convertible memory\n",
					start, end);
			return -EINVAL;
		}
	}

	return 0;
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
	 * cal_tdmr_size() always return 512-byte aligned size.
	 */
	*array_sz = cal_tdmr_size() * tdx_sysinfo.max_tdmrs;

	/*
	 * Zero the buffer so 'struct tdmr_info::size' can be
	 * used to determine whether a TDMR is valid.
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
 * Create TDMRs to cover all memory regions in memblock.  The actual
 * number of TDMRs is set to @tdmr_num.
 */
static int create_tdmrs(struct tdmr_info *tdmr_array, int *tdmr_num)
{
	unsigned long start_pfn, end_pfn;
	int i, nid, tdmr_idx = 0;

	/*
	 * Loop over all memory regions in memblock and create TDMRs to
	 * cover them.  To keep it simple, always try to use one TDMR to
	 * cover memory region.
	 */
	memblock_for_each_tdx_mem_pfn_range(i, &start_pfn, &end_pfn, &nid) {
		struct tdmr_info *tdmr;
		u64 start, end;

		tdmr = tdmr_array_entry(tdmr_array, tdmr_idx);
		start = TDMR_ALIGN_DOWN(start_pfn << PAGE_SHIFT);
		end = TDMR_ALIGN_UP(end_pfn << PAGE_SHIFT);

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
			 * region has already fully covered by the
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

/* Page sizes supported by TDX */
enum tdx_page_sz {
	TDX_PG_4K,
	TDX_PG_2M,
	TDX_PG_1G,
	TDX_PG_MAX,
};

/*
 * Calculate PAMT size given a TDMR and a page size.  The returned
 * PAMT size is always aligned up to 4K page boundary.
 */
static unsigned long tdmr_get_pamt_sz(struct tdmr_info *tdmr,
				      enum tdx_page_sz pgsz)
{
	unsigned long pamt_sz;
	int pamt_entry_nr;

	switch (pgsz) {
	case TDX_PG_4K:
		pamt_entry_nr = tdmr->size >> PAGE_SHIFT;
		break;
	case TDX_PG_2M:
		pamt_entry_nr = tdmr->size >> PMD_SHIFT;
		break;
	case TDX_PG_1G:
		pamt_entry_nr = tdmr->size >> PUD_SHIFT;
		break;
	default:
		WARN_ON_ONCE(1);
		return 0;
	}

	pamt_sz = pamt_entry_nr * tdx_sysinfo.pamt_entry_size;
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
	unsigned long start_pfn, end_pfn;
	int i, nid;

	/* Find the first memory region covered by the TDMR */
	memblock_for_each_tdx_mem_pfn_range(i, &start_pfn, &end_pfn, &nid) {
		if (end_pfn > (tdmr_start(tdmr) >> PAGE_SHIFT))
			return nid;
	}

	/*
	 * No memory region found for this TDMR.  It cannot happen since
	 * when one TDMR is created, it must cover at least one (or
	 * partial) memory region.
	 */
	WARN_ON_ONCE(1);
	return 0;
}

static int tdmr_set_up_pamt(struct tdmr_info *tdmr)
{
	unsigned long pamt_base[TDX_PG_MAX];
	unsigned long pamt_size[TDX_PG_MAX];
	unsigned long tdmr_pamt_base;
	unsigned long tdmr_pamt_size;
	enum tdx_page_sz pgsz;
	struct page *pamt;
	int nid;

	nid = tdmr_get_nid(tdmr);

	/*
	 * Calculate the PAMT size for each TDX supported page size
	 * and the total PAMT size.
	 */
	tdmr_pamt_size = 0;
	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++) {
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

	/* Calculate PAMT base and size for all supported page sizes. */
	tdmr_pamt_base = page_to_pfn(pamt) << PAGE_SHIFT;
	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++) {
		pamt_base[pgsz] = tdmr_pamt_base;
		tdmr_pamt_base += pamt_size[pgsz];
	}

	tdmr->pamt_4k_base = pamt_base[TDX_PG_4K];
	tdmr->pamt_4k_size = pamt_size[TDX_PG_4K];
	tdmr->pamt_2m_base = pamt_base[TDX_PG_2M];
	tdmr->pamt_2m_size = pamt_size[TDX_PG_2M];
	tdmr->pamt_1g_base = pamt_base[TDX_PG_1G];
	tdmr->pamt_1g_size = pamt_size[TDX_PG_1G];

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

static unsigned long tdmrs_get_pamt_pages(struct tdmr_info *tdmr_array,
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

/*
 * Construct an array of TDMRs to cover all memory regions in memblock.
 * This makes sure all pages managed by the page allocator are TDX
 * memory.  The actual number of TDMRs is kept to @tdmr_num.
 */
static int construct_tdmrs_memeblock(struct tdmr_info *tdmr_array,
				     int *tdmr_num)
{
	int ret;

	ret = create_tdmrs(tdmr_array, tdmr_num);
	if (ret)
		goto err;

	ret = tdmrs_set_up_pamt_all(tdmr_array, *tdmr_num);
	if (ret)
		goto err;

	/* Return -EINVAL until constructing TDMRs is done */
	ret = -EINVAL;
	tdmrs_free_pamt_all(tdmr_array, *tdmr_num);
err:
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
	 * Whether the TDX module is loaded is still unknown.  SEAMCALL
	 * instruction fails with VMfailInvalid if the target SEAM
	 * software module is not loaded, so it can be used to detect the
	 * module.
	 *
	 * The first step of initializing the TDX module is module global
	 * initialization.  Just use it to detect the module.
	 */
	ret = tdx_module_init_global();
	if (ret)
		goto out;

	/* Logical-cpu scope initialization */
	ret = tdx_module_init_cpus();
	if (ret)
		goto out;

	ret = tdx_get_sysinfo(&tdx_sysinfo, tdx_cmr_array, &tdx_cmr_num);
	if (ret)
		goto out;

	/*
	 * To avoid having to modify the page allocator to distinguish
	 * TDX and non-TDX memory allocation, convert all memory regions
	 * in memblock to TDX memory to make sure all pages managed by
	 * the page allocator are TDX memory.
	 *
	 * Sanity check all memory regions are fully covered by CMRs to
	 * make sure they are truly convertible.
	 */
	ret = check_memblock_tdx_convertible();
	if (ret)
		goto out;

	/* Prepare enough space to construct TDMRs */
	tdmr_array = alloc_tdmr_array(&tdmr_array_sz);
	if (!tdmr_array) {
		ret = -ENOMEM;
		goto out;
	}

	/* Construct TDMRs to cover all memory regions in memblock */
	ret = construct_tdmrs_memeblock(tdmr_array, &tdmr_num);
	if (ret)
		goto out_free_tdmrs;

	/*
	 * Return -EINVAL until all steps of TDX module initialization
	 * process are done.
	 */
	ret = -EINVAL;
	if (ret)
		tdmrs_free_pamt_all(tdmr_array, tdmr_num);
	else
		pr_info("%lu pages allocated for PAMT.\n",
				tdmrs_get_pamt_pages(tdmr_array, tdmr_num));
out_free_tdmrs:
	/*
	 * The array of TDMRs is freed no matter the initialization is
	 * successful or not.  They are not needed anymore after the
	 * module initialization.
	 */
	free_pages_exact(tdmr_array, tdmr_array_sz);
out:
	return ret;
}

static void shutdown_tdx_module(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_SHUTDOWN };

	seamcall_on_each_cpu(&sc);

	tdx_module_status = TDX_MODULE_SHUTDOWN;
}

static int __tdx_init(void)
{
	int ret;

	/*
	 * Initializing the TDX module requires running some code on
	 * all MADT-enabled CPUs.  If not all MADT-enabled CPUs are
	 * online, it's not possible to initialize the TDX module.
	 *
	 * For simplicity temporarily disable CPU hotplug to prevent
	 * any CPU from going offline during the initialization.
	 */
	cpus_read_lock();

	/*
	 * Check whether all MADT-enabled CPUs are online and return
	 * early with an explicit message so the user can be aware.
	 *
	 * Note ACPI CPU hotplug is prevented when TDX is enabled, so
	 * num_processors always reflects all present MADT-enabled
	 * CPUs during boot when disabled_cpus is 0.
	 */
	if (disabled_cpus || num_online_cpus() != num_processors) {
		pr_err("Unable to initialize the TDX module when there's offline CPU(s).\n");
		ret = -EINVAL;
		goto out;
	}

	ret = init_tdx_module();
	if (ret == -ENODEV) {
		pr_info("TDX module is not loaded.\n");
		goto out;
	}

	/*
	 * Shut down the TDX module in case of any error during the
	 * initialization process.  It's meaningless to leave the TDX
	 * module in any middle state of the initialization process.
	 *
	 * Shutting down the module also requires running some code on
	 * all MADT-enabled CPUs.  Do it while CPU hotplug is disabled.
	 *
	 * Return all errors during initialization as -EFAULT as
	 * the TDX module is always shut down in such cases.
	 */
	if (ret) {
		pr_info("Failed to initialize TDX module.  Shut it down.\n");
		shutdown_tdx_module();
		ret = -EFAULT;
		goto out;
	}

	pr_info("TDX module initialized.\n");
out:
	cpus_read_unlock();

	return ret;
}

/**
 * platform_tdx_enabled() - Return whether BIOS has enabled TDX
 *
 * Return whether BIOS has enabled TDX regardless whether the TDX module
 * has been loaded or not.
 */
bool platform_tdx_enabled(void)
{
	return tdx_keyid_num >= 2;
}

/**
 * tdx_init - Initialize the TDX module
 *
 * Initialize the TDX module to make it ready to run TD guests.
 *
 * Caller to make sure all CPUs are online before calling this function.
 * CPU hotplug is temporarily disabled internally to prevent any cpu
 * from going offline.
 *
 * Caller also needs to guarantee all CPUs are in VMX operation during
 * this function, otherwise Oops may be triggered.
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
int tdx_init(void)
{
	int ret;

	if (!platform_tdx_enabled())
		return -ENODEV;

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNKNOWN:
		ret = __tdx_init();
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
EXPORT_SYMBOL_GPL(tdx_init);
