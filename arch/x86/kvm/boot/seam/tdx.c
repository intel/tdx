// SPDX-License-Identifier: GPL-2.0
#include <linux/earlycpio.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/percpu.h>
#include <linux/memblock.h>
#include <linux/idr.h>
#include <linux/sort.h>

#include <asm/cpu.h>
#include <asm/cmdline.h>
#include <asm/kvm_boot.h>
#include <asm/sync_core.h>
#include <asm/virtext.h>
#include <asm/tlbflush.h>
#include <asm/e820/api.h>

#include "seamloader.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

#include "vmx/tdx_arch.h"
#include "vmx/tdx_errno.h"

#include "vmx/vmcs.h"

struct seamldr_info p_seamldr_info __aligned(256);

/*
 * TDX system information returned by TDSYSINFO.
 */
static struct tdsysinfo_struct tdx_tdsysinfo;

/*
 * CMR info array returned by TDSYSINFO.
 *
 * TDSYSINFO doesn't return specific error code indicating whether we didn't
 * pass long-enough CMR info array to it, so just reserve enough space for
 * the maximum number of CMRs.
 */
static struct cmr_info tdx_cmrs[TDX1_MAX_NR_CMRS] __aligned(512);
static int tdx_nr_cmrs;

/*
 * TDMR info array used as input for TDSYSCONFIG.
 */
static struct tdmr_info tdx_tdmrs[TDX1_MAX_NR_TDMRS] __initdata;
static int tdx_nr_tdmrs __initdata;

/* TDMRs must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT_ULL(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

struct pamt_info {
	u64 pamt_base;
	u64 pamt_size;
};

/*
 * PAMT info for each TDMR, used to free PAMT when TDX is disabled due to
 * whatever reason.
 */
static struct pamt_info tdx_pamts[TDX1_MAX_NR_TDMRS] __initdata;

static int __init set_tdmr_reserved_area(struct tdmr_info *tdmr, int *p_idx,
					 u64 offset, u64 size)
{
	int idx = *p_idx;

	if (idx >= tdx_tdsysinfo.max_reserved_per_tdmr)
		return -EINVAL;

	/* offset & size must be 4K aligned */
	if (offset & ~PAGE_MASK || size & ~PAGE_MASK)
		return -EINVAL;

	tdmr->reserved_areas[idx].offset = offset;
	tdmr->reserved_areas[idx].size = size;

	*p_idx = idx + 1;
	return 0;
}

/*
 * Construct TDMR reserved areas.
 *
 * Two types of address range will be put into reserved areas: 1) PAMT range,
 * since PAMT cannot overlap with TDMR non-reserved range; 2) any CMR hole
 * within TDMR range, since TDMR non-reserved range must be in CMR.
 *
 * Note: we are not putting any memory hole made by kernel (which is not CMR
 * hole -- i.e. some memory range is reserved by kernel and won't be freed to
 * page allocator, and it is memory hole from page allocator's view) into
 * reserved area for the sake of simplicity of implementation. The other
 * reason is for TDX1 one TDMR can only have upto 16 reserved areas so if
 * there are lots of holes we won't be have enough reserved areas to hold
 * them. This is OK, since kernel page allocator will never allocate pages
 * from those areas (as they are invalid). PAMT may internally mark them as
 * 'normal' pages but it is OK.
 *
 * Returns -EINVAL if number of reserved areas exceeds TDX1 limitation.
 *
 */
static int __init __construct_tdmr_reserved_areas(struct tdmr_info *tdmr,
						  u64 pamt_base, u64 pamt_size)
{
	u64 tdmr_start, tdmr_end, offset, size;
	struct cmr_info *cmr, *next_cmr;
	bool pamt_done = false;
	int i, idx, ret;

	memset(tdmr->reserved_areas, 0, sizeof(tdmr->reserved_areas));

	/* Save some typing later */
	tdmr_start = tdmr->base;
	tdmr_end = tdmr->base + tdmr->size;

	if (WARN_ON(!tdx_nr_cmrs))
		return -EINVAL;
	/*
	 * Find the first CMR whose end is greater than tdmr_start_pfn.
	 */
	cmr = &tdx_cmrs[0];
	for (i = 0; i < tdx_nr_cmrs; i++) {
		cmr = &tdx_cmrs[i];
		if ((cmr->base + cmr->size) > tdmr_start)
			break;
	}

	/* Unable to find ?? Something is wrong here */
	if (i == tdx_nr_cmrs)
		return -EINVAL;

	/*
	 * If CMR base is within TDMR range, [tdmr_start, cmr->base) needs to be
	 * in reserved area.
	 */
	idx = 0;
	if (cmr->base > tdmr_start) {
		offset = 0;
		size = cmr->base - tdmr_start;

		ret = set_tdmr_reserved_area(tdmr, &idx, offset, size);
		if (ret)
			return ret;
	}

	/*
	 * Check whether there's any hole between CMRs within TDMR range.
	 * If there is any, it needs to be in reserved area.
	 */
	for (++i; i < tdx_nr_cmrs; i++) {
		next_cmr = &tdx_cmrs[i];

		/*
		 * If next CMR is beyond TDMR range, there's no CMR hole within
		 * TDMR range, and we only need to insert PAMT into reserved
		 * area, thus  we are done here.
		 */
		if (next_cmr->base >= tdmr_end)
			break;

		/* Otherwise need to have CMR hole in reserved area */
		if (cmr->base + cmr->size < next_cmr->base) {
			offset = cmr->base + cmr->size - tdmr_start;
			size = next_cmr->base - (cmr->base + cmr->size);

			/*
			 * Reserved areas needs to be in physical address
			 * ascending order, therefore we need to check PAMT
			 * range before filling any CMR hole into reserved
			 * area.
			 */
			if (pamt_base < tdmr_start + offset) {
				/*
				 * PAMT won't overlap with any CMR hole
				 * otherwise there's bug -- see comments below.
				 */
				if (WARN_ON((pamt_base + pamt_size) >
					    (tdmr_start + offset)))
					return -EINVAL;

				ret = set_tdmr_reserved_area(tdmr, &idx,
							     pamt_base - tdmr_start,
							     pamt_size);
				if (ret)
					return ret;

				pamt_done = true;
			}

			/* Insert CMR hole into reserved area */
			ret = set_tdmr_reserved_area(tdmr, &idx, offset, size);
			if (ret)
				return ret;
		}

		cmr = next_cmr;
	}

	if (!pamt_done) {
		/*
		 * PAMT won't overlap with CMR range, otherwise there's bug
		 * -- we have guaranteed this by checking all CMRs have
		 * covered all memory in e820.
		 */
		if (WARN_ON((pamt_base + pamt_size) > (cmr->base + cmr->size)))
			return -EINVAL;

		ret = set_tdmr_reserved_area(tdmr, &idx,
					     pamt_base - tdmr_start, pamt_size);
		if (ret)
			return ret;
	}

	/*
	 * If CMR end is in TDMR range, [cmr->end, tdmr_end) needs to be in
	 * reserved area.
	 */
	if (cmr->base + cmr->size < tdmr_end) {
		offset = cmr->base + cmr->size - tdmr_start;
		size = tdmr_end - (cmr->base + cmr->size);

		ret = set_tdmr_reserved_area(tdmr, &idx, offset, size);
		if (ret)
			return ret;
	}

	return 0;
}

static int __init __construct_tdmr_node(int tdmr_idx,
					unsigned long tdmr_start_pfn,
					unsigned long tdmr_end_pfn)
{
	u64 tdmr_size, pamt_1g_size, pamt_2m_size, pamt_4k_size, pamt_size;
	struct pamt_info *pamt = &tdx_pamts[tdmr_idx];
	struct tdmr_info *tdmr = &tdx_tdmrs[tdmr_idx];
	u64 pamt_phys;
	int ret;

	tdmr_size = (tdmr_end_pfn - tdmr_start_pfn) << PAGE_SHIFT;

	/* sanity check */
	if (!tdmr_size || !IS_ALIGNED(tdmr_size, TDMR_ALIGNMENT))
		return -EINVAL;

	/* 1 entry to cover 1G */
	pamt_1g_size = (tdmr_size >> 30) * tdx_tdsysinfo.pamt_entry_size;
	/* 1 entry to cover 2M */
	pamt_2m_size = (tdmr_size >> 21) * tdx_tdsysinfo.pamt_entry_size;
	/* 1 entry to cover 4K */
	pamt_4k_size = (tdmr_size >> 12) * tdx_tdsysinfo.pamt_entry_size;

	pamt_size = ALIGN(pamt_1g_size, PAGE_SIZE) +
		    ALIGN(pamt_2m_size, PAGE_SIZE) +
		    ALIGN(pamt_4k_size, PAGE_SIZE);

	pamt_phys = memblock_phys_alloc_range(pamt_size, PAGE_SIZE,
					      tdmr_start_pfn << PAGE_SHIFT,
					      tdmr_end_pfn << PAGE_SHIFT);
	if (!pamt_phys)
		return -ENOMEM;

	tdmr->base = tdmr_start_pfn << PAGE_SHIFT;
	tdmr->size = tdmr_size;

	/* PAMT for 1G at first */
	tdmr->pamt_1g_base = pamt_phys;
	tdmr->pamt_1g_size = ALIGN(pamt_1g_size, PAGE_SIZE);
	/* PAMT for 2M right after PAMT for 1G */
	tdmr->pamt_2m_base = tdmr->pamt_1g_base + tdmr->pamt_1g_size;
	tdmr->pamt_2m_size = ALIGN(pamt_2m_size, PAGE_SIZE);
	/* PAMT for 4K comes after PAMT for 2M */
	tdmr->pamt_4k_base = tdmr->pamt_2m_base + tdmr->pamt_2m_size;
	tdmr->pamt_4k_size = ALIGN(pamt_4k_size, PAGE_SIZE);

	/* Construct TDMR's reserved areas */
	ret = __construct_tdmr_reserved_areas(tdmr, tdmr->pamt_1g_base,
					      pamt_size);
	if (ret) {
		memblock_free(pamt_phys, pamt_size);
		return ret;
	}

	/* Record PAMT info for this TDMR */
	pamt->pamt_base = pamt_phys;
	pamt->pamt_size = pamt_size;

	return 0;
}

/*
 * Convert node's memory into TDMRs as less as possible.
 *
 * @node_start_pfn and @node_end_pfn are not node's real memory region, but
 * already 1G aligned passed from caller.
 */
static int __init construct_tdmr_node(int *p_tdmr_idx,
				      unsigned long tdmr_start_pfn,
				      unsigned long tdmr_end_pfn)
{
	u64 start_pfn, end_pfn, mid_pfn;
	int ret = 0, idx = *p_tdmr_idx;

	start_pfn = tdmr_start_pfn;
	end_pfn = tdmr_end_pfn;

	while (start_pfn < tdmr_end_pfn) {
		/* Cast to u32, else compiler will sign extend and complain. */
		if (idx >= (u32)tdx_tdsysinfo.max_tdmrs) {
			ret = -EINVAL;
			break;
		}

		ret = __construct_tdmr_node(idx, start_pfn, end_pfn);

		/*
		 * Try again with smaller TDMR if the failure was due to unable
		 * to allocate PAMT.
		 */
		if (ret == -ENOMEM) {
			mid_pfn = start_pfn + (end_pfn - start_pfn) / 2;
			mid_pfn = ALIGN_DOWN(mid_pfn, TDMR_PFN_ALIGNMENT);
			mid_pfn = max(mid_pfn, start_pfn + TDMR_PFN_ALIGNMENT);
			if (mid_pfn == end_pfn) {
				/*
				 * This region is too small to use. Mark it
				 * reserved.
				 */
				memblock_reserve(start_pfn << PAGE_SHIFT,
						 (end_pfn - start_pfn) * PAGE_SIZE);
				start_pfn = mid_pfn;
				end_pfn = tdmr_end_pfn;
				ret = 0;
				continue;
			}

			end_pfn = mid_pfn;
			continue;
		} else if (ret) {
			break;
		}

		/* Successfully done with one TDMR, and continue if there's remaining */
		start_pfn = end_pfn;
		end_pfn = tdmr_end_pfn;
		idx++;
	}

	/* Setup next TDMR entry to work on */
	*p_tdmr_idx = idx;
	return ret;
}

/*
 * Construct TDMR based on system memory info and CMR info. To avoid modifying
 * kernel core-mm page allocator to have TDMR specific logic for memory
 * allocation in TDMR, we choose to simply convert all memory to TDMR, with the
 * disadvantage of wasting some memory for PAMT, but since TDX is mainly a
 * virtualization feature so it is expected majority of memory will be used as
 * TD guest memory so wasting some memory for PAMT won't be big issue.
 *
 * There are some restrictions of TDMR/PAMT/CMR:
 *
 *  - TDMR's base and size need to be 1G aligned.
 *  - TDMR's size need to be multiple of 1G.
 *  - TDMRs cannot overlap with each other.
 *  - PAMTs cannot overlap with each other.
 *  - Each TDMR can have reserved areas (TDX1 upto 16).
 *  - TDMR reserved areas must be in physical address ascending order.
 *  - TDMR non-reserved area must be in CMR.
 *  - TDMR reserved area doesn't have to be in CMR.
 *  - TDMR non-reserved area cannot overlap with PAMT.
 *  - PAMT may reside within TDMR reserved area.
 *  - PAMT must be in CMR.
 *
 */
static int __init __construct_tdmrs(void)
{
	u64 tdmr_start_pfn, tdmr_end_pfn, tdmr_start_pfn_next, inc_pfn;
	unsigned long start_pfn, end_pfn;
	int last_nid, nid, i, idx, ret;

	/* Sanity check on tdx_tdsysinfo... */
	if (!tdx_tdsysinfo.max_tdmrs || !tdx_tdsysinfo.max_reserved_per_tdmr ||
	    !tdx_tdsysinfo.pamt_entry_size) {
		pr_err("Invalid TDSYSINFO_STRUCT reported by TDSYSINFO.\n");
		return -EOPNOTSUPP;
	}

	idx = 0;
	tdmr_start_pfn = 0;
	tdmr_end_pfn = 0;
	last_nid = MAX_NUMNODES;
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		if (last_nid == MAX_NUMNODES) {
			/* First memory range */
			last_nid = nid;
			tdmr_start_pfn = ALIGN_DOWN(start_pfn, TDMR_PFN_ALIGNMENT);
			tdmr_end_pfn = ALIGN(end_pfn, TDMR_PFN_ALIGNMENT);
			WARN_ON(tdmr_start_pfn != 0);
		} else if (nid == last_nid) {
			/*
			 * This memory range is in the same node as previous
			 * one, update tdmr_end_pfn.
			 */
			tdmr_end_pfn = ALIGN(end_pfn, TDMR_PFN_ALIGNMENT);
		} else if (ALIGN_DOWN(start_pfn, TDMR_PFN_ALIGNMENT) >= tdmr_end_pfn) {
			/* This memory range is in next node */
			/*
			 * If new TDMR start pfn is greater than previous TDMR
			 * end pfn, then it's ready to convert previous node's
			 * memory to TDMR.
			 */
			ret = construct_tdmr_node(&idx, tdmr_start_pfn,
						  tdmr_end_pfn);
			if (ret)
				return ret;
			tdmr_start_pfn = ALIGN(start_pfn, TDMR_PFN_ALIGNMENT);
			tdmr_end_pfn = ALIGN(end_pfn, TDMR_PFN_ALIGNMENT);
			last_nid = nid;
		} else {
			/*
			 * This memory range is in the next node, and the
			 * boundary between nodes falls into 1G range. In this
			 * case, put beginning of second node into the TDMR
			 * which covers previous node. This is not ideal but
			 * this case is very unlikely as well so should be OK
			 * for now.
			 */
			tdmr_end_pfn = ALIGN(start_pfn, TDMR_PFN_ALIGNMENT);

			ret = construct_tdmr_node(&idx, tdmr_start_pfn,
						  tdmr_end_pfn);
			if (ret)
				return ret;

			tdmr_start_pfn = tdmr_end_pfn;
			tdmr_end_pfn = ALIGN(end_pfn, TDMR_PFN_ALIGNMENT);
			last_nid = nid;
		}
	}

	/* Spread out the remaining memory across multiple TDMRs. */
	inc_pfn = (tdmr_end_pfn - tdmr_start_pfn) /
		  (tdx_tdsysinfo.max_tdmrs - idx);
	inc_pfn = ALIGN(inc_pfn, TDMR_PFN_ALIGNMENT);

	tdmr_start_pfn_next = tdmr_end_pfn;
	while (tdmr_start_pfn < tdmr_start_pfn_next) {
		if (idx == tdx_tdsysinfo.max_tdmrs - 1)
			tdmr_end_pfn = tdmr_start_pfn_next;
		else
			tdmr_end_pfn = tdmr_start_pfn + inc_pfn;
retry:
		tdmr_end_pfn = min(tdmr_end_pfn, tdmr_start_pfn_next);

		ret = construct_tdmr_node(&idx, tdmr_start_pfn, tdmr_end_pfn);
		if (ret == -ENOMEM) {
			if (tdmr_end_pfn == tdmr_start_pfn_next)
				return -ENOMEM;
			tdmr_end_pfn += inc_pfn;
			goto retry;
		}
		if (ret)
			return ret;
		tdmr_start_pfn = tdmr_end_pfn;
	}

	tdx_nr_tdmrs = idx;

	return 0;
}

static int __init e820_type_cmr_ram(enum e820_type type)
{
	/*
	 * CMR needs to at least cover e820 memory regions which will be later
	 * freed to kernel memory allocator, otherwise kernel may allocate
	 * non-TDMR pages, i.e. when KVM allocates memory.
	 *
	 * Note memblock also treats E820_TYPE_RESERVED_KERN as memory so also
	 * need to cover it.
	 *
	 * FIXME:
	 *
	 * Need to cover other types which are actually RAM, i.e:
	 *
	 *   E820_TYPE_ACPI,
	 *   E820_TYPE_NVS
	 */
	return (type == E820_TYPE_RAM || type == E820_TYPE_RESERVED_KERN);
}

static int __init in_cmr_range(u64 addr, u64 size)
{
	struct cmr_info *cmr;
	u64 cmr_end, end;
	int i;

	end = addr + size;

	/* Ignore bad area */
	if (end < addr)
		return 1;

	for (i = 0; i < tdx_nr_cmrs; i++) {
		cmr = &tdx_cmrs[i];
		cmr_end = cmr->base + cmr->size;

		/* Found one CMR which covers the range [addr, addr + size) */
		if (cmr->base <= addr && cmr_end >= end)
			return 1;
	}

	return 0;
}

static int __init sanitize_cmrs(void)
{
	struct e820_entry *entry;
	bool observed_empty;
	int i, j;

	if (!tdx_nr_cmrs)
		return -EIO;

	for (i = 0, j = -1, observed_empty = false; i < tdx_nr_cmrs; i++) {
		if (!tdx_cmrs[i].size) {
			observed_empty = true;
			continue;
		}
		/* Valid entry after empty entry isn't allowed, per SEAM. */
		if (observed_empty)
			return -EIO;

		/* The previous CMR must reside fully below this CMR. */
		if (j >= 0 &&
		    (tdx_cmrs[j].base + tdx_cmrs[j].size) > tdx_cmrs[i].base)
			return -EIO;

		if (j < 0 ||
		    (tdx_cmrs[j].base + tdx_cmrs[j].size) != tdx_cmrs[i].base) {
			j++;
			if (i != j) {
				tdx_cmrs[j].base = tdx_cmrs[i].base;
				tdx_cmrs[j].size = tdx_cmrs[i].size;
			}
		} else {
			tdx_cmrs[j].size += tdx_cmrs[i].size;
		}
	}
	tdx_nr_cmrs = j + 1;
	if (!tdx_nr_cmrs)
		return -EINVAL;

	/*
	 * Sanity check whether CMR has covered all memory in E820. We need
	 * to make sure that CMR covers all memory that will be freed to page
	 * allocator, otherwise alloc_pages() may return non-TDMR pages, i.e.
	 * when KVM allocates memory for VM. Cannot allow that to happen, so
	 * disable TDX if we found CMR doesn't cover all.
	 *
	 * FIXME:
	 *
	 * Alternatively we could just check against memblocks? Only memblocks
	 * are freed to page allocator so it appears to be OK as long as CMR
	 * covers all memblocks. But CMR should be generated by BIOS thus should
	 * be cover e820..
	 */
	for (i = 0; i < e820_table->nr_entries; i++) {
		entry = &e820_table->entries[i];

		if (!e820_type_cmr_ram(entry->type))
			continue;

		if (!in_cmr_range(entry->addr, entry->size)) {
			pr_err("e820 ram [0x%llx - 0x%llx] not covered by CMRs\n",
			       entry->addr, entry->addr + entry->size);
			return -EINVAL;
		}
	}

	return 0;
}

static int __init construct_tdmrs(void)
{
	struct pamt_info *pamt;
	int ret, i;

	ret = sanitize_cmrs();
	if (ret)
		return ret;

	ret = __construct_tdmrs();
	if (ret)
		goto free_pamts;

	return 0;

free_pamts:
	for (i = 0; i < ARRAY_SIZE(tdx_pamts); i++) {
		pamt = &tdx_pamts[i];
		if (pamt->pamt_base && pamt->pamt_size) {
			if (WARN_ON(!IS_ALIGNED(pamt->pamt_base, PAGE_SIZE) ||
				    !IS_ALIGNED(pamt->pamt_size, PAGE_SIZE)))
				continue;

			memblock_free(pamt->pamt_base, pamt->pamt_size);
		}
	}

	memset(tdx_pamts, 0, sizeof(tdx_pamts));
	memset(tdx_tdmrs, 0, sizeof(tdx_tdmrs));
	tdx_nr_tdmrs = 0;
	return ret;
}

/*
 * Build information needed to construct TDMRs, such as max_tdmrs,
 * max_reserved_per_tdmr and pamt entry_size, and CMRs.
 *
 * Sanity check will be performed after this information becomes available
 * to ensure no violation against TDX module or hardware.
 */
static int __init build_tdsysinfo_and_cmrs_from_e820(void)
{
	struct e820_entry *entry;
	int i, j;

	tdx_tdsysinfo.max_tdmrs = TDX1_MAX_NR_TDMRS;
	tdx_tdsysinfo.max_reserved_per_tdmr = TDX1_MAX_NR_RSVD_AREAS;
	tdx_tdsysinfo.pamt_entry_size = TDX1_PAMT_ENTRY_SIZE;

	for (i = 0, j = 0; i < e820_table->nr_entries; i++) {
		entry = &e820_table->entries[i];

		if (!e820_type_cmr_ram(entry->type))
			continue;

		if (j == TDX1_MAX_NR_CMRS)
			return -EINVAL;

		tdx_cmrs[j].base = entry->addr;
		tdx_cmrs[j].size = entry->size;
		j++;
	}

	tdx_nr_cmrs = j;

	return 0;
}

static bool __init tdx_all_cpus_available(void)
{
	/*
	 * CPUs detected in ACPI can be marked as disabled due to:
	 *   1) disabled in ACPI MADT table
	 *   2) disabled by 'disable_cpu_apicid' kernel parameter, which
	 *     disables CPU with particular APIC id.
	 *   3) limited by 'nr_cpus' kernel parameter.
	 */
	if (disabled_cpus) {
		pr_info("Disabled CPUs detected");
		goto err;
	}

	if (num_possible_cpus() < num_processors) {
		pr_info("Number of CPUs limited by 'possible_cpus' kernel param");
		goto err;
	}

#ifdef CONFIG_SMP
	if (setup_max_cpus < num_processors) {
		pr_info("Boot-time CPUs limited by 'maxcpus' kernel param");
		goto err;
	}
#endif

	return true;

err:
	pr_cont(", skipping TDX-SEAM load/config.\n");
	return false;
}

static bool __init tdx_get_firmware(struct cpio_data *blob, const char *name)
{
	char path[64];
	long offset;
	void *data;
	size_t size;
	static const char * const search_path[] = {
		"lib/firmware/%s",
		"usr/lib/firmware/%s",
		"opt/intel/%s"
	};
	int i;

	if (get_builtin_firmware(blob, name))
		return true;

	if (!IS_ENABLED(CONFIG_BLK_DEV_INITRD) || !initrd_start)
		return false;

	for (i = 0; i < ARRAY_SIZE(search_path); i++) {
		offset = 0;
		data = (void *)initrd_start;
		size = initrd_end - initrd_start;
		snprintf(path, sizeof(path), search_path[i], name);
		while (size > 0) {
			*blob = find_cpio_data(path, data, size, &offset);

			/* find the filename, the returned blob name is empty */
			if (blob->data && blob->name[0] == '\0')
				return true;

			if (!blob->data)
				break;

			/* match the item with the same path prefix, skip it*/
			data += offset;
			size -= offset;
		}
	}

	return false;
}

void __init tdx_seam_init(void)
{
	const char *np_seamldr_name = "intel-seam/np-seamldr.acm";
	struct cpio_data seamldr;

	if (cmdline_find_option_bool(boot_command_line, "disable_tdx"))
		return;

	/*
	 * Don't load/configure SEAM if not all CPUs can be brought up during
	 * smp_init(), TDX must execute TDH_SYS_LP_INIT on all logical processors.
	 */
	if (!tdx_all_cpus_available())
		goto error;

	if (!tdx_get_firmware(&seamldr, np_seamldr_name)) {
		pr_err("no np-seamldr found\n");
		goto error;
	}

	if (seam_load_module(seamldr.data, seamldr.size)) {
		pr_err("failed to load np-seamldr\n");
		goto error;
	}

	if (seamldr_info(__pa(&p_seamldr_info))) {
		pr_info("Failed to get p-seamldr info\n");
		goto error;
	}
	pr_info("TDX P-SEAMLDR: "
		"attributes 0x%0x vendor_id 0x%x "
		"build_date %d build_num 0x%x "
		"minor_version 0x%x major_version 0x%x.\n",
		p_seamldr_info.attributes,
		p_seamldr_info.vendor_id,
		p_seamldr_info.build_date,
		p_seamldr_info.build_num,
		p_seamldr_info.minor_version,
		p_seamldr_info.major_version);

	if (build_tdsysinfo_and_cmrs_from_e820() || construct_tdmrs())
		goto error;

	setup_force_cpu_cap(X86_FEATURE_TDX);
	pr_info("tdx module successfully initialized.\n");
	return;

error:
	pr_err("can't load/init TDX module. disabling TDX feature.\n");
	setup_clear_cpu_cap(X86_FEATURE_TDX);
}
