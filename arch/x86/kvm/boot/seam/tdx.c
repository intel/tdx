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
#include "seamcall_boot.h"
#include "tdx_ops_boot.h"
#include "tdx_common.h"
#include "vmx/seamcall.h"

#include "vmx/vmcs.h"

struct seamldr_info p_seamldr_info __aligned(256);

static DEFINE_PER_CPU(unsigned long, tdx_vmxon_vmcs);
static atomic_t tdx_init_cpu_errors;

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
static atomic_t tdx_next_tdmr_index;
static atomic_t tdx_nr_initialized_tdmrs;

/* TDMRs must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT_ULL(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

/*
 * TDSYSCONFIG takes a array of pointers to TDMR infos.  Its just big enough
 * that allocating it on the stack is undesirable.
 */
static u64 tdx_tdmr_addrs[TDX1_MAX_NR_TDMRS] __aligned(TDX_TDMR_ADDR_ALIGNMENT) __initdata;

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

static inline int tdx_init_vmxon_vmcs(struct vmcs *vmcs)
{
	u64 msr;

	/*
	 * Can't enable TDX if VMX is unsupported or disabled by BIOS.
	 * cpu_has(X86_FEATURE_VMX) can't be relied on as the BSP calls this
	 * before the kernel has configured feat_ctl().
	 */
	if (!cpu_has_vmx())
		return -EOPNOTSUPP;

	if (rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ||
	    !(msr & FEAT_CTL_LOCKED) ||
	    !(msr & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX))
		return -EOPNOTSUPP;

	if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &msr))
		return -EOPNOTSUPP;

	memset(vmcs, 0, PAGE_SIZE);
	vmcs->hdr.revision_id = (u32)msr;

	return 0;
}

static inline void tdx_get_keyids(u32 *keyids_start, u32 *nr_keyids)
{
	u32 nr_mktme_ids;

	rdmsr(MSR_IA32_MKTME_KEYID_PART, nr_mktme_ids, *nr_keyids);

	/* KeyID 0 is reserved, i.e. KeyIDs are 1-based. */
	*keyids_start = nr_mktme_ids + 1;
}

/* Detect if wrong assumptions were made during TDMRs construction. */
static int __init sanity_check(void)
{
	if ((tdx_tdsysinfo.max_tdmrs != TDX1_MAX_NR_TDMRS) ||
	    (tdx_tdsysinfo.pamt_entry_size != TDX1_PAMT_ENTRY_SIZE) ||
	    (tdx_tdsysinfo.max_reserved_per_tdmr != TDX1_MAX_NR_RSVD_AREAS)) {
		pr_err("Early TDMRs are constructed based on wrong info.\n");
		return -EINVAL;
	}
	return 0;
}

static int tdx_init_cpu(unsigned long vmcs)
{
	u32 keyids_start, nr_keyids;
	struct tdx_ex_ret ex_ret;
	u64 err;

	/*
	 * MSR_IA32_MKTME_KEYID_PART is core-scoped, disable TDX if this CPU's
	 * partitioning doesn't match the BSP's partitioning.
	 */
	tdx_get_keyids(&keyids_start, &nr_keyids);
	if (keyids_start != tdx_keyids_start || nr_keyids != tdx_nr_keyids) {
		pr_err("MKTME KeyID partioning inconsistent on CPU %u\n",
		       smp_processor_id());
		return -EOPNOTSUPP;
	}

	cpu_vmxon(__pa(vmcs));
	err = tdh_sys_lp_init(&ex_ret);
	cpu_vmxoff();

	if (TDX_ERR(err, TDH_SYS_LP_INIT, &ex_ret))
		return -EIO;

	return 0;
}

static __init void tdx_init_local(void *unused)
{
	unsigned long vmcs;

	/* In case this cpu has been initialized. */
	WARN_ON(this_cpu_read(tdx_vmxon_vmcs));

	/* Allocate VMCS for VMXON. */
	vmcs = __get_free_page(GFP_ATOMIC);
	if (!vmcs)
		goto err;

	/* VMCS configuration shouldn't fail at this point. */
	if (WARN_ON_ONCE(tdx_init_vmxon_vmcs((void *)vmcs)))
		goto err_vmcs;

	if (tdx_init_cpu(vmcs))
		goto err_vmcs;

	this_cpu_write(tdx_vmxon_vmcs, vmcs);
	return;

err_vmcs:
	free_page(vmcs);
err:
	atomic_inc(&tdx_init_cpu_errors);
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

static __init int tdx_init_global(void)
{
	struct tdx_ex_ret ex_ret;
	unsigned long vmcs;
	u64 err;
	int ret;

	/*
	 * Detect HKID for TDX if initialization was successful.
	 *
	 * TDX provides core-scoped MSR for us to simply read out TDX start
	 * keyID and number of keyIDs.
	 */
	tdx_get_keyids(&tdx_keyids_start, &tdx_nr_keyids);
	if (!tdx_nr_keyids)
		return -EOPNOTSUPP;

	/* Allocate VMCS for VMXON. */
	vmcs = __get_free_page(GFP_ATOMIC);
	if (!vmcs)
		return -ENOMEM;

	ret = tdx_init_vmxon_vmcs((void *)vmcs);
	if (ret)
		goto out;

	cpu_vmxon(__pa(vmcs));

	err = tdh_sys_init(0, &ex_ret);
	if (TDX_ERR(err, TDH_SYS_INIT, &ex_ret)) {
		ret = -EIO;
		goto out_vmxoff;
	}

	err = tdh_sys_lp_init(&ex_ret);
	if (TDX_ERR(err, TDH_SYS_LP_INIT, &ex_ret)) {
		ret = -EIO;
		goto out_vmxoff;
	}

	/*
	 * Do TDSYSINFO to collect the information needed to construct TDMRs,
	 * which needs to be done before kernel page allocator is up as the
	 * page allocator can't provide the large chunk (>4MB) of memory needed
	 * for the PAMTs.
	 */
	err = tdh_sys_info(__pa(&tdx_tdsysinfo), sizeof(tdx_tdsysinfo),
			   __pa(tdx_cmrs), TDX1_MAX_NR_CMRS, &ex_ret);
	if (TDX_ERR(err, TDH_SYS_INFO, &ex_ret)) {
		ret = -EIO;
		goto out_vmxoff;
	}
	pr_info("TDX SEAM module: "
		"attributes 0x%x vendor_id 0x%x "
		"build_date %d build_num 0x%x "
		"minor_version 0x%x major_version 0x%x.\n",
		tdx_tdsysinfo.attributes,
		tdx_tdsysinfo.vendor_id,
		tdx_tdsysinfo.build_date,
		tdx_tdsysinfo.build_num,
		tdx_tdsysinfo.minor_version,
		tdx_tdsysinfo.major_version);

	cpu_vmxoff();
	tdx_nr_cmrs = ex_ret.nr_cmr_entries;
	this_cpu_write(tdx_vmxon_vmcs, vmcs);
	return 0;

out_vmxoff:
	cpu_vmxoff();
out:
	free_page(vmcs);
	return ret;
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

/* Load seam module on one CPU */
static void __init p_seamldr_load_module_one(void *data)
{
	struct seamldr_params *params = data;

	if (seamldr_install(__pa(params)))
		atomic_inc(&tdx_init_cpu_errors);
}

/*
 * Look for seam module binary in built-in firmware and initrd, and load it on
 * all CPUs through P-SEAMLDR.
 */
static int __init p_seamldr_load_module(void)
{
	const char *sigstruct_name = "intel-seam/libtdx.so.sigstruct";
	const char *module_name = "intel-seam/libtdx.so";
	struct cpio_data module, sigstruct;
	struct seamldr_params *params;
	int ret;

	if (tdx_get_firmware(&module, module_name) ||
	    tdx_get_firmware(&sigstruct, sigstruct_name))
		return -EINVAL;

	params = init_seamldr_params(module.data, module.size,
				     sigstruct.data, sigstruct.size);
	if (IS_ERR(params))
		return -ENOMEM;

	smp_call_function(p_seamldr_load_module_one, params, 1);

	p_seamldr_load_module_one(params);

	if (!atomic_read(&tdx_init_cpu_errors)) {
		setup_force_cpu_cap(X86_FEATURE_TDX);
		ret = 0;
	} else {
		pr_info("Late seam module loading failed.\n");
		ret = -EIO;
	}

	free_seamldr_params(params);
	return ret;
}

static atomic_t tdx_vmxonoff_errors __initdata;

static void __init tdx_vmxon(void *ign)
{
	if (cpu_vmxon(__pa(this_cpu_read(tdx_vmxon_vmcs))))
		atomic_inc(&tdx_vmxonoff_errors);
}

static void __init tdx_vmxoff(void *ign)
{
	if (cpu_vmxoff())
		atomic_inc(&tdx_vmxonoff_errors);
}

static int __init on_each_cpu_vmxon(void)
{
	atomic_set(&tdx_vmxonoff_errors, 0);
	on_each_cpu(tdx_vmxon, NULL, 1);
	if (atomic_read(&tdx_vmxonoff_errors))
		return -EFAULT;
	return 0;
}

static int __init on_each_cpu_vmxoff(void)
{
	atomic_set(&tdx_vmxonoff_errors, 0);
	on_each_cpu(tdx_vmxoff, NULL, 1);
	if (atomic_read(&tdx_vmxonoff_errors))
		return -EIO;
	return 0;
}

static void __init tdx_free_vmxon_vmcs(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		free_page(per_cpu(tdx_vmxon_vmcs, cpu));
		per_cpu(tdx_vmxon_vmcs, cpu) = 0;
	}
}

static int __init do_tdh_sys_key_config(void *param)
{
	u64 err;

	do {
		err = tdh_sys_key_config();
	} while (err == TDX_KEY_GENERATION_FAILED);

	if (TDX_ERR(err, TDH_SYS_KEY_CONFIG, NULL))
		return -EIO;

	return 0;
}

static void __init __tdx_init_tdmrs(void *failed)
{
	struct tdx_ex_ret ex_ret;
	u64 base, size;
	u64 err;
	int i;

	for (i = atomic_fetch_add(1, &tdx_next_tdmr_index);
	     i < tdx_nr_tdmrs;
	     i = atomic_fetch_add(1, &tdx_next_tdmr_index)) {
		base = tdx_tdmrs[i].base;
		size = tdx_tdmrs[i].size;

		do {
			/* Abort if a different CPU failed. */
			if (atomic_read(failed))
				return;

			err = tdh_sys_tdmr_init(base, &ex_ret);
			if (TDX_ERR(err, TDH_SYS_TDMR_INIT, &ex_ret)) {
				atomic_inc(failed);
				return;
			}
			/*
			 * Note, "next" is simply an indicator, base is passed to
			 * TDSYSINTTDMR on every iteration.
			 */
		} while (ex_ret.next < (base + size));

		atomic_inc(&tdx_nr_initialized_tdmrs);
	}
}

static int __init tdx_init_tdmrs(void)
{
	atomic_t failed = ATOMIC_INIT(0);

	/*
	 * Flush the cache to guarantee there no MODIFIED cache lines exist for
	 * PAMTs before TDH_SYS_TDMR_INIT, which will initialize PAMT memory using
	 * TDX-SEAM's reserved/system HKID.
	 */
	wbinvd_on_all_cpus();

	on_each_cpu(__tdx_init_tdmrs, &failed, 0);

	while (atomic_read(&tdx_nr_initialized_tdmrs) < tdx_nr_tdmrs) {
		if (atomic_read(&failed))
			return -EIO;
	}

	return 0;
}

/*
 * Invoke TDH.SYS.INIT to perform system-wise initialization and invoke
 * TDH.SYS.LP.INIT on all CPUs to perform processor-wise initialization.
 */
static int __init tdx_init_cpus(void)
{
	int ret;

	/*
	 * Initialize TDX module needs to involve all CPUs.
	 * Disable cpu hotplug and ensure all CPUs are online.
	 */
	cpus_read_lock();
#ifdef CONFIG_SMP
	if (!cpumask_equal(cpu_present_mask, cpu_online_mask)) {
		ret = -EIO;
		goto out;
	}
#endif

	/*
	 * Ensure one cpu calls tdx_init_global() and others call
	 * tdx_init_local(). Thread migration may lead to a CPU tries
	 * to initialize TDX module twice and another CPU does nothing.
	 */
	get_cpu();
	ret = tdx_init_global();
	if (ret)
		goto out;

	ret = sanity_check();
	if (ret)
		goto out;

	smp_call_function(tdx_init_local, NULL, 1);

	if (atomic_read(&tdx_init_cpu_errors))
		ret = -EIO;

out:
	put_cpu();
	cpus_read_unlock();
	return ret;
}

static int __init tdx_init(void)
{
	int ret, i;
	u64 err;

	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -EOPNOTSUPP;

	/* Load TDX module if it hasn't been. */
	pr_info("Loading TDX module via P-SEAMLDR.\n");
	if (p_seamldr_load_module()) {
		ret = -EOPNOTSUPP;
		goto err;
	}

	ret = tdx_init_cpus();
	if (ret)
		goto err;

	ret = init_package_masters();
	if (ret)
		goto err;

	ret = on_each_cpu_vmxon();
	if (ret)
		goto err;

	for (i = 0; i < tdx_nr_tdmrs; i++)
		tdx_tdmr_addrs[i] = __pa(&tdx_tdmrs[i]);

	/* Use the first keyID as TDX-SEAM's global key. */
	err = tdh_sys_config(__pa(tdx_tdmr_addrs), tdx_nr_tdmrs, tdx_keyids_start);
	if (TDX_ERR(err, TDH_SYS_CONFIG, NULL)) {
		ret = -EIO;
		goto err_vmxoff;
	}
	tdx_seam_keyid = tdx_keyids_start;

	ret = tdx_seamcall_on_each_pkg(do_tdh_sys_key_config, NULL);
	if (ret)
		goto err_vmxoff;

	ret = tdx_init_tdmrs();
	if (ret)
		goto err_vmxoff;

	on_each_cpu_vmxoff();
	tdx_free_vmxon_vmcs();

	pr_info("TDX initialized.\n");
	pr_info("support upto %d TD keyids\n", tdx_nr_keyids - 1);
	return 0;

err_vmxoff:
	on_each_cpu_vmxoff();
err:
	tdx_free_vmxon_vmcs();
	clear_cpu_cap(&boot_cpu_data, X86_FEATURE_TDX);
	return ret;
}
arch_initcall(tdx_init);

#ifdef CONFIG_SYSFS

#define P_SEAMLDR_ATTR_SHOW_FMT(name, fmt)				\
static ssize_t p_seamldr_ ## name ## _show(				\
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)	\
{									\
	return sprintf(buf, fmt, p_seamldr_info.name);			\
}									\
static struct kobj_attribute p_seamldr_attr_##name = __ATTR_RO(p_seamldr_ ## name)

#define P_SEAMLDR_ATTR_SHOW_HEX(name)	P_SEAMLDR_ATTR_SHOW_FMT(name, "0x%x\n")
#define P_SEAMLDR_ATTR_SHOW_DEC(name)	P_SEAMLDR_ATTR_SHOW_FMT(name, "%d\n")

P_SEAMLDR_ATTR_SHOW_HEX(attributes);
P_SEAMLDR_ATTR_SHOW_HEX(vendor_id);
P_SEAMLDR_ATTR_SHOW_DEC(build_date);
P_SEAMLDR_ATTR_SHOW_HEX(build_num);
P_SEAMLDR_ATTR_SHOW_HEX(minor_version);
P_SEAMLDR_ATTR_SHOW_HEX(major_version);

static struct kobject *p_seamldr_kobj;
static struct attribute *p_seamldr_attrs[] = {
	&p_seamldr_attr_attributes.attr,
	&p_seamldr_attr_vendor_id.attr,
	&p_seamldr_attr_build_date.attr,
	&p_seamldr_attr_build_num.attr,
	&p_seamldr_attr_minor_version.attr,
	&p_seamldr_attr_major_version.attr,
	NULL,
};

static const struct attribute_group p_seamldr_attr_group = {
	.attrs = p_seamldr_attrs,
};

static int __init p_seamldr_sysfs_init(void)
{
	int ret = 0;

	p_seamldr_kobj = kobject_create_and_add("p_seamldr", firmware_kobj);
	if (!p_seamldr_kobj) {
		pr_err("kobject_create_and_add p_seamldr failed\n");
		ret = -EINVAL;
		goto out;
	}
	ret = sysfs_create_group(p_seamldr_kobj, &p_seamldr_attr_group);
	if (ret)
		pr_err("Sysfs exporting attribute failed with error %d", ret);

out:
	if (ret) {
		if (p_seamldr_kobj)
			sysfs_remove_group(p_seamldr_kobj,
					   &p_seamldr_attr_group);
		kobject_put(p_seamldr_kobj);
	}
	return ret;
}
device_initcall(p_seamldr_sysfs_init);
#endif
