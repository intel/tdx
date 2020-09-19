// SPDX-License-Identifier: GPL-2.0
#include <linux/earlycpio.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/percpu.h>
#include <linux/memblock.h>
#include <linux/idr.h>
#include <linux/sort.h>

#include <asm/cpu.h>
#include <asm/kvm_boot.h>
#include <asm/virtext.h>
#include <asm/tlbflush.h>
#include <asm/e820/api.h>

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

/* Instruct tdx_ops.h to do boot-time friendly SEAMCALL exception handling. */
#define INTEL_TDX_BOOT_TIME_SEAMCALL 1

#include "vmx/tdx_arch.h"
#include "vmx/tdx_ops.h"
#include "vmx/tdx_errno.h"

#include "vmx/vmcs.h"

static DEFINE_PER_CPU(unsigned long, tdx_vmxon_vmcs);
static atomic_t tdx_init_cpu_errors;

/*
 * TODO: better to have kernel boot parameter to let admin control whether to
 * enable TDX with sysprof or not.
 *
 * Or how to decide tdx_sysprof??
 */
static bool tdx_sysprof;

/* KeyID range reserved to TDX by BIOS */
static u32 tdx_keyids_start;
static u32 tdx_nr_keyids;

u32 tdx_seam_keyid __ro_after_init;
EXPORT_SYMBOL_GPL(tdx_seam_keyid);

/* TDX keyID pool */
static DEFINE_IDA(tdx_keyid_pool);

static int *tdx_package_masters __ro_after_init;

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
static atomic_t tdx_next_tdmr_index;
static atomic_t tdx_nr_initialized_tdmrs;

/* TDMRs must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT_ULL(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

/*
 * TDSYSCONFIG takes a array of pointers to TDMR infos.  Its just big enough
 * that allocating it on the stack is undesirable.
 */
static u64 tdx_tdmr_addrs[TDX1_MAX_NR_TDMRS] __aligned(512) __initdata;

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
		return -ENOTSUPP;
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

	if (!tdx_nr_cmrs) {
		pr_err("no valid CMR\n");
		return -EIO;
	}

	for (i = 0, j = -1, observed_empty = false; i < tdx_nr_cmrs; i++) {
		if (!tdx_cmrs[i].size) {
			observed_empty = true;
			continue;
		}
		/* Valid entry after empty entry isn't allowed, per SEAM. */
		if (observed_empty) {
			pr_err("empty CMR entry among valid entries\n");
			return -EIO;
		}

		/* The previous CMR must reside fully below this CMR. */
		if (j >= 0 &&
		    (tdx_cmrs[j].base + tdx_cmrs[j].size) > tdx_cmrs[i].base) {
			pr_err("disordered CMRs\n");
			return -EIO;
		}

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
	if (!tdx_nr_cmrs) {
		pr_err("no valid CMR after adjustment\n");
		return -EINVAL;
	}

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
 * Well.. I guess a better way is to put cpu_vmxon() into asm/virtext.h,
 * and split kvm_cpu_vmxon() into cpu_vmxon(), and intel_pt_handle_vmx(),
 * so we just only have one cpu_vmxon() in asm/virtext.h..
 */
static inline void cpu_vmxon(u64 vmxon_region)
{
	cr4_set_bits(X86_CR4_VMXE);
	asm volatile ("vmxon %0" : : "m"(vmxon_region));
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
		return -ENOTSUPP;

	if (rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ||
	    !(msr & FEAT_CTL_LOCKED) ||
	    !(msr & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX))
		return -ENOTSUPP;

	if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &msr))
		return -ENOTSUPP;

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

static int tdx_init_ap(unsigned long vmcs)
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
		return -ENOTSUPP;
	}

	cpu_vmxon(__pa(vmcs));
	err = tdsysinitlp(&ex_ret);
	cpu_vmxoff();

	if (TDX_ERR(err, TDSYSINITLP))
		return -EIO;

	return 0;
}

void tdx_init_cpu(struct cpuinfo_x86 *c)
{
	unsigned long vmcs;

	/* Allocate VMCS for VMXON. */
	vmcs = __get_free_page(GFP_KERNEL);
	if (!vmcs)
		goto err;

	/* VMCS configuration shouldn't fail at this point. */
	if (WARN_ON_ONCE(tdx_init_vmxon_vmcs((void *)vmcs)))
		goto err_vmcs;

	/* BSP does TDSYSINITLP as part of tdx_seam_init(). */
	if (c != &boot_cpu_data && tdx_init_ap(vmcs))
		goto err_vmcs;

	this_cpu_write(tdx_vmxon_vmcs, vmcs);
	return;

err_vmcs:
	free_page(vmcs);
err:
	clear_cpu_cap(c, X86_FEATURE_TDX);
	atomic_inc(&tdx_init_cpu_errors);
}

static __init int tdx_init_bsp(void)
{
	struct tdx_ex_ret ex_ret;
	void *vmcs;
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
		return -ENOTSUPP;

	/*
	 * Allocate a temporary VMCS for early BSP init, the VMCS for late(ish)
	 * init will be allocated after the page allocator is up and running.
	 */
	vmcs = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
	if (!vmcs)
		return -ENOMEM;

	ret = tdx_init_vmxon_vmcs(vmcs);
	if (ret)
		goto out;

	cpu_vmxon(__pa(vmcs));

	err = tdsysinit(tdx_sysprof ? BIT(0) : 0, &ex_ret);
	if (TDX_ERR(err, TDSYSINIT)) {
		ret = -EIO;
		goto out_vmxoff;
	}

	err = tdsysinitlp(&ex_ret);
	if (TDX_ERR(err, TDSYSINITLP)) {
		ret = -EIO;
		goto out_vmxoff;
	}

	/*
	 * Do TDSYSINFO to collect the information needed to construct TDMRs,
	 * which needs to be done before kernel page allocator is up as the
	 * page allocator can't provide the large chunk (>4MB) of memory needed
	 * for the PAMTs.
	 */
	err = tdsysinfo(__pa(&tdx_tdsysinfo), sizeof(tdx_tdsysinfo),
			__pa(tdx_cmrs), TDX1_MAX_NR_CMRS, &ex_ret);
	if (TDX_ERR(err, TDSYSINFO)) {
		ret = -EIO;
		goto out_vmxoff;
	}
	pr_info("TDX SEAM module: "
		"attributes 0x%x vendor_id 0x%x "
		"build_date 0x%x build_num 0x%x "
		"minor_version 0x%x major_version 0x%x.\n",
		tdx_tdsysinfo.attributes,
		tdx_tdsysinfo.vendor_id,
		tdx_tdsysinfo.build_date,
		tdx_tdsysinfo.build_num,
		tdx_tdsysinfo.minor_version,
		tdx_tdsysinfo.major_version);

	tdx_nr_cmrs = ex_ret.nr_cmr_entries;
	ret = 0;

out_vmxoff:
	cpu_vmxoff();
out:
	memblock_free(__pa(vmcs), PAGE_SIZE);
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
	const char *search_path[] = {
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
	const char *sigstruct_name = "intel-seam/libtdx.so.sigstruct";
	const char *seamldr_name = "intel-seam/seamldr.acm";
	const char *module_name = "intel-seam/libtdx.so";
	struct cpio_data module, sigstruct, seamldr;

	/*
	 * Don't load/configure SEAM if not all CPUs can be brought up during
	 * smp_init(), TDX must execute TDSYSINITLP on all logical processors.
	 */
	if (!tdx_all_cpus_available())
		goto error;

	if (!tdx_get_firmware(&module, module_name))
		goto error;

	if (!tdx_get_firmware(&sigstruct, tdx_sigstruct_name))
		goto error;

	if (!tdx_get_firmware(&seamldr, tdx_seamldr_name))
		goto error;

	if (seam_load_module(module.data, module.size, sigstruct.data,
			     sigstruct.size, seamldr.data, seamldr.size))
		goto error;

	if (tdx_init_bsp() || construct_tdmrs())
		goto error;

	setup_force_cpu_cap(X86_FEATURE_TDX);
	return;

error:
	pr_err("can't load/init TDX module. disabling TDX feature.\n");
	setup_clear_cpu_cap(X86_FEATURE_TDX);
}

/*
 * Setup one-cpu-per-pkg array to do package-scoped SEAMCALLs.  The array is
 * only necessary if there are multiple packages.
 */
static int __init init_package_masters(void)
{
	int cpu, pkg, nr_filled, nr_pkgs;

	nr_pkgs = topology_max_packages();
	if (nr_pkgs == 1)
		return 0;

	tdx_package_masters = kcalloc(nr_pkgs, sizeof(int), GFP_KERNEL);
	if (!tdx_package_masters)
		return -ENOMEM;

	memset(tdx_package_masters, -1, nr_pkgs * sizeof(int));

	nr_filled = 0;
	for_each_online_cpu(cpu) {
		pkg = topology_physical_package_id(cpu);
		if (tdx_package_masters[pkg] >= 0)
			continue;

		tdx_package_masters[pkg] = cpu;
		if (++nr_filled == topology_max_packages())
			break;
	}

	if (WARN_ON(nr_filled != topology_max_packages())) {
		kfree(tdx_package_masters);
		return -EIO;
	}

	return 0;
}

int tdx_seamcall_on_each_pkg(int (*fn)(void *), void *param)
{
	int ret, i;

	if (!tdx_package_masters) {
		return fn(param);
	}

	for (i = 0; i < topology_max_packages(); i++) {
		ret = smp_call_on_cpu(tdx_package_masters[i], fn, param, 1);
		if (ret)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(tdx_seamcall_on_each_pkg);

static void __init tdx_vmxon(void *ret)
{
	cpu_vmxon(__pa(this_cpu_read(tdx_vmxon_vmcs)));
}

static void __init tdx_vmxoff(void *ign)
{
	cpu_vmxoff();
}

static void __init tdx_free_vmxon_vmcs(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		free_page(per_cpu(tdx_vmxon_vmcs, cpu));
		per_cpu(tdx_vmxon_vmcs, cpu) = 0;
	}
}

static int __init do_tdsysconfigkey(void *param)
{
	u64 err;

	do {
		err = tdsysconfigkey();
	} while (err == TDX_KEY_GENERATION_FAILED);
	TDX_ERR(err, TDSYSCONFIGKEY);

	if (err)
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

			err = tdsysinittdmr(base, &ex_ret);
			if (TDX_ERR(err, TDSYSINITTDMR)) {
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
	 * PAMTs before TDSYSINITTDMR, which will initialize PAMT memory using
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

static int __init tdx_init(void)
{
	int ret, i;
	u64 err;

	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -ENOTSUPP;

	/* Disable TDX if any CPU(s) failed to boot. */
	if (!cpumask_equal(cpu_present_mask, &cpus_booted_once_mask)) {
		ret = -EIO;
		goto err;
	}

	if (atomic_read(&tdx_init_cpu_errors)) {
		ret = -EIO;
		goto err;
	}

	ret = init_package_masters();
	if (ret)
		goto err;

	on_each_cpu(tdx_vmxon, NULL, 1);

	for (i = 0; i < tdx_nr_tdmrs; i++)
		tdx_tdmr_addrs[i] = __pa(&tdx_tdmrs[i]);

	/* Use the first keyID as TDX-SEAM's global key. */
	err = tdsysconfig(__pa(tdx_tdmr_addrs), tdx_nr_tdmrs, tdx_keyids_start);
	if (TDX_ERR(err, TDSYSCONFIG)) {
		ret = -EIO;
		goto err_vmxoff;
	}
	tdx_seam_keyid = tdx_keyids_start;

	ret = tdx_seamcall_on_each_pkg(do_tdsysconfigkey, NULL);
	if (ret)
		goto err_vmxoff;

	ret = tdx_init_tdmrs();
	if (ret)
		goto err_vmxoff;

	on_each_cpu(tdx_vmxoff, NULL, 1);
	tdx_free_vmxon_vmcs();

	pr_info("TDX initialized.\n");
	pr_info("support upto %d TD keyids\n", tdx_nr_keyids - 1);
	return 0;

err_vmxoff:
	on_each_cpu(tdx_vmxoff, NULL, 1);
err:
	tdx_free_vmxon_vmcs();
	clear_cpu_cap(&boot_cpu_data, X86_FEATURE_TDX);
	return ret;
}
arch_initcall(tdx_init);

struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	if (boot_cpu_has(X86_FEATURE_TDX))
		return &tdx_tdsysinfo;

	return NULL;
}
EXPORT_SYMBOL_GPL(tdx_get_sysinfo);

int tdx_keyid_alloc(void)
{
	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -EINVAL;

	if (WARN_ON_ONCE(!tdx_keyids_start || !tdx_nr_keyids))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_keyid_pool, tdx_keyids_start + 1,
			       tdx_keyids_start + tdx_nr_keyids - 1,
			       GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(tdx_keyid_alloc);

void tdx_keyid_free(int keyid)
{
	if (!keyid || keyid < 0)
		return;

	ida_free(&tdx_keyid_pool, keyid);
}
EXPORT_SYMBOL_GPL(tdx_keyid_free);

#ifdef CONFIG_SYSFS

#define TDX_SEAM_ATTR_SHOW(name)					\
static ssize_t name ## _show(						\
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)	\
{									\
	return sprintf(buf, "0x%x\n", tdx_tdsysinfo. name );		\
}									\
static struct kobj_attribute tdx_attr_##name = __ATTR_RO(name);

TDX_SEAM_ATTR_SHOW(attributes);
TDX_SEAM_ATTR_SHOW(vendor_id);
TDX_SEAM_ATTR_SHOW(build_date);
TDX_SEAM_ATTR_SHOW(build_num);
TDX_SEAM_ATTR_SHOW(minor_version);
TDX_SEAM_ATTR_SHOW(major_version);

static struct kobject *tdx_seam_kobj;
static struct attribute *tdx_seam_attrs[] = {
	&tdx_attr_attributes.attr,
	&tdx_attr_vendor_id.attr,
	&tdx_attr_build_date.attr,
	&tdx_attr_build_num.attr,
	&tdx_attr_minor_version.attr,
	&tdx_attr_major_version.attr,
	NULL,
};

static const struct attribute_group tdx_seam_attr_group = {
	.attrs = tdx_seam_attrs,
};

static int __init tdx_seam_sysfs_init(void)
{
	int ret = 0;

	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -ENOTSUPP;

	tdx_seam_kobj = kobject_create_and_add("tdx_seam", firmware_kobj);
	if (!tdx_seam_kobj) {
		pr_err("kobject_create_and_add tdx_seam failed\n");
		ret = -EINVAL;
		goto out;
	}
	ret = sysfs_create_group(tdx_seam_kobj, &tdx_seam_attr_group);
	if (ret) {
		pr_err("Sysfs exporting attribute faild with error %d", ret);
	}
out:
	if (ret) {
		if (tdx_seam_kobj)
			sysfs_remove_group(tdx_seam_kobj, &tdx_seam_attr_group);
		kobject_put(tdx_seam_kobj);
	}
	return ret;
}

device_initcall(tdx_seam_sysfs_init);
#endif
