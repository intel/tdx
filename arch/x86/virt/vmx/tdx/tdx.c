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
#include <linux/list.h>
#include <linux/memblock.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/tdx.h>
#include "tdx.h"

struct tdx_memblock {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
	int nid;
};

static u32 tdx_keyid_start __ro_after_init;
static u32 tdx_keyid_num __ro_after_init;

/* All TDX-usable memory regions */
static LIST_HEAD(tdx_memlist);

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

static void __init tdx_memory_destroy(void)
{
	while (!list_empty(&tdx_memlist)) {
		struct tdx_memblock *tmb = list_first_entry(&tdx_memlist,
				struct tdx_memblock, list);

		list_del(&tmb->list);
		kfree(tmb);
	}
}

/* Add one TDX memory block after all existing TDX memory blocks */
static int __init tdx_memory_add_block(unsigned long start_pfn,
				       unsigned long end_pfn,
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

/*
 * TDX reports a list of "Convertible Memory Regions" (CMR) to indicate
 * all memory regions that _can_ be used by TDX, but the kernel needs to
 * choose the _actual_ regions that TDX can use and pass those regions
 * to the TDX module when initializing it.  After the TDX module gets
 * initialized, no more TDX-usable memory can be hot-added to the TDX
 * module.
 *
 * TDX convertible memory must be physically present during machine boot.
 * To keep things simple, the current implementation simply chooses to
 * use all boot-time present memory regions as TDX memory so that all
 * pages allocated via the page allocator are TDX memory.
 *
 * Build all boot-time memory regions managed by memblock as TDX-usable
 * memory regions by making a snapshot of memblock memory regions during
 * kernel boot.  Memblock is discarded when CONFIG_ARCH_KEEP_MEMBLOCK is
 * not enabled after kernel boots.  Also, memblock can be changed due to
 * memory hotplug (i.e. memory removal from core-mm) even if it is kept.
 *
 * Those regions will be verified when CMRs become available when the TDX
 * module gets initialized.  At this stage, it's not possible to get CMRs
 * during kernel boot as the core-kernel doesn't support VMXON.
 *
 * Note: this means the current implementation _requires_ all boot-time
 * present memory regions are TDX convertible memory to enable TDX.  This
 * is true in practice.  Also, this can be enhanced in the future when
 * the core-kernel gets VMXON support.
 *
 * Important note:
 *
 * TDX doesn't work with physical memory hotplug, as all hot-added memory
 * are not convertible memory.
 *
 * Also to keep things simple, the current implementation doesn't handle
 * memory hotplug at all for TDX.  To use TDX, it is the machine owner's
 * responsibility to not do any operation that will hot-add any non-TDX
 * memory to the page allocator.  For example, the machine owner should
 * not plug any non-CMR memory (such as NVDIMM and CXL memory) to the
 * machine, or should not use kmem driver to plug any NVDIMM or CXL
 * memory to the core-mm.
 *
 * This will be enhanced in the future.
 *
 * Note: tdx_init() is called before acpi_init(), which will scan the
 * entire ACPI namespace and hot-add all ACPI memory devices if there
 * are any.  This belongs to the memory hotplug category as mentioned
 * above.
 */
static int __init build_tdx_memory(void)
{
	unsigned long start_pfn, end_pfn;
	int i, nid, ret;

	/*
	 * Cannot use for_each_free_mem_range() here as some reserved
	 * memory (i.e. initrd image) will be freed to the page allocator
	 * at the late phase of kernel boot.
	 */
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		/*
		 * The first 1MB is not reported as TDX convertible
		 * memory on some platforms.  Manually exclude them as
		 * TDX memory.  This is fine as the first 1MB is already
		 * reserved in reserve_real_mode() and won't end up to
		 * ZONE_DMA as free page anyway.
		 */
		if (start_pfn < (SZ_1M >> PAGE_SHIFT))
			start_pfn = (SZ_1M >> PAGE_SHIFT);
		if (start_pfn >= end_pfn)
			continue;

		/*
		 * All TDX memory blocks must be in address ascending
		 * order when initializing the TDX module.  Memblock
		 * already guarantees that.
		 */
		ret = tdx_memory_add_block(start_pfn, end_pfn, nid);
		if (ret)
			goto err;
	}

	return 0;
err:
	tdx_memory_destroy();
	return ret;
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

	/*
	 * Build all boot-time system memory managed in memblock as
	 * TDX-usable memory.  As part of initializing the TDX module,
	 * those regions will be passed to the TDX module.
	 */
	if (build_tdx_memory()) {
		pr_err("Build TDX-usable memory regions failed. Disable TDX.\n");
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
