// SPDX-License-Identifier: GPL-2.0
/*
 * tdxc.c - Intel TDX Connect Extensions support
 *
 * Copyright (C) 2026 Intel Corporation
 */

#define pr_fmt(fmt)	"DMAR: " fmt

#include <linux/pci.h>
#include <asm/vmx.h>
#include <asm/tdx.h>

#include "../iommu-pages.h"
#include "iommu.h"

#define IQ_BUFFERS_NUM		2
#define IQ_BUFFER_PAGES		2
#define IQ_BUFFER_SIZE		SZ_8K

bool intel_tdxc_initialized;

static void free_mt_pages(struct tdxc_pages *array)
{
	if (!array)
		return;

	for (int i = 0; i < array->nr_entries; i++)
		iommu_free_pages(array->pages[i]);

	iommu_free_pages(array->root);
	kfree(array->pages);
	kfree(array);
}

DEFINE_FREE(free_mt_pages, struct tdxc_pages *, free_mt_pages(_T))

static void **alloc_mt_pages(unsigned int nr_entries, int node)
{
	void **pages;
	void *vaddr;
	int i;

	pages = kzalloc_objs(*pages, nr_entries);
	if (!pages)
		return NULL;

	/* Allocate two contiguous buffers for the invalidation queue. */
	pages[0] = iommu_alloc_pages_node_sz(node, GFP_KERNEL, IQ_BUFFER_SIZE);
	if (!pages[0])
		goto free_pages;

	pages[1] = iommu_alloc_pages_node_sz(node, GFP_KERNEL, IQ_BUFFER_SIZE);
	if (!pages[1])
		goto free_pages;

	/* Allocate the required number of pages for the IOMMU metadata. */
	for (i = IQ_BUFFERS_NUM; i < nr_entries; i++) {
		vaddr = iommu_alloc_pages_node_sz(node, GFP_KERNEL, SZ_4K);
		if (!vaddr)
			goto free_pages;
		pages[i] = vaddr;
	}

	return pages;
free_pages:
	for (i = 0; i < nr_entries; i++) {
		if (!pages[i])
			break;

		iommu_free_pages(pages[i]);
	}
	kfree(pages);

	return NULL;
}

static void populate_mt_pages(struct tdxc_pages *array)
{
	unsigned int nr_entries = array->nr_entries;
	void **pages = array->pages;
	u64 *entries = array->root;
	int i;

	/*
	 * Populate the parameter for the TDH_IOMMU_SETUP SEAMCALL according to
	 * the format defined in "Table 3.35: Structure of IOMMU_MT Parameter"
	 * of the ABI reference specification:
	 */
	for (i = 0; i < nr_entries; i++) {
		entries[i] = __pa(pages[i]);
		if (i < IQ_BUFFERS_NUM)
			entries[i] |= IQ_BUFFER_PAGES;
	}
}

static struct tdxc_pages *tdxc_alloc_mt_pages(struct intel_iommu *iommu,
					      unsigned int nr_mt_pages)
{
	unsigned int nr_entries = nr_mt_pages + IQ_BUFFERS_NUM;
	struct tdxc_pages *array;

	if (!nr_mt_pages || nr_mt_pages > (PAGE_SIZE / sizeof(u64) - IQ_BUFFERS_NUM))
		return NULL;

	array = kzalloc_obj(*array);
	if (!array)
		return NULL;

	array->root = iommu_alloc_pages_node_sz(iommu->node, GFP_KERNEL, SZ_4K);
	if (!array->root)
		goto free_array;

	array->nr_entries = nr_entries;
	array->pages = alloc_mt_pages(nr_entries, iommu->node);
	if (!array->pages)
		goto free_root;

	populate_mt_pages(array);

	return array;

free_root:
	iommu_free_pages(array->root);
free_array:
	kfree(array);
	return NULL;
}

static int intel_iommu_bringup_tdxc(struct intel_iommu *iommu, unsigned int nr_pages)
{
	unsigned long ndoms = cap_ndoms(iommu->cap);
	struct dmar_drhd_unit *drhd = iommu->drhd;
	u64 r, tdx_iommu_id;

	/*
	 * Nothing to do if the iommu doesn't support TDX extension or the
	 * DMA translation has not been enabled.
	 */
	if (!ecap_tdxc(iommu->ecap) || !(iommu->gcmd & DMA_GCMD_TE))
		return 0;

	struct tdxc_pages *iommu_mt __free(free_mt_pages) =
			tdxc_alloc_mt_pages(iommu, nr_pages);
	if (!iommu_mt)
		return -ENOMEM;

	guard(mutex)(&iommu->did_lock);
	if (ida_find_first_range(&iommu->domain_ida, ndoms >> 1, ndoms - 1) > 0)
		return -EBUSY;

	guard(mutex)(&iommu->tdx_lock);
	r = tdh_iommu_setup(drhd->reg_base_addr, iommu_mt->root, &tdx_iommu_id);
	/* TDX Extension is not supported on this iommu. Nothing to do. */
	if ((r & TDX_SEAMCALL_STATUS_MASK)  == TDX_OPERAND_INVALID)
		return 0;
	if (r) {
		pr_err("%s: Failed to initialize trusted DMA for TEE, error 0x%llx\n",
		       iommu->name, r);
		return -EFAULT;
	}

	/*
	 * Intel TDX Connect Architecture Specification, Section 2.2 Trusted DMA
	 *
	 * When IOMMU is enabled to support TDX Connect, the IOMMU restricts
	 * the VMM’s DID setting, reserving the MSB bit for the TDX module. The
	 * TDX module always sets this reserved bit on the trusted DMA table.
	 */
	iommu->max_domain_id = ndoms >> 1;
	iommu->tdx_iommu_id = tdx_iommu_id;
	iommu->mt_pages = no_free_ptr(iommu_mt);

	pr_info("Trusted IOMMU for TEE initialized on %s\n", iommu->name);

	return 0;
}

static void intel_iommu_teardown_tdxc(struct intel_iommu *iommu)
{
	u64 r;

	guard(mutex)(&iommu->did_lock);
	guard(mutex)(&iommu->tdx_lock);

	if (!iommu->mt_pages)
		return;

	r = tdh_iommu_clear(iommu->tdx_iommu_id, iommu->mt_pages->root);
	if (r) {
		pr_err("%s: Fail to disable trusted DMA for TEE, error 0x%llx\n",
		       iommu->name, r);
		return;
	}

	free_mt_pages(iommu->mt_pages);
	iommu->mt_pages = NULL;
	iommu->tdx_iommu_id = 0;
	iommu->max_domain_id = cap_ndoms(iommu->cap);
}

void intel_tdxc_exit(void)
{
	struct dmar_drhd_unit *drhd;
	struct intel_iommu *iommu;

	guard(rwsem_write)(&dmar_global_lock);
	if (!intel_tdxc_initialized)
		return;

	for_each_active_iommu(iommu, drhd)
		intel_iommu_teardown_tdxc(iommu);
	intel_tdxc_initialized = false;
}
EXPORT_SYMBOL_GPL(intel_tdxc_exit);

int intel_tdxc_init(void)
{
	const struct tdx_sys_info *tdx_sysinfo = tdx_get_sysinfo();
	struct dmar_drhd_unit *drhd;
	unsigned int mt_page_count;
	struct intel_iommu *iommu;
	int ret;

	if (!intel_iommu_enabled)
		return -EOPNOTSUPP;

	if (!tdx_sysinfo ||
	    !(tdx_sysinfo->features.tdx_features0 & TDX_FEATURES0_TDXCONNECT))
		return -EOPNOTSUPP;

	mt_page_count = tdx_sysinfo->tdx_connect.iommu_mt_page_count;
	guard(rwsem_write)(&dmar_global_lock);
	if (intel_tdxc_initialized)
		return 0;

	for_each_active_iommu(iommu, drhd) {
		ret = intel_iommu_bringup_tdxc(iommu, mt_page_count);
		if (ret) {
			for_each_active_iommu(iommu, drhd)
				intel_iommu_teardown_tdxc(iommu);

			return ret;
		}
	}
	intel_tdxc_initialized = true;

	return 0;
}
EXPORT_SYMBOL_GPL(intel_tdxc_init);
