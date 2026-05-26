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
#include "iommu.h"

bool intel_tdxc_initialized;

static int intel_iommu_bringup_tdxc(struct intel_iommu *iommu, unsigned int nr_pages)
{
	/*
	 * Nothing to do if the iommu doesn't support TDX extension or the
	 * DMA translation has not been enabled.
	 */
	if (!ecap_tdxc(iommu->ecap) || !(iommu->gcmd & DMA_GCMD_TE))
		return 0;

	/* Bring-up is not complete yet; report as unsupported for now. */
	return -EOPNOTSUPP;
}

static void intel_iommu_teardown_tdxc(struct intel_iommu *iommu)
{
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
