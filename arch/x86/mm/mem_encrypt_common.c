// SPDX-License-Identifier: GPL-2.0-only
/*
 * Memory Encryption Support Common Code
 *
 * Copyright (C) 2021 Intel Corporation
 *
 * Author: Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */

#include <asm/mem_encrypt_common.h>
#include <linux/dma-mapping.h>
#include <linux/cc_platform.h>
#include <linux/swiotlb.h>

/* Override for DMA direct allocation check - ARCH_HAS_FORCE_DMA_UNENCRYPTED */
bool force_dma_unencrypted(struct device *dev)
{
	if (cc_platform_has(CC_ATTR_GUEST_TDX) &&
	    cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		return true;

	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT) ||
	    cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT))
		return amd_force_dma_unencrypted(dev);

	return false;
}

/* Architecture __weak replacement functions */
void __init mem_encrypt_init(void)
{
	/*
	 * For TDX guest or SEV/SME, call into SWIOTLB to update
	 * the SWIOTLB DMA buffers
	 */
	if (sme_me_mask || cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		swiotlb_update_mem_attributes();

	amd_mem_encrypt_init();
}
