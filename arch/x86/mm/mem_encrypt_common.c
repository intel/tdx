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
#include <linux/protected_guest.h>
#include <linux/virtio_config.h>
#include <linux/swiotlb.h>

/* Override for DMA direct allocation check - ARCH_HAS_FORCE_DMA_UNENCRYPTED */
bool force_dma_unencrypted(struct device *dev)
{
	if (sev_active() || sme_active())
		return amd_force_dma_unencrypted(dev);

	if (prot_guest_has(PR_GUEST_MEM_ENCRYPT))
		return true;

	return false;
}

/* Architecture __weak replacement functions */
void __init mem_encrypt_init(void)
{
	/*
	 * For TDX guest or SEV/SME, call into SWIOTLB to update
	 * the SWIOTLB DMA buffers
	 */
	if (sme_me_mask || prot_guest_has(PR_GUEST_MEM_ENCRYPT))
		swiotlb_update_mem_attributes();

	amd_mem_encrypt_init();
}

int arch_has_restricted_virtio_memory_access(void)
{
	return (prot_guest_has(PR_GUEST_TDX) || sev_active());
}
EXPORT_SYMBOL_GPL(arch_has_restricted_virtio_memory_access);
