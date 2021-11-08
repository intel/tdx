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
#include <linux/virtio_config.h>
#include <linux/swiotlb.h>
#include <linux/memblock.h>

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

void __init mem_encrypt_init_swiotlb_size(void)
{
	unsigned long size;

	/*
	 * For SEV and TDX, all DMA has to occur via shared/unencrypted pages.
	 * Kernel uses SWIOTLB to make this happen without changing device
	 * drivers. However, depending on the workload being run, the
	 * default 64MB of SWIOTLB may not be enough and SWIOTLB may
	 * run out of buffers for DMA, resulting in I/O errors and/or
	 * performance degradation especially with high I/O workloads.
	 *
	 * Adjust the default size of SWIOTLB using a percentage of guest
	 * memory for SWIOTLB buffers. Also, as the SWIOTLB bounce buffer
	 * memory is allocated from low memory, ensure that the adjusted size
	 * is within the limits of low available memory.
	 *
	 * The percentage of guest memory used here for SWIOTLB buffers
	 * is more of an approximation of the static adjustment which
	 * 64MB for <1G, and ~128M to 256M for 1G-to-4G, i.e., the 6%
	 */
	size = memblock_phys_mem_size() * 6 / 100;
	size = clamp_val(size, IO_TLB_DEFAULT_SIZE, SZ_1G);
	swiotlb_adjust_size(size);
}

int arch_has_restricted_virtio_memory_access(void)
{
	return (cc_platform_has(CC_ATTR_GUEST_TDX) ||
		cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT));
}
EXPORT_SYMBOL_GPL(arch_has_restricted_virtio_memory_access);
