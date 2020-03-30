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
