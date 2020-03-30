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

/* Override for DMA direct allocation check - ARCH_HAS_FORCE_DMA_UNENCRYPTED */
bool force_dma_unencrypted(struct device *dev)
{
	if (sev_active() || sme_active())
		return amd_force_dma_unencrypted(dev);

	if (prot_guest_has(PR_GUEST_MEM_ENCRYPT))
		return true;

	return false;
}
