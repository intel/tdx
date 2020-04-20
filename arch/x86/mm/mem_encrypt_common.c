// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2016 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <linux/mm.h>
#include <linux/mem_encrypt.h>
#include <linux/dma-mapping.h>
#include <linux/swiotlb.h>

/* Override for DMA direct allocation check - ARCH_HAS_FORCE_DMA_UNENCRYPTED */
bool force_dma_unencrypted(struct device *dev)
{
	/*
	 * For SEV and TDX, all DMA must be to unencrypted/shared addresses.
	 */
	if (sev_active() || is_tdx_guest())
		return true;

	/*
	 * For SME, all DMA must be to unencrypted addresses if the
	 * device does not support DMA to addresses that include the
	 * encryption mask.
	 */
	if (sme_active()) {
		u64 dma_enc_mask = DMA_BIT_MASK(__ffs64(sme_me_mask));
		u64 dma_dev_mask = min_not_zero(dev->coherent_dma_mask,
						dev->bus_dma_limit);

		if (dma_dev_mask <= dma_enc_mask)
			return true;
	}

	return false;
}

static void print_mem_encrypt_feature_info(void)
{
	pr_info("AMD Memory Encryption Features active:");

	/* Secure Memory Encryption */
	if (sme_active()) {
		/*
		 * SME is mutually exclusive with any of the SEV
		 * features below.
		 */
		pr_cont(" SME\n");
		return;
	}

	/* Secure Encrypted Virtualization */
	if (sev_active())
		pr_cont(" SEV");

	/* Encrypted Register State */
	if (sev_es_active())
		pr_cont(" SEV-ES");

	pr_cont("\n");
}

/* Architecture __weak replacement functions */
void __init mem_encrypt_init(void)
{
	if (!sme_me_mask && !is_tdx_guest())
		return;

	/* Call into SWIOTLB to update the SWIOTLB DMA buffers */
	swiotlb_update_mem_attributes();

	/*
	 * With SEV, we need to unroll the rep string I/O instructions.
	 */
	if (sev_active())
		static_branch_enable(&sev_enable_key);

	if (!is_tdx_guest())
		print_mem_encrypt_feature_info();
}
