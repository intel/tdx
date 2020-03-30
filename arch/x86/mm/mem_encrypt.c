// SPDX-License-Identifier: GPL-2.0-only
/*
 * Memory Encryption Support Common Code
 *
 * Copyright (C) 2016 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <linux/dma-direct.h>
#include <linux/dma-mapping.h>
#include <linux/swiotlb.h>
#include <linux/cc_platform.h>
#include <linux/mem_encrypt.h>
#include <linux/virtio_config.h>

#include <asm/tdx.h>

/*
 * Used to set or unset encryption attribute in vendor agnostic way.
 */
pgprot_t pgrot_cc_encrypted(pgprot_t prot)
{
	if (cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT))
		return __pgprot(__sme_set(pgprot_val(prot)));
	else if (cc_platform_has(CC_ATTR_GUEST_TDX))
		return __pgprot(pgprot_val(prot) & ~tdx_shared_mask());

	return prot;
}
EXPORT_SYMBOL_GPL(pgrot_cc_encrypted);

pgprot_t pgrot_cc_decrypted(pgprot_t prot)
{
	if (cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT))
		return __pgprot(__sme_clr(pgprot_val(prot)));
	else if (cc_platform_has(CC_ATTR_GUEST_TDX))
		return __pgprot(pgprot_val(prot) | tdx_shared_mask());

	return prot;
}
EXPORT_SYMBOL_GPL(pgrot_cc_decrypted);

/* Override for DMA direct allocation check - ARCH_HAS_FORCE_DMA_UNENCRYPTED */
bool force_dma_unencrypted(struct device *dev)
{
	/*
	 * For SEV, all DMA must be to unencrypted addresses.
	 */
	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		return true;

	/*
	 * For SME, all DMA must be to unencrypted addresses if the
	 * device does not support DMA to addresses that include the
	 * encryption mask.
	 */
	if (cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT)) {
		u64 dma_enc_mask = DMA_BIT_MASK(__ffs64(sme_me_mask));
		u64 dma_dev_mask = min_not_zero(dev->coherent_dma_mask,
						dev->bus_dma_limit);

		if (dma_dev_mask <= dma_enc_mask)
			return true;
	}

	return false;
}

static void print_amd_mem_encrypt_feature_info(void)
{
	pr_info("AMD Memory Encryption Features active:");

	/* Secure Memory Encryption */
	if (cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT)) {
		/*
		 * SME is mutually exclusive with any of the SEV
		 * features below.
		 */
		pr_cont(" SME\n");
		return;
	}

	/* Secure Encrypted Virtualization */
	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		pr_cont(" SEV");

	/* Encrypted Register State */
	if (cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT))
		pr_cont(" SEV-ES");

	pr_cont("\n");
}

/* Architecture __weak replacement functions */
void __init mem_encrypt_init(void)
{
	if (!sme_me_mask)
		return;

	/* Call into SWIOTLB to update the SWIOTLB DMA buffers */
	swiotlb_update_mem_attributes();

	print_amd_mem_encrypt_feature_info();
}

int arch_has_restricted_virtio_memory_access(void)
{
	return cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT);
}
EXPORT_SYMBOL_GPL(arch_has_restricted_virtio_memory_access);
