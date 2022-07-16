// SPDX-License-Identifier: GPL-2.0-only
/*
 * Confidential Computing Decrypted Memory Allocator
 *
 * Copyright (C) 2022 Intel Corporation, Inc.
 *
 */

#undef pr_fmt
#define pr_fmt(fmt)     "cc/mem: " fmt

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/cc_platform.h>
#include <linux/set_memory.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>

#include <asm/coco.h>
#include <asm/processor.h>

#define CC_MEM_DRIVER		"ccmem"

static struct platform_device *mem_pdev;

static inline dma_addr_t virt_to_dma(void *vaddr)
{
	return phys_to_dma(&mem_pdev->dev, virt_to_phys(vaddr));
}

/* Allocate decrypted memory of given size */
void *cc_decrypted_alloc(size_t size, gfp_t gfp)
{
	dma_addr_t handle;
	void *vaddr;

	if (!mem_pdev)
		return NULL;

	vaddr = dma_alloc_coherent(&mem_pdev->dev, size, &handle, gfp);

	/*
	 * Since we rely on virt_to_dma() in cc_decrypted_free() to
	 * calculate DMA address, make sure address translation works.
	 */
	VM_BUG_ON(virt_to_dma(vaddr) != handle);

	return vaddr;
}

/* Free the given decrypted memory */
void cc_decrypted_free(void *addr, size_t size)
{
	if (!mem_pdev || !addr)
		return;

	dma_free_coherent(&mem_pdev->dev, size, addr, virt_to_phys(addr));
}

static struct platform_driver cc_mem_driver = {
	.driver.name = CC_MEM_DRIVER,
};

static int __init cc_mem_init(void)
{
	struct platform_device *pdev;
	int ret;

	if (!cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		return -ENODEV;

	ret =  platform_driver_register(&cc_mem_driver);
	if (ret)
		return ret;

	pdev = platform_device_register_simple(CC_MEM_DRIVER, -1, NULL, 0);
	if (IS_ERR(pdev)) {
		platform_driver_unregister(&cc_mem_driver);
		return PTR_ERR(pdev);
	}

	if (dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64)))
		return -EIO;

	mem_pdev = pdev;

	return 0;
}
device_initcall(cc_mem_init);
