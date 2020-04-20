/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_MEM_ENCRYPT_COMMON_H
#define _ASM_X86_MEM_ENCRYPT_COMMON_H

#include <linux/mem_encrypt.h>
#include <linux/device.h>

#ifdef CONFIG_AMD_MEM_ENCRYPT
bool amd_force_dma_unencrypted(struct device *dev);
void __init amd_mem_encrypt_init(void);
#else /* CONFIG_AMD_MEM_ENCRYPT */
static inline bool amd_force_dma_unencrypted(struct device *dev)
{
	return false;
}
static inline void amd_mem_encrypt_init(void) {}
#endif /* CONFIG_AMD_MEM_ENCRYPT */

#endif
