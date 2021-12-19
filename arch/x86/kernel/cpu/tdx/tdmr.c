// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) memory initialization
 */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/slab.h>
#include <asm/string.h>
#include "tdmr.h"

static void destroy_tdmr(struct tdmr_info *tdmr)
{
	WARN_ON(!tdmr);
	kfree(tdmr);
}

/**
 * construct_tdmrs - Construct TDMRs to cover all system RAM in e820
 *
 * @tdmr_array:	Array of pointer to TDMR_INFO
 * @tdmr_num:	Actual number of TDMRs
 *
 * Construct TDMRs to cover all RAM entries in e820_table to convert
 * all system RAM to TDX memory.  The constructed TDMRs are stored in
 * @tdmr_array, with @tdmr_num reflects the actual TDMR number.
 *
 * Caller is responsible for allocating the space for @tdmr_array with
 * at least tdx_sysinfo.max_tdmrs entries.
 *
 * Return: 0 for success, or error.
 */
int construct_tdmrs(struct tdmr_info **tdmr_array, int *tdmr_num)
{
	/* Make sure all entries in the TDMR array are initially NULL */
	memset(tdmr_array, 0,
			sizeof(struct tdmr_info *) * tdx_sysinfo.max_tdmrs);

	return -EFAULT;
}

/**
 * destroy_tdmrs - Destroy TDMRs
 *
 * @tdmr_array: Array of pointer to TDMR_INFO
 * @tdmr_num:	Actual number of TDMRs
 *
 * Destroy all TDMRs that are constructed by construct_tdmrs().
 * @tdmr_array is not freed.  It's caller's responsibility to free it.
 */
void destroy_tdmrs(struct tdmr_info **tdmr_array, int tdmr_num)
{
	int i;

	for (i = 0; i < tdmr_num; i++)
		destroy_tdmr(tdmr_array[i]);
}
