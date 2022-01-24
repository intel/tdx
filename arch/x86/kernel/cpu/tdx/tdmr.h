/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) memory initialization
 */

#ifndef _X86_TDX_TDMR_H
#define _X86_TDX_TDMR_H

#include "tdx_arch.h"

extern struct cmr_info tdx_cmr_array[];
extern int tdx_cmr_num;
extern struct tdsysinfo_struct tdx_sysinfo;

int construct_tdmrs(struct tdmr_info **tdmr_array, int *tdmr_num);
void destroy_tdmrs(struct tdmr_info **tdmr_array, int tdmr_num);

#endif /* _X86_TDX_TDMR_H */
