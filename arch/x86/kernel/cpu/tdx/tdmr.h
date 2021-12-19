/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) memory initialization
 */

#ifndef _X86_TDX_TDMR_H
#define _X86_TDX_TDMR_H

#include <linux/align.h>
#include "tdx_arch.h"

/* Page sizes supported by TDX */
enum tdx_page_sz {
	TDX_PG_4K = 0,
	TDX_PG_2M,
	TDX_PG_1G,
	TDX_PG_MAX,
};

/*
 * TDX module descriptor, which contains TDX module's TDMR
 * related global characteristics.
 */
struct tdx_module_descriptor {
	int max_tdmr_num;
	int pamt_entry_size[TDX_PG_MAX];
	int max_rsvd_area_num;
};

/* Get the actual size of TDMR_INFO structure */
static inline int tdmr_info_struct_sz(int max_rsvd_area_num)
{
	int tdmr_sz;

	/*
	 * TDMR_INFO's actual size depends on maximum number of reserved
	 * areas that one TDMR can support.  TDMR_INFO needs to be 512
	 * bytes aligned, so make the size always aligned up to 512 bytes.
	 */
	tdmr_sz = 64 + /* TDMR reserved areas start at byte 64 */
		max_rsvd_area_num * sizeof(struct tdmr_reserved_area);

	return ALIGN(tdmr_sz, TDMR_INFO_ALIGNMENT);
}

/*
 * Get the TDMR_INFO at index @idx from the array.  Using &tdmr_array[idx]
 * may not work since sizeof(struct tdmr_info) may not reflect the real
 * TDMR_INFO size.
 */
static inline struct tdmr_info *tdmr_array_entry(struct tdmr_info *tdmr_array,
						 int idx, int max_rsvd_area_num)
{
	unsigned long base = (unsigned long)tdmr_array;

	return (struct tdmr_info *)(base +
			idx * tdmr_info_struct_sz(max_rsvd_area_num));
}

int construct_tdmrs(struct cmr_info *cmr_array, int cmr_num,
		    struct tdmr_info *tdmr_array,
		    struct tdx_module_descriptor *desc,
		    int *tdmr_num);

#endif /* _X86_TDX_TDMR_H */
