/* SPDX-License-Identifier: GPL-2.0 */
/* common functions/symbols used by SEAMLDR and KVM */

#ifndef __BOOT_SEAM_TDX_COMMON_H
#define __BOOT_SEAM_TDX_COMMON_H

extern struct tdsysinfo_struct tdx_tdsysinfo;
extern u32 tdx_keyids_start;
extern u32 tdx_nr_keyids;

int __init init_package_masters(void);

#endif /* __BOOT_SEAM_TDX_COMMON_H */
