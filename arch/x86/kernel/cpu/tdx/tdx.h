/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _X86_TDX_H
#define _X86_TDX_H

#ifdef CONFIG_SYSFS
extern struct kobject *tdx_kobj;
int __init tdx_sysfs_init(void);
#endif

#endif /* _X86_TDX_H */
