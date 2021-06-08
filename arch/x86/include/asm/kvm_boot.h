/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_KVM_BOOT_H
#define _ASM_X86_KVM_BOOT_H

#include <linux/cpumask.h>
#include <linux/mutex.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <asm/processor.h>

#ifdef CONFIG_KVM_INTEL_TDX
extern u32 tdh_seam_keyid __ro_after_init;

void __init tdh_seam_init(void);

int tdh_seamcall_on_each_pkg(int (*fn)(void *), void *param);
/*
 * Return pointer to TDX system info (TDSYSINFO_STRUCT) if TDX has been
 * successfully initialized, or NULL.
 */
struct tdsysinfo_struct;
const struct tdsysinfo_struct *tdh_get_sysinfo(void);

/* TDX keyID allocation functions */
extern int tdh_keyid_alloc(void);
extern void tdh_keyid_free(int keyid);
#else
static inline void __init tdh_seam_init(void) {}
#endif

#endif /* _ASM_X86_KVM_BOOT_H */
