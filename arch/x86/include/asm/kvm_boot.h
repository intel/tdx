/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_KVM_BOOT_H
#define _ASM_X86_KVM_BOOT_H

#include <linux/cpumask.h>
#include <linux/mutex.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <asm/processor.h>

#ifdef CONFIG_KVM_INTEL_TDX
int __init seam_load_module(void *module, unsigned long module_size,
			    void *sigstruct, unsigned long sigstruct_size,
			    void *seamldr, unsigned long seamldr_size);

void __init tdx_seam_init(void);
void tdx_init_cpu(struct cpuinfo_x86 *c);

int tdx_seamcall_on_each_pkg(int (*fn)(void *), void *param);
/*
 * Return pointer to TDX system info (TDSYSINFO_STRUCT) if TDX has been
 * successfully initialized, or NULL.
 */
struct tdsysinfo_struct;
struct tdsysinfo_struct *tdx_get_sysinfo(void);

/* TDX keyID allocation functions */
extern int tdx_keyid_alloc(void);
extern void tdx_keyid_free(int keyid);
#else
static inline void __init tdx_seam_init(void) {}
static inline void tdx_init_cpu(struct cpuinfo_x86 *c) {}
#endif

#endif /* _ASM_X86_KVM_BOOT_H */
