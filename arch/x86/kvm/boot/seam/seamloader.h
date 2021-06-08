/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __X86_SEAMLOADER_H
#define __X86_SEAMLOADER_H

#ifdef CONFIG_KVM_INTEL_TDX
int fake_seam_init_seamrr(void);
bool is_seam_module_loaded(void);
int fake_seam_load_module(const char *name, void *data, u64 size);
bool is_hypersim_guest(void);

int __init seam_load_module(void *module, unsigned long module_size,
			    void *sigstruct, unsigned long sigstruct_size,
			    void *seamldr, unsigned long seamldr_size);
#endif

#endif /* __X86_SEAMLOADER_H */
