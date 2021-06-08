/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __X86_SEAMLOADER_H
#define __X86_SEAMLOADER_H

#ifdef CONFIG_KVM_INTEL_TDX
#define SEAMLDR_MAX_NR_MODULE_PAGES    496

struct seamldr_params {
	u32 version;
	u32 scenario;
	u64 sigstruct_pa;
	u8 reserved[104];
	u64 module_pages;
	u64 module_pa_list[SEAMLDR_MAX_NR_MODULE_PAGES];
} __packed __aligned(PAGE_SIZE);

struct seamldr_info {
	u32 version;
	u32 attributes;
	u32 vendor_id;
	u32 build_date;
	u16 build_num;
	u16 minor_version;
	u16 major_version;
	u8 reserved0[2];
	u32 last_shutdown_x2apic_id;
	u8 reserved1[228];
} __packed __aligned(256);

int fake_seam_init_seamrr(void);
bool is_seam_module_loaded(void);
int fake_seam_load_module(const char *name, void *data, u64 size);
bool is_hypersim_guest(void);

int __init seam_load_module(void *seamldr, unsigned long seamldr_size,
			    const struct seamldr_params *params);
struct seamldr_params * __init init_seamldr_params(void *module,
						   unsigned long module_size,
						   void *sigstruct,
						   unsigned long sigstruct_size);
void __init free_seamldr_params(struct seamldr_params *params);
phys_addr_t __init seam_alloc_mem(phys_addr_t size, phys_addr_t align);
void __init seam_free_mem(phys_addr_t addr, phys_addr_t size);
#endif

#endif /* __X86_SEAMLOADER_H */
