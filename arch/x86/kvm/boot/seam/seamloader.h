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

int seamldr_info(u64 seamldr_info);
int seamldr_install(u64 seamldr_params);
int seamldr_shutdown(void);

#endif

#endif /* __X86_SEAMLOADER_H */
