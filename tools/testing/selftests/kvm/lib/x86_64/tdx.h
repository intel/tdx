/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KVM_LIB_TDX_H_
#define KVM_LIB_TDX_H_

#include <kvm_util.h>
#include "processor.h"

/*
 * Max page size for the guest image.
 */
#define TDX_GUEST_MAX_NR_PAGES 10000

/*
 * Page Table Address used when paging is enabled.
 */
#define TDX_GUEST_PT_FIXED_ADDR (0xFFFFFFFF -\
				 (TDX_GUEST_MAX_NR_PAGES * PAGE_SIZE) + 1)

/*
 * Max Page Table Size
 * To map 4GB memory region with 2MB pages, there needs to be 1 page for PML4,
 * 1 Page for PDPT, 4 pages for PD. Reserving 6 pages for PT.
 */
#define TDX_GUEST_NR_PT_PAGES (1 + 1 + 4)

/*
 * Predefined GDTR values.
 */
#define TDX_GUEST_GDTR_ADDR (TDX_GUEST_PT_FIXED_ADDR + (TDX_GUEST_NR_PT_PAGES *\
							PAGE_SIZE))
#define TDX_GUEST_GDTR_BASE (TDX_GUEST_GDTR_ADDR + PAGE_SIZE)
#define TDX_GUEST_LINEAR_CODE64_SEL 0x38

#define TDX_GUEST_STACK_NR_PAGES (3)
#define TDX_GUEST_STACK_BASE (TDX_GUEST_GDTR_BASE + (TDX_GUEST_STACK_NR_PAGES *\
						     PAGE_SIZE) - 1)
/*
 * Reserving some pages to copy the test code. This is an arbitrary number for
 * now to simplify to guest image layout calculation.
 * TODO: calculate the guest code dynamcially.
 */
#define TDX_GUEST_CODE_ENTRY (TDX_GUEST_GDTR_BASE + (TDX_GUEST_STACK_NR_PAGES *\
						     PAGE_SIZE))

#define KVM_MAX_CPUID_ENTRIES 256

/*
 * TODO: Move page attributes to processor.h file.
 */
#define _PAGE_PRESENT       (1UL<<0)       /* is present */
#define _PAGE_RW            (1UL<<1)       /* writeable */
#define _PAGE_PS            (1UL<<7)       /* page size bit*/

#define GDT_ENTRY(flags, base, limit)				\
		((((base)  & 0xff000000ULL) << (56-24)) |	\
		 (((flags) & 0x0000f0ffULL) << 40) |		\
		 (((limit) & 0x000f0000ULL) << (48-16)) |	\
		 (((base)  & 0x00ffffffULL) << 16) |		\
		 (((limit) & 0x0000ffffULL)))

struct tdx_cpuid_data {
	struct kvm_cpuid2 cpuid;
	struct kvm_cpuid_entry2 entries[KVM_MAX_CPUID_ENTRIES];
};

struct __packed tdx_gdtr {
	uint16_t limit;
	uint32_t base;
};

struct page_table {
	uint64_t  pml4[512];
	uint64_t  pdpt[512];
	uint64_t  pd[4][512];
};

void add_td_memory(struct kvm_vm *vm, void *source_page,
		   uint64_t gpa, int size);
void finalize_td_memory(struct kvm_vm *vm);
void initialize_td(struct kvm_vm *vm);
void initialize_td_vcpu(struct kvm_vcpu *vcpu);
void prepare_source_image(struct kvm_vm *vm, void *guest_code,
			  size_t guest_code_size,
			  uint64_t guest_code_signature);

#endif  // KVM_LIB_TDX_H_
