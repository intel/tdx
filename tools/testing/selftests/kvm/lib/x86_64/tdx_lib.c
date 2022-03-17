// SPDX-License-Identifier: GPL-2.0
#include <linux/stringify.h>
#include "asm/kvm.h"
#include "tdx.h"
#include <stdlib.h>
#include <malloc.h>
#include "processor.h"
#include <string.h>

char *tdx_cmd_str[] = {
	"KVM_TDX_CAPABILITIES",
	"KVM_TDX_INIT_VM",
	"KVM_TDX_INIT_VCPU",
	"KVM_TDX_INIT_MEM_REGION",
	"KVM_TDX_FINALIZE_VM"
};

#define TDX_MAX_CMD_STR (ARRAY_SIZE(tdx_cmd_str))
#define EIGHT_INT3_INSTRUCTIONS 0xCCCCCCCCCCCCCCCC

#define XFEATURE_LBR		15
#define XFEATURE_XTILECFG	17
#define XFEATURE_XTILEDATA	18
#define XFEATURE_MASK_LBR	(1 << XFEATURE_LBR)
#define XFEATURE_MASK_XTILECFG	(1 << XFEATURE_XTILECFG)
#define XFEATURE_MASK_XTILEDATA	(1 << XFEATURE_XTILEDATA)
#define XFEATURE_MASK_XTILE	(XFEATURE_MASK_XTILECFG | XFEATURE_MASK_XTILEDATA)
#define XFEATURE_MASK_CET	((1 << 11) | (1 << 12))

static int __tdx_ioctl(int fd, int ioctl_no, uint32_t flags, void *data)
{
	struct kvm_tdx_cmd tdx_cmd;

	TEST_ASSERT(ioctl_no < TDX_MAX_CMD_STR, "Unknown TDX CMD : %d\n",
		    ioctl_no);

	memset(&tdx_cmd, 0x0, sizeof(tdx_cmd));
	tdx_cmd.id = ioctl_no;
	tdx_cmd.flags = flags;
	tdx_cmd.data = (uint64_t)data;
	return ioctl(fd, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
}


static void tdx_ioctl(int fd, int ioctl_no, uint32_t flags, void *data)
{
	int r;

	r = __tdx_ioctl(fd, ioctl_no, flags, data);
	TEST_ASSERT(r == 0, "%s failed: %d  %d", tdx_cmd_str[ioctl_no], r,
		    errno);
}

static struct tdx_cpuid_data get_tdx_cpuid_data(struct kvm_vm *vm)
{
	static struct tdx_cpuid_data cpuid_data;
	int ret, i;

	if (cpuid_data.cpuid.nent)
		return cpuid_data;

	memset(&cpuid_data, 0, sizeof(cpuid_data));
	cpuid_data.cpuid.nent = KVM_MAX_CPUID_ENTRIES;
	ret = ioctl(vm->kvm_fd, KVM_GET_SUPPORTED_CPUID, &cpuid_data);
	if (ret) {
		TEST_FAIL("KVM_GET_SUPPORTED_CPUID failed %d %d\n",
		    ret, errno);
		cpuid_data.cpuid.nent = 0;
		return cpuid_data;
	}

	for (i = 0; i < KVM_MAX_CPUID_ENTRIES; i++) {
		struct kvm_cpuid_entry2 *e = &cpuid_data.entries[i];

		/* TDX doesn't support LBR yet.
		 * Disable those bits from the XCR0 register.
		 */
		if (e->function == 0xd && (e->index == 0)) {
			e->eax &= ~XFEATURE_MASK_LBR;

			/*
			 * TDX modules requires both CET_{U, S} to be set even
			 * if only one is supported.
			 */
			if (e->eax & XFEATURE_MASK_CET) {
				e->eax |= XFEATURE_MASK_CET;
			}
			/*
			 * TDX module requires both XTILE_{CFG, DATA} to be set.
			 * Both bits are required for AMX to be functional.
			 */
			if ((e->eax & XFEATURE_MASK_XTILE) != XFEATURE_MASK_XTILE) {
				e->eax &= ~XFEATURE_MASK_XTILE;
			}
		}
	}

	return cpuid_data;
}

/* Call KVM_TDX_CAPABILITIES for API test. The result isn't used. */
void get_tdx_capabilities(struct kvm_vm *vm)
{
	int i;
	int rc;
	int nr_cpuid_configs = 8;
	struct kvm_tdx_capabilities *tdx_cap = NULL;

	while (true) {
		tdx_cap = realloc(
			tdx_cap, sizeof(*tdx_cap) +
			nr_cpuid_configs * sizeof(*tdx_cap->cpuid_configs));
		tdx_cap->nr_cpuid_configs = nr_cpuid_configs;
		TEST_ASSERT(tdx_cap != NULL,
			"Could not allocate memory for tdx capability "
			"nr_cpuid_configs %d\n", nr_cpuid_configs);
		rc = __tdx_ioctl(vm->fd, KVM_TDX_CAPABILITIES, 0, tdx_cap);
		if (rc < 0 && errno == E2BIG) {
			nr_cpuid_configs *= 2;
			continue;
		}
		TEST_ASSERT(rc == 0, "%s failed: %d %d",
			tdx_cmd_str[KVM_TDX_CAPABILITIES], rc, errno);
		break;
	}
	pr_debug("tdx_cap: attrs: fixed0 0x%016llx fixed1 0x%016llx\n"
		"tdx_cap: xfam fixed0 0x%016llx fixed1 0x%016llx\n",
		tdx_cap->attrs_fixed0, tdx_cap->attrs_fixed1,
		tdx_cap->xfam_fixed0, tdx_cap->xfam_fixed1);
	for (i = 0; i < tdx_cap->nr_cpuid_configs; i++) {
		const struct kvm_tdx_cpuid_config *config =
			&tdx_cap->cpuid_configs[i];
		pr_debug("cpuid config[%d]: leaf 0x%x sub_leaf 0x%x "
			"eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
			i, config->leaf, config->sub_leaf,
			config->eax, config->ebx, config->ecx, config->edx);
	}
}

/*
 * Initialize a VM as a TD with attributes.
 *
 */
void initialize_td_with_attributes(struct kvm_vm *vm, uint64_t attributes)
{
	struct tdx_cpuid_data cpuid_data;
	int rc;

	/* No guest VMM controlled cpuid information yet. */
	struct kvm_tdx_init_vm init_vm;

	rc = kvm_check_cap(KVM_CAP_X2APIC_API);
	TEST_ASSERT(rc, "TDX: KVM_CAP_X2APIC_API is not supported!");
	rc = kvm_check_cap(KVM_CAP_SPLIT_IRQCHIP);
	TEST_ASSERT(rc, "TDX: KVM_CAP_SPLIT_IRQCHIP is not supported!");

	vm_enable_cap(vm, KVM_CAP_X2APIC_API,
		      KVM_X2APIC_API_USE_32BIT_IDS |
			      KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK);
	vm_enable_cap(vm, KVM_CAP_SPLIT_IRQCHIP, 24);

	/* Allocate and setup memory for the td guest. */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TDX_GUEST_PT_FIXED_ADDR,
				    0, TDX_GUEST_MAX_NR_PAGES, 0);

	memset(&init_vm, 0, sizeof(init_vm));

	cpuid_data = get_tdx_cpuid_data(vm);

	init_vm.max_vcpus = TDX_GUEST_MAX_NUM_VCPUS;
	init_vm.attributes = attributes;
	memcpy(&init_vm.cpuid, &cpuid_data, sizeof(cpuid_data));
	tdx_ioctl(vm->fd, KVM_TDX_INIT_VM, 0, &init_vm);
}

/*
 * Initialize a VM as a TD with no attributes.
 *
 */
void initialize_td(struct kvm_vm *vm)
{
	initialize_td_with_attributes(vm, 0);
}

void initialize_td_vcpu(struct kvm_vcpu *vcpu)
{
	struct tdx_cpuid_data cpuid_data;

	cpuid_data = get_tdx_cpuid_data(vcpu->vm);
	vcpu_init_cpuid(vcpu, (struct kvm_cpuid2 *) &cpuid_data);
	tdx_ioctl(vcpu->fd, KVM_TDX_INIT_VCPU, 0, NULL);
}

void add_td_memory(struct kvm_vm *vm, void *source_pages,
		   uint64_t gpa, int size)
{
	struct kvm_tdx_init_mem_region mem_region = {
		.source_addr = (uint64_t)source_pages,
		.gpa = gpa,
		.nr_pages = size / PAGE_SIZE,
	};
	uint32_t metadata = KVM_TDX_MEASURE_MEMORY_REGION;

	TEST_ASSERT((mem_region.nr_pages > 0) &&
		   ((mem_region.nr_pages * PAGE_SIZE) == size),
		   "Cannot add partial pages to the guest memory.\n");
	TEST_ASSERT(((uint64_t)source_pages & (PAGE_SIZE - 1)) == 0,
		    "Source memory buffer is not page aligned\n");
	tdx_ioctl(vm->fd, KVM_TDX_INIT_MEM_REGION, metadata, &mem_region);
}

void finalize_td_memory(struct kvm_vm *vm)
{
	tdx_ioctl(vm->fd, KVM_TDX_FINALIZE_VM, 0, NULL);
}

void build_gdtr_table(void *gdtr_target, void *gdt_target)
{
	uint64_t gdt_table[] = {
		GDT_ENTRY(0, 0, 0),              // NULL_SEL
		GDT_ENTRY(0xc093, 0, 0xfffff),   // LINEAR_DATA32_SEL
		GDT_ENTRY(0xc09b, 0, 0xfffff),   // LINEAR_CODE32_SEL
		GDT_ENTRY(0, 0, 0),              // NULL_SEL
		GDT_ENTRY(0, 0, 0),              // NULL_SEL
		GDT_ENTRY(0, 0, 0),              // NULL_SEL
		GDT_ENTRY(0, 0, 0),              // NULL_SEL
		GDT_ENTRY(0xa09b, 0, 0xfffff)    // LINEAR_CODE64_SEL
	};

	struct tdx_gdtr gdtr;

	gdtr.limit = sizeof(gdt_table) - 1;
	gdtr.base = TDX_GUEST_GDTR_BASE;

	memcpy(gdt_target, gdt_table, sizeof(gdt_table));
	memcpy(gdtr_target, &gdtr, sizeof(gdtr));
}


/*
 * Constructing 1:1 mapping for the lowest 4GB address space using 2MB pages
 * which will be used by the TDX guest when paging is enabled.
 * TODO: use virt_pg_map() functions to dynamically allocate the page tables.
 */
void build_page_tables(void *pt_target, uint64_t  pml4_base_address,
		       uint64_t gpa_shared_bit)
{
	uint64_t i;
	uint64_t shared_pdpt_index;
	uint64_t gpa_shared_mask;
	uint64_t *pde;
	struct page_table *pt;

	pt = malloc(sizeof(struct page_table));
	TEST_ASSERT(pt != NULL, "Could not allocate memory for page tables!\n");
	memset((void *) &(pt->pml4[0]), 0, sizeof(pt->pml4));
	memset((void *) &(pt->pdpt[0]), 0, sizeof(pt->pdpt));
	for (i = 0; i < 8; i++)
		memset((void *) &(pt->pd[i][0]), 0, sizeof(pt->pd[i]));

	/* Populate pml4 entry. */
	pt->pml4[0] = (pml4_base_address + PAGE_SIZE) |
		      _PAGE_PRESENT | _PAGE_RW;

	/* Populate pdpt entries for private memory region. */
	for (i = 0; i < 4; i++)
		pt->pdpt[i] = (pml4_base_address + (i + 2) * PAGE_SIZE) |
			      _PAGE_PRESENT | _PAGE_RW;

	/* Index used in pdpt #0 to map to pd with guest virt shared bit set. */
	static_assert(TDX_GUEST_VIRT_SHARED_BIT >= 32 &&
		      TDX_GUEST_VIRT_SHARED_BIT <= 38,
		      "Guest virtual shared bit must be in the range [32 - 38].\n");
	shared_pdpt_index = 1 << (TDX_GUEST_VIRT_SHARED_BIT - 30);

	/* Populate pdpt entries for shared memory region. */
	for (i = 0; i < 4; i++)
		pt->pdpt[shared_pdpt_index + i] = (pml4_base_address + (i + 6) *
						  PAGE_SIZE) | _PAGE_PRESENT |
						  _PAGE_RW;

	/* Populate pd entries for private memory region. */
	pde = &(pt->pd[0][0]);
	for (i = 0; i < (sizeof(pt->pd) / sizeof(pt->pd[0][0])) / 2; i++, pde++)
		*pde = (i << 21) | _PAGE_PRESENT | _PAGE_RW | _PAGE_PS;

	/* Populate pd entries for shared memory region; set shared bit. */
	pde = &(pt->pd[4][0]);
	gpa_shared_mask = BIT_ULL(gpa_shared_bit);
	for (i = 0; i < (sizeof(pt->pd) / sizeof(pt->pd[0][0])) / 2; i++, pde++)
		*pde = gpa_shared_mask | (i << 21) | _PAGE_PRESENT | _PAGE_RW |
		       _PAGE_PS;

	memcpy(pt_target, pt, 10 * PAGE_SIZE);
}

static void
__attribute__((__flatten__, section("guest_boot_section"))) guest_boot(void)
{
	asm volatile(" .code32\n\t;"
		     "main_32:\n\t;"
		     "	cli\n\t;"
		     "	movl $" __stringify(TDX_GUEST_STACK_BASE) ", %%esp\n\t;"
		     "	movl $" __stringify(TDX_GUEST_GDTR_ADDR) ", %%eax\n\t;"
		     "	lgdt (%%eax)\n\t;"
		     "	movl $0x660, %%eax\n\t;"
		     "	movl %%eax, %%cr4\n\t;"
		     "	movl $" __stringify(TDX_GUEST_PT_FIXED_ADDR) ", %%eax\n\t;"
		     "	movl %%eax, %%cr3\n\t;"
		     "	movl $0x80000023, %%eax\n\t;"
		     "	movl %%eax, %%cr0\n\t;"
		     "	ljmp $" __stringify(TDX_GUEST_LINEAR_CODE64_SEL)
		     ", $" __stringify(TDX_GUEST_CODE_ENTRY) "\n\t;"
		     /*
		      * This is where the CPU will start running.
		      * Do not remove any int3 instruction below.
		      */
		     "reset_vector:\n\t;"
		     "	jmp main_32\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     "	int3\n\t;"
		     ".code64\n\t"
		     :::"rax");
}

extern char *__start_guest_boot_section;
extern char *__stop_guest_boot_section;
#define GUEST_BOOT_SIZE ((uint64_t)&__stop_guest_boot_section -\
			(uint64_t)&__start_guest_boot_section)

/*
 * Copies the guest code to the guest image. If signature value is not 0, it
 * will verify that the guest code ends with the signature provided. We might
 * need to check the signature to prevent compiler to add additional instruction
 * to the end of the guest code which might create problems in some cases ie
 * when copying code for resetvector.
 */
void copy_guest_code(void *target, void *guest_function, size_t code_size,
		     uint64_t signature)
{
	uint64_t *end;

	TEST_ASSERT((target != NULL) && (guest_function != NULL) &&
		    (code_size > 0), "Invalid inputs to copy guest code\n");
	if (signature) {
		while (code_size >= sizeof(signature)) {
			end = guest_function + code_size - sizeof(signature);
			if (*end == signature)
				break;
			/* Trimming the unwanted code at the end added by
			 * compiler. We need to add nop instruction to the
			 * begginning of the buffer to make sure that the guest
			 * code is aligned from the bottom and top as expected
			 * based on the original code size. This is important
			 * for reset vector which is copied to the bottom of
			 * the first 4GB memory.
			 */
			code_size--;
			*(unsigned char *)target = 0x90;
			target++;
		}
		TEST_ASSERT(code_size >= sizeof(signature),
			    "Guest code does not end with the signature: %lx\n"
			    , signature);
	}

	memcpy(target, guest_function, code_size);
}

void prepare_source_image(struct kvm_vm *vm, void *guest_code,
			  size_t guest_code_size, uint64_t guest_code_signature)
{
	void *source_mem, *pt_address, *code_address, *gdtr_address,
	     *gdt_address, *guest_code_base;
	int number_of_pages;

	number_of_pages = (GUEST_BOOT_SIZE + guest_code_size) / PAGE_SIZE + 1 +
			TDX_GUEST_NR_PT_PAGES + TDX_GUEST_STACK_NR_PAGES;
	TEST_ASSERT(number_of_pages < TDX_GUEST_MAX_NR_PAGES,
		    "Initial image does not fit to the memory");

	source_mem = memalign(PAGE_SIZE,
				   (TDX_GUEST_MAX_NR_PAGES * PAGE_SIZE));
	TEST_ASSERT(source_mem != NULL,
		    "Could not allocate memory for guest image\n");

	pt_address = source_mem;
	gdtr_address = source_mem + (TDX_GUEST_NR_PT_PAGES * PAGE_SIZE);
	gdt_address = gdtr_address + PAGE_SIZE;
	code_address = source_mem + (TDX_GUEST_MAX_NR_PAGES * PAGE_SIZE) -
			GUEST_BOOT_SIZE;
	guest_code_base =  gdt_address + (TDX_GUEST_STACK_NR_PAGES *
					  PAGE_SIZE);

	build_page_tables(pt_address, TDX_GUEST_PT_FIXED_ADDR, vm->pa_bits - 1);
	build_gdtr_table(gdtr_address, gdt_address);

	/* reset vector code should end with int3 instructions.
	 * The unused bytes at the reset vector with int3 to trigger triple
	 * fault shutdown if the guest manages to get into the unused code.
	 * Using the last 8 int3 instruction as a signature to find the function
	 * end offset for guest boot code that includes the instructions for
	 * reset vector.
	 * TODO: Using signature to find the exact size is a little strange but
	 * compiler might add additional bytes to the end of the function which
	 * makes it hard to calculate the offset addresses correctly.
	 * Alternatively, we can construct the jmp instruction for the reset
	 * vector manually to prevent any offset mismatch when copying the
	 * compiler generated code.
	 */
	copy_guest_code(code_address, guest_boot, GUEST_BOOT_SIZE,
			EIGHT_INT3_INSTRUCTIONS);
	if (guest_code)
		copy_guest_code(guest_code_base, guest_code, guest_code_size,
				guest_code_signature);

	add_td_memory(vm, source_mem, TDX_GUEST_PT_FIXED_ADDR,
		      (TDX_GUEST_MAX_NR_PAGES * PAGE_SIZE));
	free(source_mem);
}
