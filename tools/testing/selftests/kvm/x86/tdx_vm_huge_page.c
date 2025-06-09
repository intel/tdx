#include <stdint.h>
#include <asm/kvm.h>
#include <asm/vmx.h>
#include <linux/kvm.h>
#include <linux/sizes.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/guestmem.h>


#include "kvm_util.h"
#include "processor.h"
#include "tdx/tdcall.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"
#include "test_util.h"

/*
 * 0x80000000 is arbitrarily selected, but it should not overlap with selftest
 * code or boot page.
 */
#define HUGE_PAGE_TEST_AREA_GPA (0x80000000)
/* Test area GPA is arbitrarily selected */
#define HUGE_PAGE_AREA_GVA_PRIVATE (0x90000000)
#define HUGE_PAGE_AREA_GVA_SHARED (0x190000000)
#define TDX_PAGE_SIZE_MISMATCH 0xC0000B0B00000000
/* The test area is 2MB in size */
#define HUGE_PAGE_AREA_SIZE (2 << 20)

#define HUGE_PAGE_ASSERT(x)                             \
	do {                                            \
	        if (!(x))                               \
	                tdx_test_fatal(__LINE__);       \
	} while (0)


#define HUGE_PAGE_ACCEPT_PRINT_PORT 0x87

static void guest_test_huge_page(void)
{
	void *test_area_gva_private = (void *)HUGE_PAGE_AREA_GVA_PRIVATE;
	void *test_area_gva_shared = (void *)HUGE_PAGE_AREA_GVA_SHARED;

	memset(test_area_gva_private, 1, 8);

	tdx_test_report_to_user_space(1);
	memset(test_area_gva_shared, 1, 8);

	tdx_test_report_to_user_space(2);
	memset(test_area_gva_private, 1, 8);
	tdx_test_success();
}

static void guest_ve_handler(struct ex_regs *regs)
{
	uint64_t ret;
	struct ve_info ve;
#define MEM_PAGE_ACCEPT_LEVEL_4K 0
#define MEM_PAGE_ACCEPT_LEVEL_2M 1

	ret = tdg_vp_veinfo_get(&ve);
	HUGE_PAGE_ASSERT(!ret);

	/* For this test, we will only handle EXIT_REASON_EPT_VIOLATION */
	HUGE_PAGE_ASSERT(ve.exit_reason == EXIT_REASON_EPT_VIOLATION);

	if (ve.gpa & tdx_s_bit)
		return;

	tdx_test_report_to_user_space(3);

	ret = tdg_mem_page_accept(ve.gpa, MEM_PAGE_ACCEPT_LEVEL_2M);
	if (!ret)
		tdx_test_send_64bit(HUGE_PAGE_ACCEPT_PRINT_PORT, ve.gpa | MEM_PAGE_ACCEPT_LEVEL_2M);

	if (ret == (TDX_PAGE_SIZE_MISMATCH | MEM_PAGE_ACCEPT_LEVEL_2M)) {
		tdx_test_report_to_user_space(4);
		ret = tdg_mem_page_accept(ve.gpa, MEM_PAGE_ACCEPT_LEVEL_4K);
		if (!ret)
		tdx_test_send_64bit(HUGE_PAGE_ACCEPT_PRINT_PORT, ve.gpa | MEM_PAGE_ACCEPT_LEVEL_4K);
	}

	HUGE_PAGE_ASSERT(!ret);
}

static void punch_shared(struct kvm_vm *vm, u64 gpa, u64 size)
{
	void *host_addr = addr_gva2hva(vm, HUGE_PAGE_AREA_GVA_SHARED);
	int ret;

	ret = madvise(host_addr, size, MADV_DONTNEED);

	HUGE_PAGE_ASSERT(!ret);
}


static void add_memslot(struct kvm_vm *vm, size_t memslot_size, uint64_t guest_memfd_flags)
{
	struct userspace_mem_region *region;
	int guest_memfd;

	region = vm_mem_region_alloc(vm);
	guest_memfd = vm_create_guest_memfd(vm, memslot_size, guest_memfd_flags);
	TEST_REQUIRE(guest_memfd > 0);

	guest_memfd = vm_mem_region_install_guest_memfd(region, guest_memfd, guest_memfd_flags);
	vm_mem_region_mmap(region, memslot_size, MAP_SHARED, guest_memfd, 0);

	vm_mem_region_install_memory(region, memslot_size, PAGE_SIZE);

	region->region.slot = 3;
	region->region.flags = KVM_MEM_GUEST_MEMFD;
	region->region.guest_phys_addr = HUGE_PAGE_TEST_AREA_GPA;
	region->region.guest_memfd_offset = 0;

	vm_mem_region_add(vm, region);

	return;
}
static void huge_page_test(bool non_in_place, uint64_t guest_memfd_flags)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	void *guest_code;
	uint64_t test_area_npages;
	vm_vaddr_t test_area_gva_private;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	guest_code = guest_test_huge_page;
	vcpu = td_vcpu_add(vm, 0, guest_code);
	vm_install_exception_handler(vm, VE_VECTOR, guest_ve_handler);

	test_area_npages = HUGE_PAGE_AREA_SIZE / vm->page_size;
	if (non_in_place) {
		/*
		 * vm_userspace_mem_region_add() is not updated for in-place conversion.
		 * Use it for non-in-place conversion to ensure it's not broken
		 */
		vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
					    HUGE_PAGE_TEST_AREA_GPA, 3,
					    test_area_npages, KVM_MEM_GUEST_MEMFD);
	} else {
		add_memslot(vm, HUGE_PAGE_AREA_SIZE, guest_memfd_flags);
	}
	vm->memslots[MEM_REGION_TEST_DATA] = 3;


	test_area_gva_private = vm_vaddr_alloc_private(vm, HUGE_PAGE_AREA_SIZE,
							   HUGE_PAGE_AREA_GVA_PRIVATE,
							   HUGE_PAGE_TEST_AREA_GPA,
							   MEM_REGION_TEST_DATA);
	TEST_ASSERT_EQ(test_area_gva_private, HUGE_PAGE_AREA_GVA_PRIVATE);
	virt_map_shared(vm, HUGE_PAGE_AREA_GVA_SHARED,
			HUGE_PAGE_TEST_AREA_GPA,
			test_area_npages);
	TEST_ASSERT_EQ(addr_gva2gpa(vm, HUGE_PAGE_AREA_GVA_SHARED) & ~vm->arch.s_bit,
			   (vm_paddr_t)HUGE_PAGE_TEST_AREA_GPA);

	td_finalize(vm);
	handle_memory_conversion(vm, vcpu->id, HUGE_PAGE_TEST_AREA_GPA,
				 HUGE_PAGE_AREA_SIZE, false);
	handle_memory_conversion(vm, vcpu->id, HUGE_PAGE_TEST_AREA_GPA,
				 HUGE_PAGE_AREA_SIZE, true);
	for (;;) {
	        _vcpu_run(vcpu);
	        if (vcpu->run->exit_reason == KVM_EXIT_IO) {
			switch (vcpu->run->io.port) {
			case HUGE_PAGE_ACCEPT_PRINT_PORT: {
							uint64_t gpa = tdx_test_read_64bit(vcpu,
						   HUGE_PAGE_ACCEPT_PRINT_PORT);
				printf("\t ... guest accepted 1 page at GPA: 0x%llx, level %d\n",
				       gpa & PAGE_MASK, (int)(gpa & 0x3));
				break;
			}
			case TDX_TEST_REPORT_PORT: {
				int sync_stage = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);
				printf("guest sync stage=%x\n", sync_stage);
				break;
			}
			default:
				tdx_test_assert_success(vcpu);
				printf("\t ... PASSED\n");
				goto out;
			}
		} else if (vcpu->run->exit_reason == KVM_EXIT_MEMORY_FAULT) {
			printf("handle convertion gpa=%llx, size=%llx, to private=%d\n",  vcpu->run->memory_fault.gpa, vcpu->run->memory_fault.size, vcpu->run->memory_fault.flags == KVM_MEMORY_EXIT_FLAG_PRIVATE);
			handle_memory_conversion(
				vm, vcpu->id, vcpu->run->memory_fault.gpa,
				vcpu->run->memory_fault.size,
				vcpu->run->memory_fault.flags == KVM_MEMORY_EXIT_FLAG_PRIVATE);

			if (non_in_place) {
				if (vcpu->run->memory_fault.flags != KVM_MEMORY_EXIT_FLAG_PRIVATE)
					vm_guest_mem_punch_hole(vm, vcpu->run->memory_fault.gpa, vcpu->run->memory_fault.size);
				else
					punch_shared(vm, vcpu->run->memory_fault.gpa, vcpu->run->memory_fault.size);
			}

			continue;
	        } else
			TEST_ASSERT(0, "Unexpected VM Exit");
	}

out:
	kvm_vm_free(vm);
}

static void huge_page_test_basic(void)
{
	printf("Verifying huge page without in-place conversion:\n");
	huge_page_test(true, 0);
}

static void huge_page_test_in_place_conversion_2M(void)
{
	printf("Verifying huge page with 2MB in-place conversion:\n");
	huge_page_test(false, GUEST_MEMFD_FLAG_SUPPORT_SHARED |
			      GUEST_MEMFD_FLAG_HUGETLB | GUESTMEM_HUGETLB_FLAG_2MB);
}

int main(int argc, char **argv)
{
	/* Disable stdout buffering */
	setbuf(stdout, NULL);

	if (!is_tdx_enabled()) {
	        printf("TDX is not supported by the KVM\n"
	               "Skipping the TDX tests.\n");
	        return 0;
	}

	run_in_new_process(&huge_page_test_basic);
	run_in_new_process(&huge_page_test_in_place_conversion_2M);
}
