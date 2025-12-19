#include <stdint.h>
#include <asm/kvm.h>
#include <asm/vmx.h>
#include <linux/kvm.h>
#include <linux/sizes.h>
#include <linux/align.h>
#include <stdbool.h>
#include <stdint.h>

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
#define TEST_AREA_GPA (0x80000000)

/* Test area GPA is arbitrarily selected */
#define TEST_AREA_GVA_PRIVATE (0x90000000)
#define TEST_AREA_GVA_SHARED (0x190000000)

/* The test area is 2*2MB in size */
#define TEST_AREA_SIZE (2*PG_SIZE_2M)
#define TEST_AREA_ORDER 9

#define ACCEPT_PRINT_PORT 0x87

#define HUGE_TEST_ASSERT(x)                             \
	do {                                            \
	        if (!(x))                               \
	                tdx_test_fatal(__LINE__);       \
	} while (0)


#define TDX_PAGE_SIZE_MISMATCH 0xC0000B0B00000000
#define MEM_PAGE_ACCEPT_LEVEL_4K 0
#define MEM_PAGE_ACCEPT_LEVEL_2M 1

static int guest_stage;

/*
 * Shared variable between guest and host
 */
static uint64_t test_area_shared_gpa;
static uint64_t test_area_shared_gva;
static uint64_t test_area_private_gva;
static uint64_t test_area_private_gpa;

static void guest_accept_2M(unsigned long gpa, bool expect_mismatch)
{
	uint64_t ret;
	unsigned long aligned_gpa = ALIGN_DOWN(gpa, PG_SIZE_2M);

	ret = tdg_mem_page_accept(aligned_gpa, MEM_PAGE_ACCEPT_LEVEL_2M);

	HUGE_TEST_ASSERT(expect_mismatch ?
			 (ret == (TDX_PAGE_SIZE_MISMATCH | MEM_PAGE_ACCEPT_LEVEL_2M)) :
			 !ret);

	if (!ret)
		tdx_test_send_64bit(ACCEPT_PRINT_PORT,
				    aligned_gpa | MEM_PAGE_ACCEPT_LEVEL_2M);
}

static void guest_accept_4K(unsigned long gpa)
{
	uint64_t ret;

	ret = tdg_mem_page_accept(gpa, MEM_PAGE_ACCEPT_LEVEL_4K);
	if (!ret)
		tdx_test_send_64bit(ACCEPT_PRINT_PORT, gpa | MEM_PAGE_ACCEPT_LEVEL_4K);

	HUGE_TEST_ASSERT(!ret);
}

static void guest_test_huge_page(void)
{
	tdx_test_report_to_user_space(guest_stage);
	memset((void *)test_area_private_gva, 1, 8);
	guest_stage++;

	/* implict conversions */
	tdx_test_report_to_user_space(guest_stage);
	memset((void *)test_area_shared_gva, 1, 8);
	memset((void *)test_area_private_gva, 1, 8);
	guest_stage++;

	tdx_test_report_to_user_space(guest_stage);
	memset((void *)test_area_shared_gva + 10*PAGE_SIZE, 1, 8);
	memset((void *)test_area_private_gva + 10*PAGE_SIZE, 1, 8);
	guest_stage++;

	tdx_test_report_to_user_space(guest_stage);
	memset((void *)test_area_shared_gva + PAGE_SIZE, 1, 8);
	memset((void *)test_area_shared_gva + 10*PAGE_SIZE, 1, 8);
	guest_stage++;

	/* explict conversions */
	tdx_test_report_to_user_space(guest_stage);
	tdg_vp_vmcall_map_gpa(test_area_shared_gpa + PG_SIZE_2M, PG_SIZE_4K, NULL);
	memset((void *)test_area_shared_gva + PG_SIZE_2M, 1, 8);
	tdg_vp_vmcall_map_gpa(test_area_private_gpa + PG_SIZE_2M, PG_SIZE_2M, NULL);
	guest_accept_2M(test_area_private_gpa + PG_SIZE_2M, false);
	guest_stage++;

	tdx_test_report_to_user_space(guest_stage);
	tdg_vp_vmcall_map_gpa(test_area_shared_gpa + PG_SIZE_2M, PG_SIZE_2M, NULL);

	tdx_test_success();
}

static void guest_ve_handler(struct ex_regs *regs)
{
	struct ve_info ve;
	uint64_t ret;
	int stage;

	ret = tdg_vp_veinfo_get(&ve);
	HUGE_TEST_ASSERT(!ret);

	/* For this test, we will only handle EXIT_REASON_EPT_VIOLATION */
	HUGE_TEST_ASSERT(ve.exit_reason == EXIT_REASON_EPT_VIOLATION);

	if (ve.gpa & tdx_s_bit)
		return;

	stage = READ_ONCE(guest_stage);
	switch (stage) {
	case 0:
		guest_accept_2M(ve.gpa, false);
		break;
	case 1:
	case 2:
		guest_accept_2M(ve.gpa, true);
		guest_accept_4K(ve.gpa);
		break;
	default:
		break;
	}
}

static void handle_exit_hypercall(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	uint64_t gpa = run->hypercall.args[0];
	uint64_t size = run->hypercall.args[1] * PAGE_SIZE;
	bool map_private = run->hypercall.args[2] == KVM_MAP_GPA_RANGE_ENCRYPTED;
	struct kvm_vm *vm = vcpu->vm;

	TEST_ASSERT(run->hypercall.args[2] == KVM_MAP_GPA_RANGE_ENCRYPTED ||
		    run->hypercall.args[2] == KVM_MAP_GPA_RANGE_DECRYPTED,
		    "Incorret KVM_MAP_GPA_RANGE state %llx", run->hypercall.args[2]);

	TEST_ASSERT(run->hypercall.nr == KVM_HC_MAP_GPA_RANGE,
		    "Wanted MAP_GPA_RANGE (%u), got '%llu'",
		    KVM_HC_MAP_GPA_RANGE, run->hypercall.nr);

	printf("map gpa %lx size %lx to %s\n", gpa, size, map_private ? "private" : "shared");
	handle_memory_conversion_v2(vm, vcpu->id, gpa, size, map_private);

	run->hypercall.ret = 0;
}

static void huge_page_test(void)
{
	uint64_t guest_memfd_flags;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t npages;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_SHMEM, 0);

	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL, (1 << KVM_HC_MAP_GPA_RANGE));

	vcpu = td_vcpu_add(vm, 0, guest_test_huge_page);
	vm_install_exception_handler(vm, VE_VECTOR, guest_ve_handler);

	guest_memfd_flags = GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_HUGETLB;
	npages = TEST_AREA_SIZE / vm->page_size;

	vm_mem_add(vm, VM_MEM_SRC_SHMEM, TEST_AREA_GPA, 3, npages,
		   KVM_MEM_GUEST_MEMFD, -1, 0, guest_memfd_flags, TEST_AREA_ORDER);
	vm->memslots[MEM_REGION_TEST_DATA] = 3;

	/* Set all test area to shared */
	handle_memory_conversion_v2(vm, vcpu->id, TEST_AREA_GPA, TEST_AREA_SIZE, false);

	test_area_private_gva = vm_vaddr_alloc_private(vm, TEST_AREA_SIZE,
					     TEST_AREA_GVA_PRIVATE,
					     TEST_AREA_GPA,
					     MEM_REGION_TEST_DATA);
	TEST_ASSERT_EQ(test_area_private_gva, TEST_AREA_GVA_PRIVATE);

	virt_map_shared(vm, TEST_AREA_GVA_SHARED, TEST_AREA_GPA, npages);
	TEST_ASSERT_EQ(addr_gva2gpa(vm, TEST_AREA_GVA_SHARED) & ~vm->arch.s_bit,
		      (vm_paddr_t)TEST_AREA_GPA);

	test_area_private_gpa = TEST_AREA_GPA;
	test_area_shared_gva = TEST_AREA_GVA_SHARED;
	test_area_shared_gpa = TEST_AREA_GPA | vm->arch.s_bit;

	sync_global_to_guest(vm, test_area_shared_gva);
	sync_global_to_guest(vm, test_area_shared_gpa);
	sync_global_to_guest(vm, test_area_private_gva);
	sync_global_to_guest(vm, test_area_private_gpa);

	td_finalize(vm);

	/* Set all test area to private */
	handle_memory_conversion_v2(vm, vcpu->id, TEST_AREA_GPA, TEST_AREA_SIZE, true);

	for (;;) {
		_vcpu_run(vcpu);
		if (vcpu->run->exit_reason == KVM_EXIT_IO) {
			switch (vcpu->run->io.port) {
			case ACCEPT_PRINT_PORT:
			{
				uint64_t gpa = tdx_test_read_64bit(vcpu, ACCEPT_PRINT_PORT);
				printf("\t ... guest accepted 1 page at GPA: 0x%llx, level %d\n",
				       gpa & PAGE_MASK, (int)(gpa & 0x3));
				break;
			}
			case TDX_TEST_REPORT_PORT:
			{
				   int sync_stage = *(uint32_t *)((void *)vcpu->run +
								  vcpu->run->io.data_offset);
				   printf("guest sync stage=%x\n", sync_stage);
				   break;
			}
			default:
				   tdx_test_assert_success(vcpu);
				   printf("\t ... PASSED\n");
				   goto out;
			}
		} else if (vcpu->run->exit_reason == KVM_EXIT_MEMORY_FAULT) {
			printf("handle convertion gpa=%llx, size=%llx, to private=%d\n",
			       vcpu->run->memory_fault.gpa, vcpu->run->memory_fault.size,
			       vcpu->run->memory_fault.flags == KVM_MEMORY_EXIT_FLAG_PRIVATE);

			handle_memory_conversion_v2(
					vm, vcpu->id, vcpu->run->memory_fault.gpa,
					vcpu->run->memory_fault.size,
					vcpu->run->memory_fault.flags == KVM_MEMORY_EXIT_FLAG_PRIVATE);

			continue;
		} else if (vcpu->run->exit_reason == KVM_EXIT_HYPERCALL) {
			handle_exit_hypercall(vcpu);
		} else {
			TEST_ASSERT(false, "Unexpected VM Exit %d", vcpu->run->exit_reason);
		}
	}

out:
	kvm_vm_free(vm);
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
	if (!(kvm_check_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES) & KVM_MEMORY_ATTRIBUTE_PRIVATE)) {
		printf("equirement not met: kvm_check_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES) & KVM_MEMORY_ATTRIBUTE_PRIVATE\n");
		return 0;
	}
	huge_page_test();

}
