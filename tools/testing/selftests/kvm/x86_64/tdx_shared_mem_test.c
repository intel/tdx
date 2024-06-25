// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm.h>
#include <stdint.h>

#include "kvm_util.h"
#include "processor.h"
#include "tdx/tdcall.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"
#include "test_util.h"

#define TDX_SHARED_MEM_TEST_PRIVATE_GVA (0x80000000)
#define TDX_SHARED_MEM_TEST_VADDR_SHARED_MASK BIT_ULL(30)
#define TDX_SHARED_MEM_TEST_SHARED_GVA     \
	(TDX_SHARED_MEM_TEST_PRIVATE_GVA | \
	 TDX_SHARED_MEM_TEST_VADDR_SHARED_MASK)

#define TDX_SHARED_MEM_TEST_GUEST_WRITE_VALUE (0xcafecafe)
#define TDX_SHARED_MEM_TEST_HOST_WRITE_VALUE (0xabcdabcd)

#define TDX_SHARED_MEM_TEST_INFO_PORT 0x87

/*
 * Shared variables between guest and host
 */
static uint64_t test_mem_private_gpa;
static uint64_t test_mem_shared_gpa;

void guest_shared_mem(void)
{
	uint32_t *test_mem_shared_gva =
		(uint32_t *)TDX_SHARED_MEM_TEST_SHARED_GVA;

	uint64_t placeholder;
	uint64_t ret;

	/* Map gpa as shared */
	ret = tdg_vp_vmcall_map_gpa(test_mem_shared_gpa, PAGE_SIZE,
				    &placeholder);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);

	*test_mem_shared_gva = TDX_SHARED_MEM_TEST_GUEST_WRITE_VALUE;

	/* Exit so host can read shared value */
	ret = tdg_vp_vmcall_instruction_io(TDX_SHARED_MEM_TEST_INFO_PORT, 4,
					   TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					   &placeholder);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);

	/* Read value written by host and send it back out for verification */
	ret = tdg_vp_vmcall_instruction_io(TDX_SHARED_MEM_TEST_INFO_PORT, 4,
					   TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					   (uint64_t *)test_mem_shared_gva);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);
}

int verify_shared_mem(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	vm_vaddr_t test_mem_private_gva;
	uint32_t *test_mem_hva;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_shared_mem);

	/*
	 * Set up shared memory page for testing by first allocating as private
	 * and then mapping the same GPA again as shared. This way, the TD does
	 * not have to remap its page tables at runtime.
	 */
	test_mem_private_gva = vm_vaddr_alloc(vm, vm->page_size,
					      TDX_SHARED_MEM_TEST_PRIVATE_GVA);
	TEST_ASSERT_EQ(test_mem_private_gva, TDX_SHARED_MEM_TEST_PRIVATE_GVA);

	test_mem_hva = addr_gva2hva(vm, test_mem_private_gva);
	TEST_ASSERT(test_mem_hva != NULL,
		    "Guest address not found in guest memory regions\n");

	test_mem_private_gpa = addr_gva2gpa(vm, test_mem_private_gva);
	virt_pg_map_shared(vm, TDX_SHARED_MEM_TEST_SHARED_GVA,
			   test_mem_private_gpa);

	test_mem_shared_gpa = test_mem_private_gpa | BIT_ULL(vm->pa_bits - 1);
	sync_global_to_guest(vm, test_mem_private_gpa);
	sync_global_to_guest(vm, test_mem_shared_gpa);

	td_finalize(vm);

	printf("Verifying shared memory accesses for TDX\n");

	/* Begin guest execution; guest writes to shared memory. */
	printf("\t ... Starting guest execution\n");

	/* Handle map gpa as shared */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);

	td_vcpu_run(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_SHARED_MEM_TEST_INFO_PORT, 4,
			   TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	TEST_ASSERT_EQ(*test_mem_hva, TDX_SHARED_MEM_TEST_GUEST_WRITE_VALUE);

	*test_mem_hva = TDX_SHARED_MEM_TEST_HOST_WRITE_VALUE;
	td_vcpu_run(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_SHARED_MEM_TEST_INFO_PORT, 4,
			   TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	TEST_ASSERT_EQ(
		*(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset),
		TDX_SHARED_MEM_TEST_HOST_WRITE_VALUE);

	printf("\t ... PASSED\n");

	kvm_vm_free(vm);

	return 0;
}

int main(int argc, char **argv)
{
	if (!is_tdx_enabled()) {
		printf("TDX is not supported by the KVM\n"
		       "Skipping the TDX tests.\n");
		return 0;
	}

	return verify_shared_mem();
}
