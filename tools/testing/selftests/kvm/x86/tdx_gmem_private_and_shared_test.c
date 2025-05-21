// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test conversion flows when guest_memfd is used to back both private and
 * shared memory.
 *
 * The tests here add on to guest_memfd_conversions_test to check behaviors
 * expected for TDs, such as
 *
 * + zeroing of memory during conversions
 * + use of the MapGPA vmcall for explicit conversions
 * + implicit conversions
 *
 * Copyright (c) 2024, Google LLC.
 */
#include <asm/vmx.h>
#include <linux/guestmem.h>
#include <linux/sizes.h>
#include <sys/wait.h>

#include "kvm_util.h"
#include "processor.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "test_util.h"
#include "ucall_common.h"

#define TEST_MEMSLOT (10)
/*
 * Use high GPA above APIC_DEFAULT_PHYS_BASE to avoid clashing with
 * APIC_DEFAULT_PHYS_BASE.
 *
 * The selected address need not be the same as TEST_GVA_PRIVATE,
 * but it should not overlap with selftest code or boot page.
 */
#define TEST_GPA (0x100000000ULL)
#define TEST_GVA_PRIVATE (0x90000000)
/* Select any bit that can be used as a flag */
#define TEST_GVA_SHARED_BIT (32)
/*
 * TEST_GVA_SHARED is used to map the same GPA twice into the guest, once as
 * shared and once as private
 */
#define TEST_GVA_SHARED (TEST_GVA_PRIVATE | BIT_ULL(TEST_GVA_SHARED_BIT))

enum {
	UCALL_CHECK_MEM = NUM_UCALLS + 1,
	UCALL_MAP_GPA,
};

static void __guest_use_memory(uint64_t gva, char expected_read_value,
			       char write_value)
{
	char *mem = (char *)gva;

	if (expected_read_value != 'X')
		GUEST_ASSERT_EQ(*mem, expected_read_value);

	if (write_value != 'X')
		*mem = write_value;
}

static void __guest_map_gpa(uint64_t gpa, uint64_t size, uint64_t expected_ret,
			    uint64_t expected_failed_gpa)
{
	uint64_t failed_gpa;
	uint64_t ret;

	ret = tdg_vp_vmcall_map_gpa(gpa, size, &failed_gpa);
	GUEST_ASSERT_EQ(ret, expected_ret);
	if (expected_ret)
		GUEST_ASSERT_EQ(failed_gpa, expected_failed_gpa);
}

static void guest_code(void)
{
	struct ucall uc;
	uint64_t cmd;

	for (;;) {
		cmd = ucall_read(&uc, UCALL_SYNC, 0);

		switch (cmd) {
		case UCALL_CHECK_MEM:
			__guest_use_memory(uc.args[0], uc.args[1], uc.args[2]);
			break;
		case UCALL_MAP_GPA:
			__guest_map_gpa(uc.args[0], uc.args[1], uc.args[2],
					uc.args[3]);
			break;
		default:
			GUEST_FAIL("Unknown ucall %ld.", cmd);
		}
	}
}

static int vcpu_run_handle_basic_ucalls(struct kvm_vcpu *vcpu)
{
	struct ucall uc;
	int rc;

keep_going:
	do {
		rc = __vcpu_run(vcpu);
	} while (rc == -1 && errno == EINTR);

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_PRINTF:
		REPORT_GUEST_PRINTF(uc);
		goto keep_going;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	}

	return rc;
}

/**
 * guest_use_memory() - Assert that guest can use memory at @gva.
 *
 * @vcpu: the vcpu to run this test on.
 * @gva: the virtual address in the guest to try to use.
 * @expected_read_value: the value that is expected at @gva. Set this to 'X' to
 *                       skip checking current value.
 * @write_value: value to write to @gva. Set to 'X' to skip writing value to
 *               @address.
 * @expected_errno: the expected errno if an error is expected while reading or
 *                  writing @gva. Set to 0 if no exception is expected,
 *                  otherwise set it to the expected errno.
 */
static void guest_use_memory(struct kvm_vcpu *vcpu, uint64_t gva,
			     char expected_read_value, char write_value,
			     int expected_errno)
{
	struct ucall *p_uc;
	uint64_t cmd;
	int rc;

	cmd = get_writable_ucall(vcpu, &p_uc);
	TEST_ASSERT_EQ(cmd, UCALL_SYNC);
	p_uc->cmd = UCALL_CHECK_MEM;
	p_uc->args[0] = gva;
	p_uc->args[1] = expected_read_value;
	p_uc->args[2] = write_value;

	rc = vcpu_run_handle_basic_ucalls(vcpu);
	if (expected_errno) {
		TEST_ASSERT_EQ(rc, -1);
		TEST_ASSERT_EQ(errno, expected_errno);

		switch (expected_errno) {
		case EFAULT:
			TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_MEMORY_FAULT);
			break;
		}
	} else {
		struct ucall uc;
		TEST_ASSERT_EQ(rc, 0);
		TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);

		/*
		 * UCALL_DONE() uses up one struct ucall slot. To reuse the slot
		 * in another run of guest_check_mem, free up that slot.
		 */
		ucall_free((struct ucall *)uc.hva);
	}
}

static void do_guest_map_gpa(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
			     uint64_t gpa, uint64_t size, bool to_shared,
			     uint64_t expected_ret,
			     uint64_t expected_failed_gpa)
{
	uint64_t hc_to_private;
	struct ucall *p_uc;
	uint64_t hc_size;
	uint64_t hc_gpa;
	uint64_t cmd;

	if (to_shared)
		gpa |= vm->arch.s_bit;

	cmd = get_writable_ucall(vcpu, &p_uc);
	TEST_ASSERT_EQ(cmd, UCALL_SYNC);
	p_uc->cmd = UCALL_MAP_GPA;
	p_uc->args[0] = gpa;
	p_uc->args[1] = size;
	p_uc->args[2] = expected_ret;
	p_uc->args[3] = expected_failed_gpa;

	vcpu_run_handle_basic_ucalls(vcpu);

	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_HYPERCALL);
	TEST_ASSERT_EQ(vcpu->run->hypercall.nr, KVM_HC_MAP_GPA_RANGE);
	hc_gpa = vcpu->run->hypercall.args[0];
	hc_size = vcpu->run->hypercall.args[1] << vm->page_shift;
	hc_to_private = vcpu->run->hypercall.args[2] & KVM_MAP_GPA_RANGE_ENCRYPTED;

	TEST_ASSERT_EQ(hc_gpa, vm_untag_gpa(vm, gpa));
	handle_memory_conversion(vm, vcpu->id, hc_gpa, hc_size, hc_to_private);

	/* Let guest check conversion outcome and wait for next command. */
	vcpu_run_handle_basic_ucalls(vcpu);
}

static void guest_map_gpa_shared(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
				 uint64_t gpa, uint64_t size,
				 uint64_t expected_ret,
				 uint64_t expected_failed_gpa)
{
	do_guest_map_gpa(vm, vcpu, gpa, size, true, expected_ret,
			 expected_failed_gpa);
}

static void guest_map_gpa_private(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
				  uint64_t gpa, uint64_t size,
				  uint64_t expected_ret,
				  uint64_t expected_failed_gpa)
{
	do_guest_map_gpa(vm, vcpu, gpa, size, false, expected_ret,
			 expected_failed_gpa);
}

/**
 * host_use_memory() - Assert that host can fault and use memory at @address.
 *
 * @address: the address to be testing.
 * @expected_read_value: the value expected to be read from @address. Set to 'X'
 *                       to skip checking current value at @address.
 * @write_value: the value to write to @address. Set to 'X' to skip writing
 *               value to @address.
 */
static void host_use_memory(char *address, char expected_read_value,
			    char write_value)
{
	if (expected_read_value != 'X')
		TEST_ASSERT_EQ(*address, expected_read_value);

	if (write_value != 'X')
		*address = write_value;
}

static void assert_host_cannot_fault(char *address)
{
	pid_t child_pid;

	child_pid = fork();
	TEST_ASSERT(child_pid != -1, "fork failed");

	if (child_pid == 0) {
		*address = 'A';
		TEST_FAIL("Child should have exited with a signal");
	} else {
		int status;

		waitpid(child_pid, &status, 0);

		TEST_ASSERT(WIFSIGNALED(status),
			    "Child should have exited with a signal");
		TEST_ASSERT_EQ(WTERMSIG(status), SIGBUS);
	}
}

static void guest_ve_handler(struct ex_regs *regs)
{
	struct ve_info ve;
	uint64_t ret;

	ret = tdg_vp_veinfo_get(&ve);
	GUEST_ASSERT(!ret);

	/* For this test, we will only handle EXIT_REASON_EPT_VIOLATION */
	GUEST_ASSERT_EQ(ve.exit_reason, EXIT_REASON_EPT_VIOLATION);

	GUEST_PRINTF("\t ... guest accepting 1 page at GPA: 0x%lx\n", ve.gpa);

#define MEM_PAGE_ACCEPT_LEVEL_4K 0
#define MEM_PAGE_ACCEPT_LEVEL_2M 1
	ret = tdg_mem_page_accept(ve.gpa & PAGE_MASK, MEM_PAGE_ACCEPT_LEVEL_4K);
	GUEST_ASSERT(!ret);
}

static void *add_memslot(struct kvm_vm *vm, size_t memslot_size,
			int guest_memfd, uint64_t guest_memfd_flags)
{
	struct userspace_mem_region *region;
	void *mem;
	int fd;

	region = vm_mem_region_alloc(vm);

	fd = vm_mem_region_install_guest_memfd(region, guest_memfd,
					       guest_memfd_flags);

	mem = vm_mem_region_mmap(region, memslot_size, MAP_SHARED, fd, 0);
	vm_mem_region_install_memory(region, memslot_size, PAGE_SIZE);

	region->region.slot = TEST_MEMSLOT;
	region->region.flags = KVM_MEM_GUEST_MEMFD;
	region->region.guest_phys_addr = TEST_GPA;
	region->region.guest_memfd_offset = 0;

	vm_mem_region_add(vm, region);
	vm->memslots[MEM_REGION_TEST_DATA] = TEST_MEMSLOT;

	return mem;
}

static struct kvm_vm *
setup_test(size_t test_page_size, size_t test_memory_size, bool init_private,
	   struct kvm_vcpu **vcpu, int *guest_memfd, char **mem)
{
	vm_paddr_t gpa_private;
	size_t test_nr_pages;
	struct kvm_vm *vm;
	uint64_t flags;

	vm = td_create();

	test_nr_pages = test_memory_size >> vm->page_shift;
	td_initialize_with_extra_mem_pages(vm, VM_MEM_SRC_ANONYMOUS, 0,
					   test_nr_pages);
	*vcpu = td_vcpu_add(vm, 0, guest_code);

	vm_install_exception_handler(vm, VE_VECTOR, guest_ve_handler);

	flags = GUEST_MEMFD_FLAG_SUPPORT_SHARED;

	if (init_private)
		flags |= GUEST_MEMFD_FLAG_INIT_PRIVATE;

	if (test_page_size == SZ_2M)
		flags |= GUEST_MEMFD_FLAG_HUGETLB | GUESTMEM_HUGETLB_FLAG_2MB;
	else if (test_page_size == SZ_1G)
		flags |= GUEST_MEMFD_FLAG_HUGETLB | GUESTMEM_HUGETLB_FLAG_1GB;

	*guest_memfd = vm_create_guest_memfd(vm, test_memory_size, flags);
	TEST_ASSERT(*guest_memfd > 0, "guest_memfd creation failed");

	*mem = add_memslot(vm, test_memory_size, *guest_memfd, flags);

	gpa_private = __vm_phy_pages_alloc(vm, test_nr_pages, TEST_GPA,
					   vm->memslots[MEM_REGION_TEST_DATA],
					   init_private);
	TEST_ASSERT_EQ(gpa_private, TEST_GPA);

	/*
	 * By mapping the same GPA as shared and private, the TD does not have
	 * to remap its page tables at runtime to perform private and shared
	 * accesses.
	 */
	virt_map_private(vm, TEST_GVA_PRIVATE, gpa_private, test_nr_pages);
	virt_map_shared(vm, TEST_GVA_SHARED, gpa_private, test_nr_pages);

	td_finalize(vm);

	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL, BIT_ULL(KVM_HC_MAP_GPA_RANGE));

	/* Run it to set guest up to receive commands. */
	vcpu_run_handle_basic_ucalls(*vcpu);
	return vm;
}

static void cleanup_test(size_t guest_memfd_size, struct kvm_vm *vm,
			 int guest_memfd, char *mem)
{
	kvm_vm_free(vm);
	TEST_ASSERT_EQ(munmap(mem, guest_memfd_size), 0);

	if (guest_memfd > -1)
		TEST_ASSERT_EQ(close(guest_memfd), 0);
}

static void test_init_private(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;

	vm = setup_test(test_page_size, test_page_size, /*init_private=*/true,
			&vcpu, &guest_memfd, &mem);

	assert_host_cannot_fault(mem);
	guest_use_memory(vcpu, TEST_GVA_PRIVATE, 0, 'A', 0);
	guest_use_memory(vcpu, TEST_GVA_PRIVATE, 'A', 'B', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void test_init_shared(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;

	vm = setup_test(test_page_size, test_page_size, /*init_private=*/false,
			&vcpu, &guest_memfd, &mem);

	host_use_memory(mem, 0, 'A');
	guest_use_memory(vcpu, TEST_GVA_SHARED, 'A', 'B', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void test_explicit_conversion_to_private(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;

	vm = setup_test(test_page_size, test_page_size, /*init_private=*/false,
			&vcpu, &guest_memfd, &mem);

	host_use_memory(mem, 0, 'A');
	guest_use_memory(vcpu, TEST_GVA_SHARED, 'A', 'B', 0);

	guest_map_gpa_private(vm, vcpu, TEST_GPA, PAGE_SIZE, 0, 0);

	assert_host_cannot_fault(mem);
	guest_use_memory(vcpu, TEST_GVA_PRIVATE, 0, 'C', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void __test_implicit_conversion_to_private(size_t test_page_size, bool write)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char expected;
	char *mem;

	vm = setup_test(test_page_size, test_page_size, /*init_private=*/false,
			&vcpu, &guest_memfd, &mem);

	host_use_memory(mem, 0, 'A');
	guest_use_memory(vcpu, TEST_GVA_SHARED, 'A', 'B', 0);

	if (write) {
		guest_use_memory(vcpu, TEST_GVA_PRIVATE, 'X', 'C', EFAULT);
	} else {
		/* This also tests for zeroing after conversion. */
		guest_use_memory(vcpu, TEST_GVA_PRIVATE, 0, 'X', EFAULT);
	}

	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_MEMORY_FAULT);
	TEST_ASSERT_EQ(vcpu->run->memory_fault.gpa, TEST_GPA);
	TEST_ASSERT_EQ(vcpu->run->memory_fault.size, vm->page_size);
	TEST_ASSERT_EQ(vcpu->run->memory_fault.flags, KVM_MEMORY_EXIT_FLAG_PRIVATE);
	handle_memory_conversion(vm, vcpu->id, vcpu->run->memory_fault.gpa,
				 vcpu->run->memory_fault.size,
				 /*shared_to_private=*/true);
	vcpu_run_handle_basic_ucalls(vcpu);

	expected = write ? 'C' : 0;
	guest_use_memory(vcpu, TEST_GVA_PRIVATE, expected, 'C', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void test_implicit_conversion_to_private_with_write(size_t test_page_size)
{
	__test_implicit_conversion_to_private(test_page_size, true);
}

static void test_implicit_conversion_to_private_with_read(size_t test_page_size)
{
	__test_implicit_conversion_to_private(test_page_size, false);
}

static void test_explicit_conversion_to_shared(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;

	vm = setup_test(test_page_size, test_page_size, /*init_private=*/true,
			&vcpu, &guest_memfd, &mem);

	assert_host_cannot_fault(mem);
	guest_use_memory(vcpu, TEST_GVA_PRIVATE, 0, 'A', 0);

	guest_map_gpa_shared(vm, vcpu, TEST_GPA, PAGE_SIZE, 0, 0);

	host_use_memory(mem, 0, 'A');
	guest_use_memory(vcpu, TEST_GVA_SHARED, 'A', 'B', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void __test_implicit_conversion_to_shared(size_t test_page_size, bool write)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char expected;
	char *mem;

	vm = setup_test(test_page_size, test_page_size, /*init_private=*/true,
			&vcpu, &guest_memfd, &mem);

	assert_host_cannot_fault(mem);
	guest_use_memory(vcpu, TEST_GVA_PRIVATE, 0, 'A', 0);

	if (write) {
		guest_use_memory(vcpu, TEST_GVA_SHARED, 'X', 'B', EFAULT);
	} else {
		/* This also tests for zeroing after conversion. */
		guest_use_memory(vcpu, TEST_GVA_SHARED, 0, 'X', EFAULT);
	}

	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_MEMORY_FAULT);
	TEST_ASSERT_EQ(vcpu->run->memory_fault.gpa, TEST_GPA);
	TEST_ASSERT_EQ(vcpu->run->memory_fault.size, vm->page_size);
	TEST_ASSERT_EQ(vcpu->run->memory_fault.flags, 0);
	handle_memory_conversion(vm, vcpu->id, vcpu->run->memory_fault.gpa,
				 vcpu->run->memory_fault.size,
				 /*shared_to_private=*/false);
	vcpu_run_handle_basic_ucalls(vcpu);

	expected = write ? 'B' : 0;
	guest_use_memory(vcpu, TEST_GVA_SHARED, expected, 'C', 0);

	host_use_memory(mem, 'C', 'D');
	guest_use_memory(vcpu, TEST_GVA_SHARED, 'D', 'E', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void test_implicit_conversion_to_shared_with_write(size_t test_page_size)
{
	__test_implicit_conversion_to_shared(test_page_size, true);
}

static void test_implicit_conversion_to_shared_with_read(size_t test_page_size)
{
	__test_implicit_conversion_to_shared(test_page_size, false);
}

static void test_with_size(size_t test_page_size)
{
	test_init_private(test_page_size);
	test_init_shared(test_page_size);

	test_explicit_conversion_to_private(test_page_size);
	test_implicit_conversion_to_private_with_write(test_page_size);
	test_implicit_conversion_to_private_with_read(test_page_size);

	test_explicit_conversion_to_shared(test_page_size);
	test_implicit_conversion_to_shared_with_write(test_page_size);
	test_implicit_conversion_to_shared_with_read(test_page_size);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_GMEM_SHARED_MEM));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_GMEM_CONVERSION));

	printf("Test guest_memfd with 4K pages\n");
	test_with_size(PAGE_SIZE);
	printf("\tPASSED\n");

	printf("Test guest_memfd with 2M pages\n");
	test_with_size(SZ_2M);
	printf("\tPASSED\n");

	printf("Test guest_memfd with 1G pages\n");
	test_with_size(SZ_1G);
	printf("\tPASSED\n");
}
