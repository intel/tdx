// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test conversion flows for guest_memfd.
 *
 * Copyright (c) 2024, Google LLC.
 */
#include <linux/guestmem.h>
#include <linux/kvm.h>
#include <linux/sizes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include "ucall_common.h"
#include "../../../../mm/gup_test.h"

#define GUEST_MEMFD_SHARING_TEST_SLOT 10
/*
 * Use high GPA above APIC_DEFAULT_PHYS_BASE to avoid clashing with
 * APIC_DEFAULT_PHYS_BASE.
 */
#define GUEST_MEMFD_SHARING_TEST_GPA 0x100000000ULL
#define GUEST_MEMFD_SHARING_TEST_GVA 0x90000000ULL

static int gup_test_fd;

static void pin_pages(void *vaddr, uint64_t size)
{
	const struct pin_longterm_test args = {
		.addr = (uint64_t)vaddr,
		.size = size,
		.flags = PIN_LONGTERM_TEST_FLAG_USE_WRITE,
	};

	gup_test_fd = open("/sys/kernel/debug/gup_test", O_RDWR);
	TEST_REQUIRE(gup_test_fd > 0);

	TEST_ASSERT_EQ(ioctl(gup_test_fd, PIN_LONGTERM_TEST_START, &args), 0);
}

static void unpin_pages(void)
{
	TEST_ASSERT_EQ(ioctl(gup_test_fd, PIN_LONGTERM_TEST_STOP), 0);
}

static void guest_check_mem(uint64_t gva, char expected_read_value, char write_value)
{
	char *mem = (char *)gva;

	if (expected_read_value != 'X')
		GUEST_ASSERT_EQ(*mem, expected_read_value);

	if (write_value != 'X')
		*mem = write_value;

	GUEST_DONE();
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
 *                  otherwise set it to the expected errno. If @expected_errno
 *                  is set, 'Z' is used instead of @expected_read_value or
 *                  @write_value.
 */
static void guest_use_memory(struct kvm_vcpu *vcpu, uint64_t gva,
			     char expected_read_value, char write_value,
			     int expected_errno)
{
	struct kvm_regs original_regs;
	int rc;

	if (expected_errno > 0) {
		expected_read_value = 'Z';
		write_value = 'Z';
	}

	/*
	 * Backup and vCPU state from first run so that guest_check_mem can be
	 * run again and again.
	 */
	vcpu_regs_get(vcpu, &original_regs);

	vcpu_args_set(vcpu, 3, gva, expected_read_value, write_value);
	vcpu_arch_set_entry_point(vcpu, guest_check_mem);

	rc = vcpu_run_handle_basic_ucalls(vcpu);

	if (expected_errno) {
		TEST_ASSERT_EQ(rc, -1);
		TEST_ASSERT_EQ(errno, expected_errno);

		switch (expected_errno) {
		case EFAULT:
			TEST_ASSERT_EQ(vcpu->run->exit_reason, 0);
			break;
		case EACCES:
			TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_MEMORY_FAULT);
			break;
		}
	} else {
		struct ucall uc;

		TEST_ASSERT_EQ(rc, 0);
		TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);

		/*
		 * UCALL_DONE() uses up one struct ucall slot. To reuse the slot
		 * in another run of guest_check_mem, free up that slot.
		 */
		ucall_free((struct ucall *)uc.hva);
	}

	vcpu_regs_set(vcpu, &original_regs);
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

static void *add_memslot(struct kvm_vm *vm, size_t memslot_size, int guest_memfd)
{
	struct userspace_mem_region *region;
	void *mem;

	TEST_REQUIRE(guest_memfd > 0);

	region = vm_mem_region_alloc(vm);

	guest_memfd = vm_mem_region_install_guest_memfd(region, guest_memfd);
	mem = vm_mem_region_mmap(region, memslot_size, MAP_SHARED, guest_memfd, 0);
	vm_mem_region_install_memory(region, memslot_size, PAGE_SIZE);

	region->region.slot = GUEST_MEMFD_SHARING_TEST_SLOT;
	region->region.flags = KVM_MEM_GUEST_MEMFD;
	region->region.guest_phys_addr = GUEST_MEMFD_SHARING_TEST_GPA;
	region->region.guest_memfd_offset = 0;

	vm_mem_region_add(vm, region);

	return mem;
}

static struct kvm_vm *setup_test(size_t test_page_size, bool init_private,
				 struct kvm_vcpu **vcpu, int *guest_memfd,
				 char **mem)
{
	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = KVM_X86_SW_PROTECTED_VM,
	};
	size_t test_nr_pages;
	struct kvm_vm *vm;
	uint64_t flags;

	test_nr_pages = test_page_size / PAGE_SIZE;
	vm = __vm_create_shape_with_one_vcpu(shape, vcpu, test_nr_pages, NULL);

	flags = GUEST_MEMFD_FLAG_SUPPORT_SHARED;
	if (init_private)
		flags |= GUEST_MEMFD_FLAG_INIT_PRIVATE;

	if (test_page_size == SZ_2M)
		flags |= GUEST_MEMFD_FLAG_HUGETLB | GUESTMEM_HUGETLB_FLAG_2MB;
	else if (test_page_size == SZ_1G)
		flags |= GUEST_MEMFD_FLAG_HUGETLB | GUESTMEM_HUGETLB_FLAG_1GB;

	*guest_memfd = vm_create_guest_memfd(vm, test_page_size, flags);
	TEST_ASSERT(*guest_memfd > 0, "guest_memfd creation failed");

	*mem = add_memslot(vm, test_page_size, *guest_memfd);

	virt_map(vm, GUEST_MEMFD_SHARING_TEST_GVA, GUEST_MEMFD_SHARING_TEST_GPA,
		 test_nr_pages);

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

static void test_sharing(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;

	vm = setup_test(test_page_size, /*init_private=*/false, &vcpu, &guest_memfd, &mem);

	host_use_memory(mem, 'X', 'A');
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'A', 'B', 0);

	/* Toggle private flag of memory attributes and run the test again. */
	guest_memfd_convert_private(guest_memfd, 0, test_page_size);

	assert_host_cannot_fault(mem);
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'B', 'C', 0);

	guest_memfd_convert_shared(guest_memfd, 0, test_page_size);

	host_use_memory(mem, 'C', 'D');
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'D', 'E', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void test_init_mappable_false(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;

	vm = setup_test(test_page_size, /*init_private=*/true, &vcpu, &guest_memfd, &mem);

	assert_host_cannot_fault(mem);
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'X', 'A', 0);

	guest_memfd_convert_shared(guest_memfd, 0, test_page_size);

	host_use_memory(mem, 'A', 'B');
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'B', 'C', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

/*
 * Test that even if there are no folios yet, conversion requests are recorded
 * in guest_memfd.
 */
static void test_conversion_before_allocation(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;

	vm = setup_test(test_page_size, /*init_private=*/false, &vcpu, &guest_memfd, &mem);

	guest_memfd_convert_private(guest_memfd, 0, test_page_size);

	assert_host_cannot_fault(mem);
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'X', 'A', 0);

	guest_memfd_convert_shared(guest_memfd, 0, test_page_size);

	host_use_memory(mem, 'A', 'B');
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'B', 'C', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void __test_conversion_if_not_all_folios_allocated(size_t test_page_size,
							  int total_nr_pages,
							  int page_to_fault)
{
	const int second_page_to_fault = 8;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	size_t total_size;
	int guest_memfd;
	char *mem;
	int i;

	total_size = test_page_size * total_nr_pages;
	vm = setup_test(total_size, /*init_private=*/false, &vcpu, &guest_memfd, &mem);

	/*
	 * Fault 2 of the pages to test filemap range operations except when
	 * page_to_fault == second_page_to_fault.
	 */
	host_use_memory(mem + page_to_fault * test_page_size, 'X', 'A');
	host_use_memory(mem + second_page_to_fault * test_page_size, 'X', 'A');

	guest_memfd_convert_private(guest_memfd, 0, total_size);

	for (i = 0; i < total_nr_pages; ++i) {
		bool is_faulted;
		char expected;

		assert_host_cannot_fault(mem + i * test_page_size);

		is_faulted = i == page_to_fault || i == second_page_to_fault;
		expected = is_faulted ? 'A' : 'X';
		guest_use_memory(vcpu,
				 GUEST_MEMFD_SHARING_TEST_GVA + i * test_page_size,
				 expected, 'B', 0);
	}

	guest_memfd_convert_shared(guest_memfd, 0, total_size);

	for (i = 0; i < total_nr_pages; ++i) {
		host_use_memory(mem + i * test_page_size, 'B', 'C');
		guest_use_memory(vcpu,
				 GUEST_MEMFD_SHARING_TEST_GVA + i * test_page_size,
				 'C', 'D', 0);
	}

	cleanup_test(total_size, vm, guest_memfd, mem);
}

static void test_conversion_if_not_all_folios_allocated(size_t test_page_size)
{
	const int total_nr_pages = 16;
	int i;

	for (i = 0; i < total_nr_pages; ++i)
		__test_conversion_if_not_all_folios_allocated(test_page_size, total_nr_pages, i);
}

static void test_conversions_should_not_affect_surrounding_pages(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	int page_to_convert;
	struct kvm_vm *vm;
	size_t total_size;
	int guest_memfd;
	int nr_pages;
	char *mem;
	int i;

	page_to_convert = 2;
	nr_pages = 4;
	total_size = test_page_size * nr_pages;

	vm = setup_test(total_size, /*init_private=*/false, &vcpu, &guest_memfd, &mem);

	for (i = 0; i < nr_pages; ++i) {
		host_use_memory(mem + i * test_page_size, 'X', 'A');
		guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA + i * test_page_size,
				 'A', 'B', 0);
	}

	guest_memfd_convert_private(guest_memfd, test_page_size * page_to_convert, test_page_size);


	for (i = 0; i < nr_pages; ++i) {
		char to_check;

		if (i == page_to_convert) {
			assert_host_cannot_fault(mem + i * test_page_size);
			to_check = 'B';
		} else {
			host_use_memory(mem + i * test_page_size, 'B', 'C');
			to_check = 'C';
		}

		guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA + i * test_page_size,
				 to_check, 'D', 0);
	}

	guest_memfd_convert_shared(guest_memfd, test_page_size * page_to_convert, test_page_size);


	for (i = 0; i < nr_pages; ++i) {
		host_use_memory(mem + i * test_page_size, 'D', 'E');
		guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA + i * test_page_size,
				 'E', 'F', 0);
	}

	cleanup_test(total_size, vm, guest_memfd, mem);
}

static void __test_conversions_should_fail_if_memory_has_elevated_refcount(
	size_t test_page_size, int nr_pages, int page_to_convert)
{
	struct kvm_vcpu *vcpu;
	loff_t error_offset;
	struct kvm_vm *vm;
	size_t total_size;
	int guest_memfd;
	char *mem;
	int ret;
	int i;

	total_size = test_page_size * nr_pages;
	vm = setup_test(total_size, /*init_private=*/false, &vcpu, &guest_memfd, &mem);

	pin_pages(mem + page_to_convert * test_page_size, test_page_size);

	for (i = 0; i < nr_pages; i++) {
		host_use_memory(mem + i * test_page_size, 'X', 'A');
		guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA + i * test_page_size,
				 'A', 'B', 0);
	}

	error_offset = 0;
	ret = __guest_memfd_convert_private(guest_memfd, page_to_convert * test_page_size,
					    test_page_size, &error_offset);
	TEST_ASSERT_EQ(ret, -1);
	TEST_ASSERT_EQ(errno, EAGAIN);
	TEST_ASSERT_EQ(error_offset, page_to_convert * test_page_size);

	unpin_pages();

	guest_memfd_convert_private(guest_memfd, page_to_convert * test_page_size, test_page_size);

	for (i = 0; i < nr_pages; i++) {
		char expected;

		if (i == page_to_convert)
			assert_host_cannot_fault(mem + i * test_page_size);
		else
			host_use_memory(mem + i * test_page_size, 'B', 'C');

		expected = i == page_to_convert ? 'X' : 'C';
		guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA + i * test_page_size,
				 expected, 'D', 0);
	}

	guest_memfd_convert_shared(guest_memfd, page_to_convert * test_page_size, test_page_size);


	for (i = 0; i < nr_pages; i++) {
		char expected = i == page_to_convert ? 'X' : 'D';

		host_use_memory(mem + i * test_page_size, expected, 'E');
		guest_use_memory(vcpu,
				 GUEST_MEMFD_SHARING_TEST_GVA + i * test_page_size,
				 'E', 'F', 0);
	}

	cleanup_test(total_size, vm, guest_memfd, mem);
}
/*
 * This test depends on CONFIG_GUP_TEST to provide a kernel module that exposes
 * pin_user_pages() to userspace.
 */
static void test_conversions_should_fail_if_memory_has_elevated_refcount(
		size_t test_page_size)
{
	int i;

	for (i = 0; i < 4; i++) {
		__test_conversions_should_fail_if_memory_has_elevated_refcount(
			test_page_size, 4, i);
	}
}

static void test_truncate_should_not_change_mappability(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;
	int ret;

	vm = setup_test(test_page_size, /*init_private=*/false, &vcpu, &guest_memfd, &mem);

	host_use_memory(mem, 'X', 'A');

	ret = fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			0, test_page_size);
	TEST_ASSERT(!ret, "truncating the first page should succeed");

	host_use_memory(mem, 'X', 'A');

	guest_memfd_convert_private(guest_memfd, 0, test_page_size);

	assert_host_cannot_fault(mem);
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'A', 'A', 0);

	ret = fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			0, test_page_size);
	TEST_ASSERT(!ret, "truncating the first page should succeed");

	assert_host_cannot_fault(mem);
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'X', 'A', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void test_fault_type_independent_of_mem_attributes(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;

	vm = setup_test(test_page_size, /*init_private=*/true, &vcpu, &guest_memfd, &mem);
	vm_mem_set_shared(vm, GUEST_MEMFD_SHARING_TEST_GPA, test_page_size);

	/*
	 * kvm->mem_attr_array set to shared, guest_memfd memory initialized as
	 * private.
	 */

	/* Host cannot use private memory. */
	assert_host_cannot_fault(mem);

	/* Guest can fault and use memory. */
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'X', 'A', 0);

	guest_memfd_convert_shared(guest_memfd, 0, test_page_size);
	vm_mem_set_private(vm, GUEST_MEMFD_SHARING_TEST_GPA, test_page_size);

	/* Host can use shared memory. */
	host_use_memory(mem, 'X', 'A');

	/* Guest can also use shared memory. */
	guest_use_memory(vcpu, GUEST_MEMFD_SHARING_TEST_GVA, 'X', 'A', 0);

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void test_truncate_shared_while_pinned(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;
	int ret;

	vm = setup_test(test_page_size, /*init_private=*/false, &vcpu,
			&guest_memfd, &mem);

	ret = fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE, 0, test_page_size);
	TEST_ASSERT(!ret, "fallocate should have succeeded");

	pin_pages(mem, test_page_size);

	ret = fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			0, test_page_size);
	if (test_page_size == PAGE_SIZE) {
		TEST_ASSERT(!ret, "truncate should have succeeded since there is no need to merge");
	} else {
		TEST_ASSERT(ret, "truncate should have failed since pages are pinned");
		TEST_ASSERT_EQ(errno, EAGAIN);
	}

	unpin_pages();

	ret = fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			0, test_page_size);
	TEST_ASSERT(!ret, "truncate should succeed now that pages are unpinned");

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void test_truncate_private(size_t test_page_size)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;
	int ret;

	vm = setup_test(test_page_size, /*init_private=*/true, &vcpu,
			&guest_memfd, &mem);

	ret = fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE, 0, test_page_size);
	TEST_ASSERT(!ret, "fallocate should have succeeded");

	ret = fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			0, test_page_size);
	TEST_ASSERT(!ret, "truncate should have succeeded since there is no need to merge");

	cleanup_test(test_page_size, vm, guest_memfd, mem);
}

static void __test_close_with_pinning(size_t test_page_size, bool init_private)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int guest_memfd;
	char *mem;
	int ret;

	vm = setup_test(test_page_size, init_private, &vcpu, &guest_memfd, &mem);

	ret = fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE, 0, test_page_size);
	TEST_ASSERT(!ret, "fallocate should have succeeded");

	if (!init_private)
		pin_pages(mem, test_page_size);

	cleanup_test(test_page_size, vm, guest_memfd, mem);

	if (!init_private)
		unpin_pages();

	/*
	 * Test this with ./guest_memfd_wrap_test_check_hugetlb_reporting.sh to
	 * check that the HugeTLB page got merged and returned to HugeTLB.
	 *
	 * Sleep here to give kernel worker time to do the merge and return.
	 */
	sleep(1);
}

static void test_close_with_pinning(size_t test_page_size)
{
	__test_close_with_pinning(test_page_size, true);
	__test_close_with_pinning(test_page_size, false);
}

static void test_with_size(size_t test_page_size)
{
	test_sharing(test_page_size);
	test_init_mappable_false(test_page_size);
	test_conversion_before_allocation(test_page_size);
	test_conversion_if_not_all_folios_allocated(test_page_size);
	test_conversions_should_not_affect_surrounding_pages(test_page_size);
	test_truncate_should_not_change_mappability(test_page_size);
	test_conversions_should_fail_if_memory_has_elevated_refcount(test_page_size);
	test_fault_type_independent_of_mem_attributes(test_page_size);
	test_truncate_shared_while_pinned(test_page_size);
	test_truncate_private(test_page_size);
	test_close_with_pinning(test_page_size);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SW_PROTECTED_VM));
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

	return 0;
}
