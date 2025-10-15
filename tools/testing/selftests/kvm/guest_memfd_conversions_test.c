// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, Google LLC.
 */
#include <sys/mman.h>
#include <unistd.h>

#include <linux/align.h>
#include <linux/kvm.h>
#include <linux/sizes.h>

#include "kvm_util.h"
#include "kselftest_harness.h"
#include "test_util.h"
#include "ucall_common.h"

FIXTURE(gmem_conversions) {
	struct kvm_vcpu *vcpu;
	int gmem_fd;
	/* HVA of the first byte of the memory mmap()-ed from gmem_fd. */
	char *mem;
};

typedef FIXTURE_DATA(gmem_conversions) test_data_t;

FIXTURE_SETUP(gmem_conversions) { }

static uint64_t page_size;

static void guest_do_rmw(void);
#define GUEST_MEMFD_SHARING_TEST_GVA 0x90000000ULL

/*
 * Defer setup until the individual test is invoked so that tests can specify
 * the number of pages and flags for the guest_memfd instance.
 */
static void gmem_conversions_do_setup(test_data_t *t, int nr_pages,
				      int gmem_flags)
{
	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = KVM_X86_SW_PROTECTED_VM,
	};
	/*
	 * Use high GPA above APIC_DEFAULT_PHYS_BASE to avoid clashing with
	 * APIC_DEFAULT_PHYS_BASE.
	 */
	const uint64_t gpa = SZ_4G;
	const uint32_t slot = 1;
	struct kvm_vm *vm;

	vm = __vm_create_shape_with_one_vcpu(shape, &t->vcpu, nr_pages, guest_do_rmw);

	vm_mem_add(vm, VM_MEM_SRC_SHMEM, gpa, slot, nr_pages,
		   KVM_MEM_GUEST_MEMFD, -1, 0, gmem_flags);

	t->gmem_fd = kvm_slot_to_fd(vm, slot);
	t->mem = addr_gpa2hva(vm, gpa);
	virt_map(vm, GUEST_MEMFD_SHARING_TEST_GVA, gpa, nr_pages);
}

static void gmem_conversions_do_teardown(test_data_t *t)
{
	/* No need to close gmem_fd, it's owned by the VM structure. */
	kvm_vm_free(t->vcpu->vm);

	/* NULL this out to avoid second free on full teardown in multipage tests. */
	t->vcpu->vm = NULL;
}

FIXTURE_TEARDOWN(gmem_conversions)
{
	gmem_conversions_do_teardown(self);
}

/*
 * In these test definition macros, __nr_pages and nr_pages is used to set up
 * the total number of pages in the guest_memfd under test. This will be
 * available in the test definitions as nr_pages.
 */

#define __GMEM_CONVERSION_TEST(test, __nr_pages, flags)				\
static void __gmem_conversions_##test(test_data_t *t, int nr_pages);		\
										\
TEST_F(gmem_conversions, test)							\
{										\
	gmem_conversions_do_setup(self, __nr_pages, flags);			\
	__gmem_conversions_##test(self, __nr_pages);				\
}										\
static void __gmem_conversions_##test(test_data_t *t, int nr_pages)		\

#define GMEM_CONVERSION_TEST(test, __nr_pages, flags)				\
	__GMEM_CONVERSION_TEST(test, __nr_pages, (flags) | GUEST_MEMFD_FLAG_MMAP)

#define __GMEM_CONVERSION_TEST_INIT_PRIVATE(test, __nr_pages)			\
	GMEM_CONVERSION_TEST(test, __nr_pages, 0)

#define GMEM_CONVERSION_TEST_INIT_PRIVATE(test)					\
	__GMEM_CONVERSION_TEST_INIT_PRIVATE(test, 1)

#define __GMEM_CONVERSION_TEST_INIT_SHARED(test, __nr_pages)			\
	GMEM_CONVERSION_TEST(test, __nr_pages, GUEST_MEMFD_FLAG_INIT_SHARED)

#define GMEM_CONVERSION_TEST_INIT_SHARED(test)					\
	__GMEM_CONVERSION_TEST_INIT_SHARED(test, 1)

/*
 * Repeats test over nr_pages in a guest_memfd of size nr_pages, providing each
 * test iteration with test_page, the index of the page under test in
 * guest_memfd. test_page takes values 0..(nr_pages - 1) inclusive.
 */
#define GMEM_CONVERSION_MULTIPAGE_TEST_INIT_SHARED(test, __nr_pages)		\
static void __gmem_conversions_multipage_##test(test_data_t *t, int nr_pages,	\
						const int test_page);		\
										\
TEST_F(gmem_conversions, test)							\
{										\
	const uint64_t flags = GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED; \
	int i;									\
										\
	for (i = 0; i < __nr_pages; ++i) {					\
		gmem_conversions_do_setup(self, __nr_pages, flags);		\
		__gmem_conversions_multipage_##test(self, __nr_pages, i);	\
		gmem_conversions_do_teardown(self);				\
	}									\
}										\
static void __gmem_conversions_multipage_##test(test_data_t *t, int nr_pages,	\
						const int test_page)

struct guest_check_data {
	void *mem;
	char expected_val;
	char write_val;
};
static struct guest_check_data guest_data;

static void guest_do_rmw(void)
{
	for (;;) {
		char *mem = READ_ONCE(guest_data.mem);

		GUEST_ASSERT_EQ(READ_ONCE(*mem), READ_ONCE(guest_data.expected_val));
		WRITE_ONCE(*mem, READ_ONCE(guest_data.write_val));

		GUEST_SYNC(0);
	}
}

static void run_guest_do_rmw(struct kvm_vcpu *vcpu, loff_t pgoff,
			     char expected_val, char write_val)
{
	struct ucall uc;
	int r;

	guest_data.mem = (void *)GUEST_MEMFD_SHARING_TEST_GVA + pgoff * page_size;
	guest_data.expected_val = expected_val;
	guest_data.write_val = write_val;
	sync_global_to_guest(vcpu->vm, guest_data);

	for (;;) {
		r = __vcpu_run(vcpu);
		if (!r && get_ucall(vcpu, &uc) == UCALL_PRINTF) {
			REPORT_GUEST_PRINTF(uc);
			continue;
		}
		if (r == -1 && errno == EINTR)
			continue;
		break;
	}

	TEST_ASSERT_EQ(r, 0);

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	case UCALL_SYNC:
		break;
	case UCALL_PRINTF:
	default:
		TEST_FAIL("Unexpected ucall %lu", uc.cmd);
	}
}

static void host_do_rmw(char *mem, loff_t pgoff, char expected_val,
			char write_val)
{
	TEST_ASSERT_EQ(READ_ONCE(mem[pgoff * page_size]), expected_val);
	WRITE_ONCE(mem[pgoff * page_size], write_val);
}

static void test_private(test_data_t *t, loff_t pgoff, char starting_val,
			 char write_val)
{
	TEST_EXPECT_SIGBUS(WRITE_ONCE(t->mem[pgoff * page_size], write_val));
	run_guest_do_rmw(t->vcpu, pgoff, starting_val, write_val);
	TEST_EXPECT_SIGBUS(READ_ONCE(t->mem[pgoff * page_size]));
}

static void test_convert_to_private(test_data_t *t, loff_t pgoff,
				    char starting_val, char write_val)
{
	gmem_set_private(t->gmem_fd, pgoff * page_size, page_size);
	test_private(t, pgoff, starting_val, write_val);
}

static void test_shared(test_data_t *t, loff_t pgoff, char starting_val,
			char host_write_val, char write_val)
{
	host_do_rmw(t->mem, pgoff, starting_val, host_write_val);
	run_guest_do_rmw(t->vcpu, pgoff, host_write_val, write_val);
	TEST_ASSERT_EQ(READ_ONCE(t->mem[pgoff * page_size]), write_val);
}

static void test_convert_to_shared(test_data_t *t, loff_t pgoff,
				   char starting_val, char host_write_val,
				   char write_val)
{
	gmem_set_shared(t->gmem_fd, pgoff * page_size, page_size);
	test_shared(t, pgoff, starting_val, host_write_val, write_val);
}

GMEM_CONVERSION_TEST_INIT_PRIVATE(init_private)
{
	test_private(t, 0, 0, 'A');
	test_convert_to_shared(t, 0, 'A', 'B', 'C');
	test_convert_to_private(t, 0, 'C', 'E');
}

GMEM_CONVERSION_TEST_INIT_SHARED(init_shared)
{
	test_shared(t, 0, 0, 'A', 'B');
	test_convert_to_private(t, 0, 'B', 'C');
	test_convert_to_shared(t, 0, 'C', 'D', 'E');
}

/*
 * Test indexing of pages within guest_memfd, using test data that is a multiple
 * of page index.
 */
GMEM_CONVERSION_MULTIPAGE_TEST_INIT_SHARED(indexing, 4)
{
	int i;

	/*
	 * Start with the highest index, to catch any errors when, perhaps, the
	 * first page is returned even for the last index.
	 */
	for (i = nr_pages - 1; i >= 0; --i)
		test_shared(t, i, 0, i, i * 2);

	for (i = 0; i < nr_pages; ++i) {
		if (i == test_page)
			test_convert_to_private(t, i, i * 2, i * 4);
		else
			test_shared(t, i, i * 2, i * 3, i * 4);
	}

	for (i = 0; i < nr_pages; ++i) {
		if (i == test_page)
			test_convert_to_shared(t, i, i * 4, i * 5, i * 6);
		else
			test_shared(t, i, i * 4, i * 5, i * 6);
	}
}

/*
 * Test that even if there are no folios yet, conversion requests are recorded
 * in guest_memfd.
 */
GMEM_CONVERSION_TEST_INIT_SHARED(before_allocation_shared)
{
	test_convert_to_private(t, 0, 0, 'A');
}

GMEM_CONVERSION_TEST_INIT_PRIVATE(before_allocation_private)
{
	test_convert_to_shared(t, 0, 0, 'A', 'B');
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SW_PROTECTED_VM));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES) &
		     KVM_MEMORY_ATTRIBUTE_PRIVATE);

	page_size = getpagesize();

	return test_harness_run(argc, argv);
}
