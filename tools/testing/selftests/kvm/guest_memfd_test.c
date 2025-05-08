// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright Intel Corporation, 2023
 *
 * Author: Chao Peng <chao.p.peng@linux.intel.com>
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include <linux/bitmap.h>
#include <linux/falloc.h>
#include <linux/guestmem.h>
#include <linux/sizes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "kvm_util.h"
#include "test_util.h"

static void test_file_read_write(int fd)
{
	char buf[64];

	TEST_ASSERT(read(fd, buf, sizeof(buf)) < 0,
		    "read on a guest_mem fd should fail");
	TEST_ASSERT(write(fd, buf, sizeof(buf)) < 0,
		    "write on a guest_mem fd should fail");
	TEST_ASSERT(pread(fd, buf, sizeof(buf), 0) < 0,
		    "pread on a guest_mem fd should fail");
	TEST_ASSERT(pwrite(fd, buf, sizeof(buf), 0) < 0,
		    "pwrite on a guest_mem fd should fail");
}

static void test_faulting_allowed(int fd, size_t page_size, size_t total_size)
{
	const char val = 0xaa;
	size_t increment;
	char *mem;
	size_t i;
	int ret;

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "mmaping() guest memory should pass.");

	increment = page_size >> 1;

	for (i = 0; i < total_size; i += increment)
		mem[i] = val;
	for (i = 0; i < total_size; i += increment)
		TEST_ASSERT_EQ(mem[i], val);

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 0,
			page_size);
	TEST_ASSERT(!ret, "fallocate the first page should succeed");

	for (i = 0; i < page_size; i += increment)
		TEST_ASSERT_EQ(mem[i], 0x00);
	for (; i < total_size; i += increment)
		TEST_ASSERT_EQ(mem[i], val);

	for (i = 0; i < total_size; i += increment)
		mem[i] = val;
	for (i = 0; i < total_size; i += increment)
		TEST_ASSERT_EQ(mem[i], val);

	ret = munmap(mem, total_size);
	TEST_ASSERT(!ret, "munmap should succeed");
}

static void assert_not_faultable(char *address)
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

static void test_faulting_sigbus(int fd, size_t total_size)
{
	char *mem;
	int ret;

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "mmaping() guest memory should pass.");

	assert_not_faultable(mem);

	ret = munmap(mem, total_size);
	TEST_ASSERT(!ret, "munmap should succeed");
}

static void test_mmap_allowed(int fd, size_t total_size)
{
	char *mem;
	int ret;

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "mmaping() guest memory should pass.");

	ret = munmap(mem, total_size);
	TEST_ASSERT(!ret, "munmap should succeed");
}

static void test_mmap_denied(int fd, size_t page_size, size_t total_size)
{
	char *mem;

	mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT_EQ(mem, MAP_FAILED);

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT_EQ(mem, MAP_FAILED);
}

static void test_file_size(int fd, size_t page_size, size_t total_size)
{
	struct stat sb;
	int ret;

	ret = fstat(fd, &sb);
	TEST_ASSERT(!ret, "fstat should succeed");
	TEST_ASSERT_EQ(sb.st_size, total_size);
	TEST_ASSERT_EQ(sb.st_blksize, page_size);
}

static void test_fallocate(int fd, size_t page_size, size_t total_size)
{
	int ret;

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, total_size);
	TEST_ASSERT(!ret, "fallocate with aligned offset and size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			page_size - 1, page_size);
	TEST_ASSERT(ret, "fallocate with unaligned offset should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, total_size, page_size);
	TEST_ASSERT(ret, "fallocate beginning at total_size should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, total_size + page_size, page_size);
	TEST_ASSERT(ret, "fallocate beginning after total_size should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			total_size, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) at total_size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			total_size + page_size, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) after total_size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			page_size, page_size - 1);
	TEST_ASSERT(ret, "fallocate with unaligned size should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			page_size, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) with aligned offset and size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, page_size, page_size);
	TEST_ASSERT(!ret, "fallocate to restore punched hole should succeed");
}

static void test_invalid_punch_hole(int fd, size_t page_size, size_t total_size)
{
	struct {
		off_t offset;
		off_t len;
	} testcases[] = {
		{0, 1},
		{0, page_size - 1},
		{0, page_size + 1},

		{1, 1},
		{1, page_size - 1},
		{1, page_size},
		{1, page_size + 1},

		{page_size, 1},
		{page_size, page_size - 1},
		{page_size, page_size + 1},
	};
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(testcases); i++) {
		ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
				testcases[i].offset, testcases[i].len);
		TEST_ASSERT(ret == -1 && errno == EINVAL,
			    "PUNCH_HOLE with !PAGE_SIZE offset (%lx) and/or length (%lx) should fail",
			    testcases[i].offset, testcases[i].len);
	}
}

static void test_create_guest_memfd_invalid_sizes(struct kvm_vm *vm,
						  uint64_t guest_memfd_flags,
						  size_t page_size)
{
	size_t size;
	int fd;

	for (size = 1; size < page_size; size += (page_size >> 1)) {
		fd = __vm_create_guest_memfd(vm, size, guest_memfd_flags);
		TEST_ASSERT(fd == -1 && errno == EINVAL,
			    "guest_memfd() with non-page-aligned page size '0x%lx' should fail with EINVAL",
			    size);
	}
}

static void test_create_guest_memfd_multiple(struct kvm_vm *vm,
					     uint64_t guest_memfd_flags,
					     size_t page_size)
{
	int fd1, fd2, ret;
	struct stat st1, st2;

	fd1 = __vm_create_guest_memfd(vm, page_size, guest_memfd_flags);
	TEST_ASSERT(fd1 != -1, "memfd creation should succeed");

	ret = fstat(fd1, &st1);
	TEST_ASSERT(ret != -1, "memfd fstat should succeed");
	TEST_ASSERT(st1.st_size == page_size, "memfd st_size should match requested size");

	fd2 = __vm_create_guest_memfd(vm, page_size * 2, guest_memfd_flags);
	TEST_ASSERT(fd2 != -1, "memfd creation should succeed");

	ret = fstat(fd2, &st2);
	TEST_ASSERT(ret != -1, "memfd fstat should succeed");
	TEST_ASSERT(st2.st_size == page_size * 2,
		    "second memfd st_size should match requested size");


	ret = fstat(fd1, &st1);
	TEST_ASSERT(ret != -1, "memfd fstat should succeed");
	TEST_ASSERT(st1.st_size == page_size,
		    "first memfd st_size should still match requested size");
	TEST_ASSERT(st1.st_ino != st2.st_ino, "different memfd should have different inode numbers");

	close(fd2);
	close(fd1);
}

#define GUEST_MEMFD_TEST_SLOT 10
#define GUEST_MEMFD_TEST_GPA 0x100000000

static void
test_bind_guest_memfd_disabling_range_match_validation(struct kvm_vm *vm,
						       int fd)
{
	size_t page_size = getpagesize();
	int ret;

	ret = __vm_set_user_memory_region2(vm, GUEST_MEMFD_TEST_SLOT,
					   KVM_MEM_GUEST_MEMFD,
					   GUEST_MEMFD_TEST_GPA, page_size, 0,
					   fd, 0);
	TEST_ASSERT(!ret,
		    "setting slot->userspace_addr to 0 should disable validation");
	ret = __vm_set_user_memory_region2(vm, GUEST_MEMFD_TEST_SLOT,
					   KVM_MEM_GUEST_MEMFD,
					   GUEST_MEMFD_TEST_GPA, 0, 0,
					   fd, 0);
	TEST_ASSERT(!ret, "Deleting memslot should work");
}

static void
test_bind_guest_memfd_anon_memory_in_userspace_addr(struct kvm_vm *vm, int fd)
{
	size_t page_size = getpagesize();
	void *userspace_addr;
	int ret;

	userspace_addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	ret = __vm_set_user_memory_region2(vm, GUEST_MEMFD_TEST_SLOT,
					   KVM_MEM_GUEST_MEMFD,
					   GUEST_MEMFD_TEST_GPA, page_size,
					   userspace_addr, fd, 0);
	TEST_ASSERT(ret == -1,
		    "slot->userspace_addr is not from the guest_memfd and should fail");
}

static void test_bind_guest_memfd_shared_memory_other_file_in_userspace_addr(
	struct kvm_vm *vm, int fd)
{
	size_t page_size = getpagesize();
	void *userspace_addr;
	int other_fd;
	int ret;

	other_fd = memfd_create("shared_memory_other_file", 0);
	TEST_ASSERT(other_fd > 0, "Creating other file should succeed");

	userspace_addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, other_fd, 0);

	ret = __vm_set_user_memory_region2(vm, GUEST_MEMFD_TEST_SLOT,
					   KVM_MEM_GUEST_MEMFD,
					   GUEST_MEMFD_TEST_GPA, page_size,
					   userspace_addr, fd, 0);
	TEST_ASSERT(ret == -1,
		    "slot->userspace_addr is not from the guest_memfd and should fail");

	TEST_ASSERT(!munmap(userspace_addr, page_size),
		    "munmap() to cleanup should succeed");

	close(other_fd);
}

static void
test_bind_guest_memfd_other_guest_memfd_in_userspace_addr(struct kvm_vm *vm,
							  int fd)
{
	size_t page_size = getpagesize();
	void *userspace_addr;
	int other_fd;
	int ret;

	other_fd = vm_create_guest_memfd(vm, page_size * 2,
					 GUEST_MEMFD_FLAG_SUPPORT_SHARED);
	TEST_ASSERT(other_fd > 0, "Creating other file should succeed");

	userspace_addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, other_fd, 0);

	ret = __vm_set_user_memory_region2(vm, GUEST_MEMFD_TEST_SLOT,
					   KVM_MEM_GUEST_MEMFD,
					   GUEST_MEMFD_TEST_GPA, page_size,
					   userspace_addr, fd, 0);
	TEST_ASSERT(ret == -1,
		    "slot->userspace_addr is not from the guest_memfd and should fail");

	TEST_ASSERT(!munmap(userspace_addr, page_size),
		    "munmap() to cleanup should succeed");

	close(other_fd);
}

static void
test_bind_guest_memfd_other_range_in_userspace_addr(struct kvm_vm *vm, int fd)
{
	size_t page_size = getpagesize();
	void *userspace_addr;
	int ret;

	userspace_addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, fd, page_size);

	ret = __vm_set_user_memory_region2(vm, GUEST_MEMFD_TEST_SLOT,
					   KVM_MEM_GUEST_MEMFD,
					   GUEST_MEMFD_TEST_GPA, page_size,
					   userspace_addr, fd, 0);
	TEST_ASSERT(ret == -1,
		    "slot->userspace_addr is not from the same range and should fail");

	TEST_ASSERT(!munmap(userspace_addr, page_size),
		    "munmap() to cleanup should succeed");
}

static void
test_bind_guest_memfd_same_range_in_userspace_addr(struct kvm_vm *vm, int fd)
{
	size_t page_size = getpagesize();
	void *userspace_addr;
	int ret;

	userspace_addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, fd, page_size);

	ret = __vm_set_user_memory_region2(vm, GUEST_MEMFD_TEST_SLOT,
					   KVM_MEM_GUEST_MEMFD,
					   GUEST_MEMFD_TEST_GPA, page_size,
					   userspace_addr, fd, page_size);
	TEST_ASSERT(!ret,
		    "slot->userspace_addr is the same range and should succeed");

	TEST_ASSERT(!munmap(userspace_addr, page_size),
		    "munmap() to cleanup should succeed");

	ret = __vm_set_user_memory_region2(vm, GUEST_MEMFD_TEST_SLOT,
					   KVM_MEM_GUEST_MEMFD,
					   GUEST_MEMFD_TEST_GPA, 0, 0,
					   fd, 0);
	TEST_ASSERT(!ret, "Deleting memslot should work");
}

static void test_bind_guest_memfd_wrt_userspace_addr(struct kvm_vm *vm)
{
	size_t page_size = getpagesize();
	int fd;

	if (!vm_check_cap(vm, KVM_CAP_GUEST_MEMFD) ||
	    !vm_check_cap(vm, KVM_CAP_GMEM_SHARED_MEM))
		return;

	fd = vm_create_guest_memfd(vm, page_size * 2,
				   GUEST_MEMFD_FLAG_SUPPORT_SHARED);

	test_bind_guest_memfd_disabling_range_match_validation(vm, fd);
	test_bind_guest_memfd_anon_memory_in_userspace_addr(vm, fd);
	test_bind_guest_memfd_shared_memory_other_file_in_userspace_addr(vm, fd);
	test_bind_guest_memfd_other_guest_memfd_in_userspace_addr(vm, fd);
	test_bind_guest_memfd_other_range_in_userspace_addr(vm, fd);
	test_bind_guest_memfd_same_range_in_userspace_addr(vm, fd);

	close(fd);
}

static void test_guest_memfd_features(struct kvm_vm *vm, size_t page_size,
				      uint64_t guest_memfd_flags,
				      bool expect_mmap_allowed,
				      bool expect_faulting_allowed)
{
	size_t total_size;
	int fd;

	total_size = page_size * 4;

	if (expect_faulting_allowed)
		TEST_REQUIRE(expect_mmap_allowed);

	test_create_guest_memfd_invalid_sizes(vm, guest_memfd_flags, page_size);

	fd = vm_create_guest_memfd(vm, total_size, guest_memfd_flags);

	test_file_read_write(fd);

	if (expect_mmap_allowed) {
		test_mmap_allowed(fd, total_size);

		if (expect_faulting_allowed)
			test_faulting_allowed(fd, page_size, total_size);
		else
			test_faulting_sigbus(fd, total_size);
	} else {
		test_mmap_denied(fd, page_size, total_size);
	}

	test_file_size(fd, page_size, total_size);
	test_fallocate(fd, page_size, total_size);
	test_invalid_punch_hole(fd, page_size, total_size);

	close(fd);
}

static void test_guest_memfd_features_for_page_size(struct kvm_vm *vm,
						    uint64_t guest_memfd_flags,
						    size_t page_size,
						    bool expect_mmap_allowed)
{
	test_create_guest_memfd_multiple(vm, guest_memfd_flags, page_size);

	if (guest_memfd_flags & GUEST_MEMFD_FLAG_SUPPORT_SHARED) {
		test_guest_memfd_features(vm, page_size, guest_memfd_flags,
					  expect_mmap_allowed, true);

		if (kvm_has_cap(KVM_CAP_GMEM_CONVERSION)) {
			uint64_t flags = guest_memfd_flags |
					 GUEST_MEMFD_FLAG_INIT_PRIVATE;

			test_guest_memfd_features(vm, page_size, flags,
						  expect_mmap_allowed, false);
		}
	} else {
		test_guest_memfd_features(vm, page_size, guest_memfd_flags,
					  expect_mmap_allowed, false);
	}
}

static void test_with_type(unsigned long vm_type, uint64_t base_flags,
			   bool expect_mmap_allowed)
{
	struct kvm_vm *vm;
	uint64_t flags;

	if (!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(vm_type)))
		return;

	vm = vm_create_barebones_type(vm_type);

	test_bind_guest_memfd_wrt_userspace_addr(vm);

	printf("Test guest_memfd with 4K pages for vm_type %ld\n", vm_type);
	test_guest_memfd_features_for_page_size(vm, base_flags, getpagesize(), expect_mmap_allowed);
	printf("\tPASSED\n");

	printf("Test guest_memfd with 2M pages for vm_type %ld\n", vm_type);
	flags = base_flags | GUEST_MEMFD_FLAG_HUGETLB | GUESTMEM_HUGETLB_FLAG_2MB;
	test_guest_memfd_features_for_page_size(vm, flags, SZ_2M, expect_mmap_allowed);
	printf("\tPASSED\n");

	printf("Test guest_memfd with 1G pages for vm_type %ld\n", vm_type);
	flags = base_flags | GUEST_MEMFD_FLAG_HUGETLB | GUESTMEM_HUGETLB_FLAG_1GB;
	test_guest_memfd_features_for_page_size(vm, flags, SZ_1G, expect_mmap_allowed);
	printf("\tPASSED\n");

	kvm_vm_release(vm);
}

static void test_vm_with_gmem_flag(struct kvm_vm *vm, uint64_t flag,
				   bool expect_valid)
{
	size_t page_size;
	int fd;

	if (flag == GUEST_MEMFD_FLAG_HUGETLB)
		page_size = get_def_hugetlb_pagesz();
	else
		page_size = getpagesize();

	fd = __vm_create_guest_memfd(vm, page_size, flag);

	if (expect_valid) {
		TEST_ASSERT(fd > 0,
			    "guest_memfd() with flag '0x%lx' should be valid",
			    flag);
		close(fd);
	} else {
		TEST_ASSERT(fd == -1 && errno == EINVAL,
			    "guest_memfd() with flag '0x%lx' should fail with EINVAL",
			    flag);
	}
}

static void test_vm_type_gmem_flag_validity(unsigned long vm_type,
					    uint64_t expected_valid_flags)
{
	struct kvm_vm *vm;
	uint64_t flag = 0;

	if (!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(vm_type)))
		return;

	vm = vm_create_barebones_type(vm_type);

	for (flag = BIT(0); flag; flag <<= 1) {
		test_vm_with_gmem_flag(vm, flag, flag & expected_valid_flags);

		if (flag == GUEST_MEMFD_FLAG_SUPPORT_SHARED &&
		    kvm_has_cap(KVM_CAP_GMEM_CONVERSION)) {
			test_vm_with_gmem_flag(
				vm, flag | GUEST_MEMFD_FLAG_INIT_PRIVATE, true);
		}
	}

	kvm_vm_release(vm);
}

static void test_gmem_flag_validity_without_conversion_cap(void)
{
	uint64_t non_coco_vm_valid_flags = 0;

	if (kvm_has_cap(KVM_CAP_GMEM_SHARED_MEM))
		non_coco_vm_valid_flags = GUEST_MEMFD_FLAG_SUPPORT_SHARED;

	test_vm_type_gmem_flag_validity(VM_TYPE_DEFAULT, non_coco_vm_valid_flags);

#ifdef __x86_64__
	test_vm_type_gmem_flag_validity(KVM_X86_SW_PROTECTED_VM, non_coco_vm_valid_flags);
	test_vm_type_gmem_flag_validity(KVM_X86_SEV_VM, 0);
	test_vm_type_gmem_flag_validity(KVM_X86_SEV_ES_VM, 0);
	test_vm_type_gmem_flag_validity(KVM_X86_SNP_VM, 0);
	test_vm_type_gmem_flag_validity(KVM_X86_TDX_VM, 0);
#endif
}

static void test_gmem_flag_validity(void)
{
	/* After conversions are supported, all VM types support shared mem. */
	uint64_t valid_flags = GUEST_MEMFD_FLAG_SUPPORT_SHARED;

	if (kvm_has_cap(KVM_CAP_GMEM_HUGETLB))
		valid_flags |= GUEST_MEMFD_FLAG_HUGETLB;

	test_vm_type_gmem_flag_validity(VM_TYPE_DEFAULT, valid_flags);

#ifdef __x86_64__
	test_vm_type_gmem_flag_validity(KVM_X86_SW_PROTECTED_VM, valid_flags);
	test_vm_type_gmem_flag_validity(KVM_X86_SEV_VM, valid_flags);
	test_vm_type_gmem_flag_validity(KVM_X86_SEV_ES_VM, valid_flags);
	test_vm_type_gmem_flag_validity(KVM_X86_SNP_VM, valid_flags);
	test_vm_type_gmem_flag_validity(KVM_X86_TDX_VM, valid_flags);
#endif
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_GUEST_MEMFD));

	if (kvm_has_cap(KVM_CAP_GMEM_CONVERSION))
		test_gmem_flag_validity();
	else
		test_gmem_flag_validity_without_conversion_cap();

	test_with_type(VM_TYPE_DEFAULT, 0, false);
	if (kvm_has_cap(KVM_CAP_GMEM_SHARED_MEM)) {
		test_with_type(VM_TYPE_DEFAULT, GUEST_MEMFD_FLAG_SUPPORT_SHARED,
			       true);
	}

#ifdef __x86_64__
	test_with_type(KVM_X86_SW_PROTECTED_VM, 0, false);
	if (kvm_has_cap(KVM_CAP_GMEM_SHARED_MEM)) {
		test_with_type(KVM_X86_SW_PROTECTED_VM,
			       GUEST_MEMFD_FLAG_SUPPORT_SHARED, true);
	}
#endif
}
