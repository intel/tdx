// SPDX-License-Identifier: GPL-2.0-only
/*
 * Tests that HugeTLB statistics are correct at various points of the lifecycle
 * of guest_memfd with 1G page support.
 *
 * Providing a HUGETLB_CGROUP_PATH will allow cgroup reservations to be
 * tested.
 *
 * Either use
 *
 *   ./guest_memfd_provide_hugetlb_cgroup_mount.sh ./guest_memfd_hugetlb_reporting_test
 *
 * or provide the mount with
 *
 *   export HUGETLB_CGROUP_PATH=/tmp/hugetlb-cgroup
 *   mount -t cgroup -o hugetlb none $HUGETLB_CGROUP_PATH
 *   ./guest_memfd_hugetlb_reporting_test
 *
 *
 * Copyright (C) 2025 Google LLC
 *
 * Authors:
 *   Ackerley Tng <ackerleytng@google.com>
 */

#include <fcntl.h>
#include <linux/falloc.h>
#include <linux/guestmem.h>
#include <linux/kvm.h>
#include <linux/limits.h>
#include <linux/memfd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "kvm_util.h"
#include "test_util.h"
#include "processor.h"

static unsigned long read_value(const char *file_name)
{
	FILE *fp;
	unsigned long num;

	fp = fopen(file_name, "r");
	TEST_ASSERT(fp != NULL, "Error opening file %s!\n", file_name);

	TEST_ASSERT_EQ(fscanf(fp, "%lu", &num), 1);

	fclose(fp);

	return num;
}

enum hugetlb_statistic {
	FREE_HUGEPAGES,
	NR_HUGEPAGES,
	NR_OVERCOMMIT_HUGEPAGES,
	RESV_HUGEPAGES,
	SURPLUS_HUGEPAGES,
	NR_TESTED_HUGETLB_STATISTICS,
};

enum hugetlb_cgroup_statistic {
	LIMIT_IN_BYTES,
	MAX_USAGE_IN_BYTES,
	USAGE_IN_BYTES,
	NR_TESTED_HUGETLB_CGROUP_STATISTICS,
};

enum hugetlb_cgroup_statistic_category {
	USAGE = 0,
	RESERVATION,
	NR_HUGETLB_CGROUP_STATISTIC_CATEGORIES,
};

static const char *hugetlb_statistics[NR_TESTED_HUGETLB_STATISTICS] = {
	[FREE_HUGEPAGES] = "free_hugepages",
	[NR_HUGEPAGES] = "nr_hugepages",
	[NR_OVERCOMMIT_HUGEPAGES] = "nr_overcommit_hugepages",
	[RESV_HUGEPAGES] = "resv_hugepages",
	[SURPLUS_HUGEPAGES] = "surplus_hugepages",
};

static const char *hugetlb_cgroup_statistics[NR_TESTED_HUGETLB_CGROUP_STATISTICS] = {
	[LIMIT_IN_BYTES] = "limit_in_bytes",
	[MAX_USAGE_IN_BYTES] = "max_usage_in_bytes",
	[USAGE_IN_BYTES] = "usage_in_bytes",
};

enum test_page_size {
	TEST_SZ_2M,
	TEST_SZ_1G,
	NR_TEST_SIZES,
};

struct test_param {
	size_t page_size;
	int memfd_create_flags;
	uint64_t guest_memfd_flags;
	char *hugetlb_size_string;
	char *hugetlb_cgroup_size_string;
};

const struct test_param *test_params(enum test_page_size size)
{
	static const struct test_param params[] = {
		[TEST_SZ_2M] = {
			.page_size = PG_SIZE_2M,
			.memfd_create_flags = MFD_HUGETLB | MFD_HUGE_2MB,
			.guest_memfd_flags = GUEST_MEMFD_FLAG_HUGETLB | GUESTMEM_HUGETLB_FLAG_2MB,
			.hugetlb_size_string = "2048kB",
			.hugetlb_cgroup_size_string = "2MB",
		},
		[TEST_SZ_1G] = {
			.page_size = PG_SIZE_1G,
			.memfd_create_flags = MFD_HUGETLB | MFD_HUGE_1GB,
			.guest_memfd_flags = GUEST_MEMFD_FLAG_HUGETLB | GUESTMEM_HUGETLB_FLAG_1GB,
			.hugetlb_size_string = "1048576kB",
			.hugetlb_cgroup_size_string = "1GB",
		},
	};

	return &params[size];
}

static unsigned long read_hugetlb_statistic(enum test_page_size size,
					    enum hugetlb_statistic statistic)
{
	char path[PATH_MAX] = "/sys/kernel/mm/hugepages/hugepages-";

	strcat(path, test_params(size)->hugetlb_size_string);
	strcat(path, "/");
	strcat(path, hugetlb_statistics[statistic]);

	return read_value(path);
}

static unsigned long read_hugetlb_cgroup_statistic(const char *hugetlb_cgroup_path,
						   enum test_page_size size,
						   enum hugetlb_cgroup_statistic statistic,
						   bool reservations)
{
	char path[PATH_MAX] = "";

	strcat(path, hugetlb_cgroup_path);

	if (hugetlb_cgroup_path[strlen(hugetlb_cgroup_path) - 1] != '/')
		strcat(path, "/");

	strcat(path, "hugetlb.");
	strcat(path, test_params(size)->hugetlb_cgroup_size_string);
	if (reservations)
		strcat(path, ".rsvd");
	strcat(path, ".");
	strcat(path, hugetlb_cgroup_statistics[statistic]);

	return read_value(path);
}

static unsigned long hugetlb_baseline[NR_TEST_SIZES]
				     [NR_TESTED_HUGETLB_STATISTICS];

static unsigned long
	hugetlb_cgroup_baseline[NR_TEST_SIZES]
			       [NR_TESTED_HUGETLB_CGROUP_STATISTICS]
			       [NR_HUGETLB_CGROUP_STATISTIC_CATEGORIES];


static void establish_baseline(const char *hugetlb_cgroup_path)
{
	const char *p = hugetlb_cgroup_path;
	int i, j;

	for (i = 0; i < NR_TEST_SIZES; ++i) {
		for (j = 0; j < NR_TESTED_HUGETLB_STATISTICS; ++j)
			hugetlb_baseline[i][j] = read_hugetlb_statistic(i, j);

		if (!hugetlb_cgroup_path)
			continue;

		for (j = 0; j < NR_TESTED_HUGETLB_CGROUP_STATISTICS; ++j) {
			hugetlb_cgroup_baseline[i][j][USAGE] =
				read_hugetlb_cgroup_statistic(p, i, j, USAGE);
			hugetlb_cgroup_baseline[i][j][RESERVATION] =
				read_hugetlb_cgroup_statistic(p, i, j, RESERVATION);
		}
	}
}

static void assert_stats_at_baseline(const char *hugetlb_cgroup_path)
{
	const char *p = hugetlb_cgroup_path;

	/* Enumerate these for easy assertion reading. */
	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_2M, FREE_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_2M][FREE_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_2M, NR_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_2M][NR_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_2M, NR_OVERCOMMIT_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_2M][NR_OVERCOMMIT_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_2M, RESV_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_2M][RESV_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_2M, SURPLUS_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_2M][SURPLUS_HUGEPAGES]);

	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_1G, FREE_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_1G][FREE_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_1G, NR_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_1G][NR_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_1G, NR_OVERCOMMIT_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_1G][NR_OVERCOMMIT_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_1G, RESV_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_1G][RESV_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(TEST_SZ_1G, SURPLUS_HUGEPAGES),
		       hugetlb_baseline[TEST_SZ_1G][SURPLUS_HUGEPAGES]);

	if (!hugetlb_cgroup_path)
		return;

	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, TEST_SZ_2M, LIMIT_IN_BYTES, USAGE),
		hugetlb_cgroup_baseline[TEST_SZ_2M][LIMIT_IN_BYTES][USAGE]);
	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, TEST_SZ_2M, MAX_USAGE_IN_BYTES, USAGE),
		hugetlb_cgroup_baseline[TEST_SZ_2M][MAX_USAGE_IN_BYTES][USAGE]);
	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, TEST_SZ_2M, USAGE_IN_BYTES, USAGE),
		hugetlb_cgroup_baseline[TEST_SZ_2M][USAGE_IN_BYTES][USAGE]);

	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, TEST_SZ_1G, LIMIT_IN_BYTES, RESERVATION),
		hugetlb_cgroup_baseline[TEST_SZ_1G][LIMIT_IN_BYTES][RESERVATION]);
	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, TEST_SZ_1G, MAX_USAGE_IN_BYTES, RESERVATION),
		hugetlb_cgroup_baseline[TEST_SZ_1G][MAX_USAGE_IN_BYTES][RESERVATION]);
	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, TEST_SZ_1G, USAGE_IN_BYTES, RESERVATION),
		hugetlb_cgroup_baseline[TEST_SZ_1G][USAGE_IN_BYTES][RESERVATION]);
}

static void assert_stats(const char *hugetlb_cgroup_path,
			 enum test_page_size size, unsigned long num_reserved,
			 unsigned long num_faulted)
{
	size_t pgsz = test_params(size)->page_size;
	const char *p = hugetlb_cgroup_path;

	TEST_ASSERT_EQ(read_hugetlb_statistic(size, FREE_HUGEPAGES),
		       hugetlb_baseline[size][FREE_HUGEPAGES] - num_faulted);
	TEST_ASSERT_EQ(read_hugetlb_statistic(size, NR_HUGEPAGES),
		       hugetlb_baseline[size][NR_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(size, NR_OVERCOMMIT_HUGEPAGES),
		       hugetlb_baseline[size][NR_OVERCOMMIT_HUGEPAGES]);
	TEST_ASSERT_EQ(read_hugetlb_statistic(size, RESV_HUGEPAGES),
		       hugetlb_baseline[size][RESV_HUGEPAGES] + num_reserved - num_faulted);
	TEST_ASSERT_EQ(read_hugetlb_statistic(size, SURPLUS_HUGEPAGES),
		       hugetlb_baseline[size][SURPLUS_HUGEPAGES]);

	if (!hugetlb_cgroup_path)
		return;

	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, size, LIMIT_IN_BYTES, USAGE),
		hugetlb_cgroup_baseline[size][LIMIT_IN_BYTES][USAGE]);
	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, size, MAX_USAGE_IN_BYTES, USAGE),
		hugetlb_cgroup_baseline[size][MAX_USAGE_IN_BYTES][USAGE]);
	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, size, USAGE_IN_BYTES, USAGE),
		hugetlb_cgroup_baseline[size][USAGE_IN_BYTES][USAGE] + num_faulted * pgsz);

	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, size, LIMIT_IN_BYTES, RESERVATION),
		hugetlb_cgroup_baseline[size][LIMIT_IN_BYTES][RESERVATION]);
	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, size, MAX_USAGE_IN_BYTES, RESERVATION),
		hugetlb_cgroup_baseline[size][MAX_USAGE_IN_BYTES][RESERVATION]);
	TEST_ASSERT_EQ(
		read_hugetlb_cgroup_statistic(p, size, USAGE_IN_BYTES, RESERVATION),
		hugetlb_cgroup_baseline[size][USAGE_IN_BYTES][RESERVATION] + num_reserved * pgsz);
}

/* Use hugetlb behavior as a baseline. guest_memfd should have comparable behavior. */
static void test_hugetlb_behavior(const char *hugetlb_cgroup_path, enum test_page_size test_size)
{
	const struct test_param *param;
	char *mem;
	int memfd;

	param = test_params(test_size);

	assert_stats_at_baseline(hugetlb_cgroup_path);

	memfd = memfd_create("guest_memfd_hugetlb_reporting_test",
			     param->memfd_create_flags);

	assert_stats(hugetlb_cgroup_path, test_size, 0, 0);

	mem = mmap(NULL, param->page_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_HUGETLB, memfd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "Couldn't mmap()");

	assert_stats(hugetlb_cgroup_path, test_size, 1, 0);

	*mem = 'A';

	assert_stats(hugetlb_cgroup_path, test_size, 1, 1);

	munmap(mem, param->page_size);

	assert_stats(hugetlb_cgroup_path, test_size, 1, 1);

	madvise(mem, param->page_size, MADV_DONTNEED);

	assert_stats(hugetlb_cgroup_path, test_size, 1, 1);

	madvise(mem, param->page_size, MADV_REMOVE);

	assert_stats(hugetlb_cgroup_path, test_size, 1, 1);

	close(memfd);

	assert_stats_at_baseline(hugetlb_cgroup_path);
}

static void test_guest_memfd_behavior(const char *hugetlb_cgroup_path,
				      enum test_page_size test_size)
{
	const struct test_param *param;
	struct kvm_vm *vm;
	int guest_memfd;

	param = test_params(test_size);

	assert_stats_at_baseline(hugetlb_cgroup_path);

	vm = vm_create_barebones_type(KVM_X86_SW_PROTECTED_VM);

	assert_stats(hugetlb_cgroup_path, test_size, 0, 0);

	guest_memfd = vm_create_guest_memfd(vm, param->page_size,
					    param->guest_memfd_flags);

	/* fd creation reserves pages. */
	assert_stats(hugetlb_cgroup_path, test_size, 1, 0);

	fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE, 0, param->page_size);

	assert_stats(hugetlb_cgroup_path, test_size, 1, 1);

	fallocate(guest_memfd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 0,
		  param->page_size);

	assert_stats(hugetlb_cgroup_path, test_size, 1, 0);

	close(guest_memfd);

	/*
	 * Wait a little for stats to be updated in rcu callback. resv_hugepages
	 * is updated on truncation in ->free_inode, and ->free_inode() happens
	 * in an rcu callback.
	 */
	usleep(300 * 1000);

	assert_stats_at_baseline(hugetlb_cgroup_path);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	char *hugetlb_cgroup_path;

	hugetlb_cgroup_path = getenv("HUGETLB_CGROUP_PATH");

	establish_baseline(hugetlb_cgroup_path);

	test_hugetlb_behavior(hugetlb_cgroup_path, TEST_SZ_2M);
	test_hugetlb_behavior(hugetlb_cgroup_path, TEST_SZ_1G);

	test_guest_memfd_behavior(hugetlb_cgroup_path, TEST_SZ_2M);
	test_guest_memfd_behavior(hugetlb_cgroup_path, TEST_SZ_1G);
}
