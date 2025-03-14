#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only */
#
# Wrapper script which runs different test setups of
# private_mem_conversions_test.
#
# Copyright (C) 2024, Google LLC.

set -e

num_vcpus_to_test=4
num_memslots_to_test=$num_vcpus_to_test

get_default_hugepage_size_in_kB() {
	grep "Hugepagesize:" /proc/meminfo | grep -o '[[:digit:]]\+'
}

# Required pages are based on the test setup (see computation for memfd_size) in
# test_mem_conversions() in private_mem_migrate_tests.c)

# These static requirements are set to the maximum required for
# num_vcpus_to_test, over all the hugetlb-related tests
required_num_2m_hugepages=$(( 1024 * num_vcpus_to_test ))
required_num_1g_hugepages=$(( 2 * num_vcpus_to_test ))

# The other hugetlb sizes are not supported on x86_64
[ "$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo 0)" \
  -ge "$required_num_2m_hugepages" ] && hugepage_2mb_enabled=1
[ "$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages 2>/dev/null || echo 0)" \
  -ge "$required_num_1g_hugepages" ] && hugepage_1gb_enabled=1

case $(get_default_hugepage_size_in_kB) in
	2048)
		hugepage_default_enabled=$hugepage_2mb_enabled
		;;
	1048576)
		hugepage_default_enabled=$hugepage_1gb_enabled
		;;
	*)
		hugepage_default_enabled=0
		;;
esac

backing_src_types=( anonymous )
backing_src_types+=( anonymous_thp )
[ -n "$hugepage_default_enabled" ] && \
	backing_src_types+=( anonymous_hugetlb ) || \
	echo "skipping anonymous_hugetlb backing source type"
[ -n "$hugepage_2mb_enabled" ] && \
	backing_src_types+=( anonymous_hugetlb_2mb ) || \
	echo "skipping anonymous_hugetlb_2mb backing source type"
[ -n "$hugepage_1gb_enabled" ] && \
	backing_src_types+=( anonymous_hugetlb_1gb ) || \
	echo "skipping anonymous_hugetlb_1gb backing source type"
backing_src_types+=( shmem )
[ -n "$hugepage_default_enabled" ] && \
	backing_src_types+=( shared_hugetlb ) || \
	echo "skipping shared_hugetlb backing source type"

set +e

TEST_EXECUTABLE="$(dirname "$0")/private_mem_conversions_test"

(
	set -e

	for src_type in "${backing_src_types[@]}"; do

		set -x

                $TEST_EXECUTABLE -s "$src_type" -n $num_vcpus_to_test
		$TEST_EXECUTABLE -s "$src_type" -n $num_vcpus_to_test -m $num_memslots_to_test

		{ set +x; } 2>/dev/null

		echo

	done
)
RET=$?

exit $RET
