#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Wrapper script which runs different test setups of
# private_mem_conversions_test.
#
# Copyright (C) 2025, Google LLC.

import os
import fcntl
import sys
import subprocess


NUM_VCPUS_TO_TEST = 4
NUM_MEMSLOTS_TO_TEST = NUM_VCPUS_TO_TEST

# Required pages are based on the test setup in the C code.
# These static requirements are set to the maximum required for
# NUM_VCPUS_TO_TEST, over all the hugetlb-related tests
REQUIRED_NUM_2M_HUGEPAGES = 1024 * NUM_VCPUS_TO_TEST
REQUIRED_NUM_1G_HUGEPAGES = 2 * NUM_VCPUS_TO_TEST


def get_hugepage_count(page_size_kb: int) -> int:
    """Reads the current number of hugepages available for a given size."""
    try:
        path = f"/sys/kernel/mm/hugepages/hugepages-{page_size_kb}kB/nr_hugepages"
        with open(path, 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def get_default_hugepage_size_in_kb():
    """Reads the default hugepage size from /proc/meminfo."""
    try:
        with open("/proc/meminfo", 'r') as f:
            for line in f:
                if line.startswith("Hugepagesize:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1])
    except FileNotFoundError:
        return None


def run_tests(executable_path: str, src_type: str, num_memslots: int, num_vcpus: int) -> None:
    """Runs the test executable with different arguments."""
    command = [executable_path, "-s", src_type, "-m", str(num_memslots), "-n", str(num_vcpus)]
    print(" ".join(command))
    _ = subprocess.run(command, check=True)


def kvm_check_cap(capability: int) -> int:
    KVM_CHECK_EXTENSION = 0xAE03
    KVM_DEVICE = '/dev/kvm'

    if not os.path.exists(KVM_DEVICE):
        print(f"Error: KVM device not found at {KVM_DEVICE}. Is the 'kvm' module loaded?")
        return -1

    try:
        fd = os.open(KVM_DEVICE, os.O_RDONLY)

        result = fcntl.ioctl(fd, KVM_CHECK_EXTENSION, capability)

        os.close(fd)
        return result
    except OSError as e:
        print(f"Error issuing KVM ioctl on {KVM_DEVICE}: {e}", file=sys.stderr)
        if fd > 0:
            os.close(fd)
        return -1


def kvm_has_gmem_attributes() -> bool:
    KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES = 246

    return kvm_check_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES) > 0


def get_backing_source_types() -> list[str]:
    hugepage_2mb_count = get_hugepage_count(2048)
    hugepage_2mb_enabled = hugepage_2mb_count >= REQUIRED_NUM_2M_HUGEPAGES
    hugepage_1gb_count = get_hugepage_count(1048576)
    hugepage_1gb_enabled = hugepage_1gb_count >= REQUIRED_NUM_1G_HUGEPAGES

    default_hugepage_size_kb = get_default_hugepage_size_in_kb()
    hugepage_default_enabled = False
    if default_hugepage_size_kb == 2048:
        hugepage_default_enabled = hugepage_2mb_enabled
    elif default_hugepage_size_kb == 1048576:
        hugepage_default_enabled = hugepage_1gb_enabled

    backing_src_types: list[str] = ["anonymous", "anonymous_thp"]

    if hugepage_default_enabled:
        backing_src_types.append("anonymous_hugetlb")
    else:
        print("skipping anonymous_hugetlb backing source type")

    if hugepage_2mb_enabled:
        backing_src_types.append("anonymous_hugetlb_2mb")
    else:
        print("skipping anonymous_hugetlb_2mb backing source type")

    if hugepage_1gb_enabled:
        backing_src_types.append("anonymous_hugetlb_1gb")
    else:
        print("skipping anonymous_hugetlb_1gb backing source type")

    backing_src_types.append("shmem")

    if hugepage_default_enabled:
        backing_src_types.append("shared_hugetlb")
    else:
        print("skipping shared_hugetlb backing source type")

    return backing_src_types


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    test_executable = os.path.join(script_dir, "private_mem_conversions_test")

    if not os.path.exists(test_executable):
        print(f"Error: Test executable not found at '{test_executable}'", file=sys.stderr)
        sys.exit(1)

    return_code = 0

    backing_src_types = ["shmem"] if kvm_has_gmem_attributes() else get_backing_source_types()
    try:
        for i, src_type in enumerate(backing_src_types):
            if i > 0:
                print()
            run_tests(test_executable, src_type, num_memslots=1, num_vcpus=1)
            run_tests(test_executable, src_type, num_memslots=1, num_vcpus=NUM_VCPUS_TO_TEST)
            run_tests(test_executable, src_type, num_memslots=NUM_MEMSLOTS_TO_TEST, num_vcpus=NUM_VCPUS_TO_TEST)
    except subprocess.CalledProcessError as e:
        print(f"Test failed for source type '{src_type}'. Command: {' '.join(e.cmd)}", file=sys.stderr)
        return_code = e.returncode
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return_code = 1

    sys.exit(return_code)


if __name__ == "__main__":
    main()
