#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Wrapper that runs test, providing a hugetlb cgroup mount in environment
# variable HUGETLB_CGROUP_PATH
#
# Example:
#   ./guest_memfd_provide_hugetlb_cgroup_mount.sh ./guest_memfd_hugetlb_reporting_test
#
# Copyright (C) 2025, Google LLC.

script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

temp_dir=$(mktemp -d /tmp/guest_memfd_hugetlb_reporting_test_XXXXXX)
if [[ -z "$temp_dir" ]]; then
  echo "Error: Failed to create temporary directory for hugetlb cgroup mount." >&2
  exit 1
fi

delete_temp_dir() {
  rm -rf $temp_dir
}
trap delete_temp_dir EXIT


mount -t cgroup -o hugetlb none $temp_dir


cleanup() {
  umount $temp_dir
  rm -rf $temp_dir
}
trap cleanup EXIT


HUGETLB_CGROUP_PATH=$temp_dir $@
