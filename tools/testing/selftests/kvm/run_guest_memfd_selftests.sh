#!/bin/bash

ignore=0
scp_target=0

while getopts ":ft:" opt; do
  case $opt in
    f)
      ignore=1
      ;;
    t)
      scp_target="$OPTARG"
      echo "scp-ing to $scp_target"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

test_list=(
  "./guest_memfd_test"
  "./guest_memfd_conversions_test"
  "./guest_memfd_provide_hugetlb_cgroup_mount.sh ./guest_memfd_wrap_test_check_hugetlb_reporting.sh ./guest_memfd_test"
  "./guest_memfd_provide_hugetlb_cgroup_mount.sh ./guest_memfd_wrap_test_check_hugetlb_reporting.sh ./guest_memfd_conversions_test"
  "./guest_memfd_provide_hugetlb_cgroup_mount.sh ./guest_memfd_wrap_test_check_hugetlb_reporting.sh ./guest_memfd_hugetlb_reporting_test"
  "./x86/memory_attributes_test"
  "./x86/private_mem_conversions_test.py"
  "./set_memory_region_test"
  "./x86/private_mem_kvm_exits_test"

  "./x86/tdx_vm_test"
  "./x86/tdx_upm_test"
  "./x86/tdx_shared_mem_test"
  "./x86/tdx_gmem_private_and_shared_test"
)

if [ "$scp_target" != "0" ]; then
  paths=(
    ./tools/testing/selftests/kvm/run_guest_memfd_selftests.sh
    ./tools/testing/selftests/kvm/x86/private_mem_conversions_test
  )

  for item in "${test_list[@]}"; do
    IFS=' ' read -r -a parts <<< "$item"

    for part in "${parts[@]}"; do
      paths+=("tools/testing/selftests/kvm/${part}")
    done
  done

  /google/bin/releases/miba-team/public/miba_ssh_session -a -- ssh root@$scp_target -t "mkdir -p /export/hda3/local/ackerleytng/tests/"
  /google/bin/releases/miba-team/public/miba_ssh_session -a -- rsync ${paths[@]} root@$scp_target:/export/hda3/local/ackerleytng/tests/
  exit 0;
fi

set -e

while :; do

  for test in "${test_list[@]}"; do
    IFS=' ' read -r -a parts <<< "$test"

    missing=
    for part in "${parts[@]}"; do
      if [ ! -f "$part" ]; then
        if [ ! -f "${part/x86/.}" ]; then
          missing=$part
          break
        else
          test=${test/x86/.}
        fi
      fi
    done

    if [ -n "$missing" ]; then
      echo "Skipping $test, missing $missing"
      continue
    fi

    if [ "$ignore" -eq 0 ]; then
      echo "========================================================================="
      read -p "Proceed with $test?"
    fi

    echo "Running $test"
    bash -c "$test"
  done

  echo "========================================================================="
  read -p "Done with one round, proceed?"
  ignore=yes
done
