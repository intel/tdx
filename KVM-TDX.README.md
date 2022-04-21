repositories and branches
=========================
Linux
-----
git repository:
https://github.com/intel/tdx

branchs:
kvm-upstream-workaround branch is recommended.
- kvm-upstream: includes patches only posted to the linux and kvm community.
- kvm-upstream-workaround: includes kvm-upstream and further patches.
If you tests TDX KVM, kvm-upstream-workaround branch is recommended.

Configurations:
- CONFIG_INTEL_TDX_HOST=y: enable TDX KVM support.
- CONFIG_INTEL_TDX_HOST_DEBUG: debug support for TDX module. optional. say N.
- CONFIG_INTEL_TDX_GUEST: guest TD support.  Optional. Not needed for TDX KVM.
- CONFIG_X86_TDX_KVM_EXPERIMENTAL=y: Enable experimental TDX KVM support.
  Optional, needed for
  https://github.com/intel/tdx/releases/tag/kvm-upstream-2022.03.29-v5.17-rc8-workaround. TDX
  KVM needs many patches and the patches will be merged step by step, not at
  once. Set it to y to enable TDX KVM support so that developer can exercise
  TDX KVM code.

kernel command line:
- tdx_host=on
  Enables TDX features in host kernel. Because it's off by default, it needs to be
  explicitly enabled.
- disable_mtrr_cleanup

Qemu
----
git repository:
https://github.com/intel/qemu-tdx

branches:
tdx-upstream-wip branch is recommended.
- tdx: includes full features.  It's being deprecated in favor for tdx-upstream-wip.
- tdx-upstream: includes patches only posted to the qemu community
- tdx-upstream-wip: includes tdx-upstream and further patches.

build:
build x86_64-softmmu target.
./configure --target-list=x86_64-softmmu

kvm-unit-tests
--------------
git repository:
https://github.com/intel/kvm-unit-tests-tdx

branches:
- tdx: include test cases for TDX.

TDVF
----
git repository:
https://github.com/tianocore/edk2-staging/tree/TDVF

Please refer its documentation for further information.
https://github.com/tianocore/edk2-staging/blob/TDVF/README.md

Guest
-----
git repository:
https://github.com/intel/tdx

branches:
- guest-upstream: guest TD support for upstreaming
- guest: guest TD support

Configurations:
- CONFIG_INTEL_TDX_GUEST=y

Unit Testing
============
selftests and kvm-unit-tests are available for TDX KVM.

selftests
---------
linux/tools/testing/selftests/kvm/x86_64/tdx_vm_tests

kvm-unit-tests
--------------
For running unit tests with TDX enabled, refer to
https://github.com/intel/kvm-unit-tests-tdx/blob/tdx/README.md#unit-test-in-tdx-environment


Running guest TD
================
qemu tdx-upstream-wip branch
----------------------------
- create tdx-guest object.
  -object tdx-guest,id=tdx0,debug=off,sept-ve-disable=on \
  -machine confidential-guest-support=tdx0
- specify q35 chipset and KVM
  -machine q35,accel=kvm
- specify TDVF
  -bios ${OVMF}
- specify split irqchip, disable PIC and PIT
  -machine kernel-irqchip=split,pic=off,pit=off

command line example:
SMP=8
MEM=512M
KERNEL=/path/to/guest-kernel
INITRD=/path/to/guest-initrd
APPEND="console=hvc0 nomce no-kvmclock no-steal-acc no_console_suspend"
DRIVE_DISC=/path/to/disk-image
OVMF=/path/to/OVMF.fd
qemu-system-x86_64 \
    -s -m ${MEM} -smp ${SMP},sockets=1 \
    -cpu host,host-phys-bits,pmu=off,pks=on \
    -no-hpet -nographic -vga none \
    -nodefaults \
    -monitor stdio \
    -object tdx-guest,id=tdx0,debug=off,sept-ve-disable=on \
    -machine confidential-guest-support=tdx0 \
    -machine q35,accel=kvm \
    -machine kernel-irqchip=split,sata=off,pic=off,pit=off \
    -bios ${OVMF} \
    -device virtio-serial \
    -chardev socket,id=tcp0,port=4445,host=0.0.0.0,server=on,wait=off \
    -device virtconsole,chardev=tcp0 \
    -kernel ${KERNEL} \
    -initrd ${INITRD} \
    -append "${APPEND}" \
    -drive file=${DRIVE_DISK},if=virtio,format=qcow2,media=disk,index=0 \
    -device vhost-vsock-pci,guest-cid=3


qemu tdx branch
---------------
- create tdx-guest object.
  -object tdx-guest,id=tdx0,debug=off,sept-ve-disable=on \
  -machine confidential-guest-support=tdx0
- specify q35 chipset, KVM and tdx kvm vm type.
  -machine q35,accel=kvm,kvm-type=tdx
- specify TDVF
  -device loader,file=${OVMF}
  or
  -device loader,file=${OVMF_CODE},config-firmware-volume=${OVMF_VARS},id=fd0
- specify split irqchip, disable PIC and PIT
  -machine kernel-irqchip=split,pic=off,pit=off
- UPM (Unmapping Process Memory): create memfd-private backend
  -object memory-backend-memfd-private,id=ram1,size=${MEM} \
  -machine memory-backend=ram1

command line example:
SMP=8
MEM=512M
KERNEL=/path/to/guest-kernel
INITRD=/path/to/guest-initrd
APPEND="console=hvc0 nomce no-kvmclock no-steal-acc no_console_suspend"
DRIVE_DISC=/path/to/disk-image
OVMF_CODE=/path/to/OVMF_CODE.fd
OVMF_VARS=/path/to/OVMF_VARS.fd
qemu-system-x86_64 \
     -s -m ${MEM} -smp ${SMP},sockets=1 \
     -cpu host,host-phys-bits,pmu=off,pks=on \
     -no-hpet -nographic -vga none \
     -nodefaults \
     -monitor stdio \
     -object tdx-guest,id=tdx0,debug=off,sept-ve-disable=on \
     -machine confidential-guest-support=tdx0 \
     -machine q35,accel=kvm,kvm-type=tdx \
     -machine kernel-irqchip=split,sata=off,pic=off,pit=off \
     -object memory-backend-memfd-private,id=ram1,size=${MEM} \
     -machine memory-backend=ram1 \
     -device loader,file=${OVMF_CODE},config-firmware-volume=${OVMF_VARS},id=fd0 \
     -kernel ${KERNEL} \
     -initrd ${INITRD} \
     -append "${APPEND}" \
     -device virtio-serial \
     -chardev socket,id=tcp0,port=4445,host=0.0.0.0,server=on,wait=off \
     -device virtconsole,chardev=tcp0 \
     -drive file=${DRIVE_DISK},if=virtio,format=qcow2,media=disk,index=0 \
     -device vhost-vsock-pci,guest-cid=3
