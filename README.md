repositories and branches
=========================
Linux
-----
git repository:
https://github.com/intel/tdx

recommended branch:
- kvm-upstream-snapshot: a snapshot of kvm-upstream-workaround branch with 6.2 code base plus some bug fixes. **This branch can be used as host/guest kernel to launch TDX VM**, as TDX guest basic functionality is already upstreamed.

Configurations:
- CONFIG_INTEL_TDX_HOST=y: enable TDX KVM support.
- CONFIG_INTEL_TDX_HOST_DEBUG: debug support for TDX module. optional. say N.
- CONFIG_INTEL_TDX_MODULE_LOADER_OLD: Load TDX module through initrd image (the old method). This can happen when 1. TDX module is not loaded by BIOS; 2. add "tdx_module_loader_old" in host kernel cmdline; 3. integrate the TDX module files into the initrd image.
- CONFIG_INTEL_TDX_GUEST=y: enable TDX guest support

kernel command line (optional):
- tdx_module_loader_old: See CONFIG_INTEL_TDX_MODULE_LOADER_OLD above.
- disable_mtrr_cleanup: If you enable TDX in BIOS and bootup a **non-TDX** kernel, add it to avoid the potential machine check.

Qemu
----
git repository:
https://github.com/intel/qemu-tdx

recommended branch:
- tdx-upstream-snapshot: a 7.2 snapshot of tdx-upstream-wip branch plus the safe device pass-through patches. It is aimed to co-work with kvm-upstream-snapshot branch.

build:  
build x86_64-softmmu target.  
./configure --target-list=x86_64-softmmu

TDVF
----
Now TDVF is merged into EDK2 upstream.
https://github.com/tianocore/edk2

build:  
source ./edksetup.sh  
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b RELEASE

Running guest TD
================
preparation
-----------
1. build the host/guest kernel with kconfig mentioned above.
2. reboot into host kernel, make sure TDX module is loaded and initailzed successfully.  
   dmesg shows: **tdx: TDX module initialized**  
   It is recommended to load TDX module through BIOS(IFWI), although old support (initrd loading) still exists.  
3. build or prepare the necessary components: TDVF, guest image, QEMU binary.
4. if necessary, configure the vfio-pci device driver to prepare the device pass-thru. e.g. configure through sysfs
```
# make sure vfio-pci driver is loaded
modprobe vfio && modprobe vfio-pci
# Free the intended pass-through PCI devices from the applicable PCI device driver
echo <function_address> > /sys/bus/pci/drivers/<pci_device_driver>/unbind
# Configure the vfio-pci device driver
echo <vendor_code> <device_code> > /sys/bus/pci/drivers/vfio-pci/new_id
```
5. Because current vfio driver has dma entry limitation due to some secure issue. TDX would add more DMA entries.  
   Thus increase the limitation:  
```
   echo 0x200000 > /sys/module/vfio_iommu_type1/parameters/dma_entry_limit
```
6. launch TD VM.

qemu tdx-upstream-snapshot branch
---------------------------------
- create tdx-guest object  
  -object tdx-guest,id=tdx0,debug=off  
  -machine confidential-guest-support=tdx0
- specify q35 chipset and KVM  
  -machine q35,accel=kvm
- specify TDVF  
  -bios ${OVMF}
- specify split irqchip  
  -machine kernel-irqchip=split
- use UPM (Unmapping Process Memory) create memfd-private backend. (To test safe device pass-thru, **UPM is a must**)   
  -object memory-backend-memfd-private,id=ram1,size=${MEM}  
  -machine memory-backend=ram1  
- use device pass-thru  
  -device vfio-pci,host=\<DDDD:BB:DD.F\>

command line example:
---------------------

```
SMP=4
MEM=4G
DRIVE_DISC=/path/to/disk-image
OVMF=/path/to/OVMF.fd
DEVICE_BDF=<DDDD:BB:DD.F>
qemu-system-x86_64 \
    -m ${MEM} -smp ${SMP},sockets=1 \
    -cpu host,host-phys-bits,pmu=off \
    -no-hpet -nographic -vga none \
    -nodefaults \
    -monitor pty \
    -object tdx-guest,id=tdx0,debug=off \
    -machine confidential-guest-support=tdx0 \
    -machine q35,accel=kvm \
    -machine kernel-irqchip=split \
    -object memory-backend-memfd-private,id=ram1,size=${MEM} \
    -machine memory-backend=ram1 \
    -bios ${OVMF} \
    -chardev stdio,id=mux,mux=on \
    -serial chardev:mux -monitor chardev:mux \
    -device virtio-serial,romfile= \
    -device virtconsole,chardev=mux \
    -drive file=${DRIVE_DISK},if=virtio,format=qcow2,media=disk,index=0 \
    -device vfio-pci,host=${DEVICE_BDF}
```