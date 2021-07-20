.. SPDX-License-Identifier: GPL-2.0

==================
Loading TDX module
==================

Glossary
========
Citation from [3].

ACM
  Authenticated Code Module:
  A code module that is designed to be loaded, verified and executed
  by the CPU in on-chip memory(CRAM).

CMR
  Convertible Memory Range:
  A range of physical memory configured by BIOS and verified by
  MCHECK. MCHECK verification is intended to help ensure that a CMR
  may be used to hold TDX memory pages encrypted with a private HKID.

MKTME
  Multi-Key TME:
  This SoC capability adds support to the TME to allow software to use
  one or more separate keys for encryption of volatile or persistent
  memory encryption. When used with TDX, it can provide
  confidentiality via separate keys for memory used by TDs. MKTME can
  be used with and without TDX extensions.

SEAMLDR
  SEAM Loader:
  An ACM intended to load the Intel TDX module.

NP-SEAMLDR
  Non-Persistent SEAM Loader

P-SEAMLDR
  Persistent SEAM Loader

PAMT
  Physical Address Metadata Table:
  An internal, hidden data structure used by the Intel TDX module,
  which is intended to hold the metadata of physical pages.

SEAM
  Secure Arbitration Mode:
  Intel CPU Instruction Set Architecture (ISA) extensions that support
  the Intel TDX module: an isolated software module that facilitates
  the operation and management of Trust Domains.

TD
  Trust Domain:
  Trust Domains (TDs) are designed to be hardware isolated Virtual
  Machines (VMs) deployed using Intel Trust Domain Extensions (Intel
  TDX).

TDMR
  Trust Domain Memory Range:
  A range of memory, configured by the host VMM, that is covered by
  PAMT and is intended to hold TD private memory and TD control
  structures.

TDX
  Trust Domain Extensions:
  An architecture, based on the TDX Instruction Set Architecture (ISA)
  extensions and the Intel TDX module, which supports operation and
  management of Trust Domains.

TME
  Total Memory Encryption:
  A memory encryption/decryption engine using an ephemeral platform
  key designed to encrypt memory contents exposed externally from the
  SoC.

Loading TDX module
==================
Overview
--------
TDX module is an isolated software module which is loaded into an isolated
memory range, Secure Arbitration Mode(SEAM) Range.  It will be executed in
isolated mode, SEAM VMX-root mode, for Intel TDX. [1]

1. Launch NP-SEAMLDR to load P-SEAMLDR on BSP.  This requires all APs in
   Wait-For-Init state.
   1a. Get info about P-SEAMLDR by SEAMLDR.INFO
2. Call SEAMLDR.INSTALL to load TDX module into SEAM region on all CPUs.  This
   requires all APs online.
3. Get info about TDX module, especially about convertible Memory Regions(CMRs)
   by TDH.SYS.INFO.
4. Calculate necessary memory for Physical Address Memory Tables(PAMTs)
   based on CMRs which was taken by the above step.
5. Allocate physically contiguous memory region for PAMTs and setup TDMRs
6. Initialize all CPUs for TDX module by TDH.SYS.LP.INIT.
7. Configure TDMRs and PAMTs by TDH.SYS.CONFIG
8. Initialize TDMRs/PAMTs by TDH.SYS.TDMR.INIT

Loading P-SEAMLDR at kernel boot time
-------------------------------------
early_initecall() is chosen for code simplicity.  It requires the following.

  - After dynamic memory allocation is usable.
  - After init_ia32_feat_ctl() which can clear X86_FEATURE_VMX and disable VMX
    feature.  The flag, X86_FEATURE_VMX, is uesed to check whether VMX is usable
    or not. The function is called by identify_boot_processor() via
    check_bugs().
  - Before booting APs, smp_init(), to avoid offline APs and online them to
    handle Wait-For-SIPI state.  NP-SEAMLDR requires all APs are in
    Wait-For-SIPI state.

With early_initcall() it can be assumed that no APs is running and kvm_module
isn't active.  It can be assumed that no one interferes with VMXON/VMXOFF.

Loading TDX module at kernel boot time
--------------------------------------
subsys_initcall_sync() is chosen to satisfy the following requirements.

  - After P-SEAMLDR is loaded.
  - After smp_init(). Loading TDX module requires SMP to be initialized because
    all CPUs needs to be initialized for TDX module. on_each_cpu() is used.
  - After NUMA node initialization and page allocator initialization because
    large physically contiguous memory with NUMA-awareness is needed for TDX
    module (e.g. about 4MB for 1GB, about 128MB for 32GB, and so on.).
    alloc_contig_region() is used to allocate such large physically contiguous
    region.
  - After iomem_resouce is populated with System RAM including regions specified
    by memmap=nn[KMG]!ss[KMG].  which is done by e820_reserve_resources() called
    by setup_arch().  Because tdx_construct_tdmr() walks iomem resources looking
    for legacy pmem region.
  - After reserved memory region is polulated in iomem_resource by
    e820__reserve_resources_late().  which is called by
    subsys_initcall(pci_subsys_init).
  - Before kvm_intel.  module_init() which is mapped to device_initcall() when
    it's built into kernel.


Options to load P-SEAMLDR and TDX module
========================================
kernel boot parameters
----------------------
  enable_tdx_host:
        enable tdx module at kernel boot time as TDX host.

  np_seamldr:
        path for np-seamloadr to launch.  By default
        "intel-seam/np-seamldr.acm".

  tdx_module:
        path for tdx module to load.  By default "intel-seam/libtdx.bin".

  tdx_sigstruct:
        path for sigstruct for tdx module. By default
        "intel-seam/libtdx.bin.sigstruct".

Loading SEAMLDR and tdx module at kernel boot time
--------------------------------------------------
enable_tdx_host specifies whether if kernel loads tdx module at boot time.

P-SEAMLDR       TDX module      kernel boot options
=========       ==========      ===================
Y               Y               enable_tdx_host
N               N               don't specify

* Y: load at kernel boot time
* N: not load at kernel boot time

Sysfs ABI
=========
/sys/firmware/p_seamldr/
------------------------
This represents P-SEAMLDR subsystem entry point directory.  It contains
sub-groups corresponding to P-SEAMLDR attributes and operation.  For P-SEAMLDR
attributes, please refer to about [4] 3.3 SEAMLDR_INFO.

Read only files. They exist only when P-SEAMLDR is loaded.

:version:         structure version
:attributes:      bitmap of attributes
:vendor_id:       vendor ID
:build_date:      build date
:build_num:       build number
:minor:           minor version number
:major:           major version number

/sys/firmware/tdx_module/
-------------------------
This represents TDX module subsystem entry point directory.  It contains
sub-groups corresponding to TDX module attributes and operation.  For TDX module
attributes, please refer to about [3] 18.6.2 TDSYSINFO_STRUCT.

Read only files. They exist only when TDX module is loaded.

:attributes:      module attribute
:vendor_id:       vendor ID
:build_data:      build date
:build_num:       build number
:minor_version:   minor version number
:major_version:   major version number
:state:
   state of TDX module in string.  possible string is "not-loaded",
   "loaded", "initialized", "shutdown" and "error".

Early load of NP-SEAMLDR and TDX module
=======================================
If TDX is enabled(CONFIG_INTEL_TDX_HOST=y), kernel is able to load TDX seam
module from initrd.  The related modules (np-seamldr.acm, libtdx.so and
libtdx.so.sigstruct) need to be stored in initrd.  Here's a example how to
customize preparation of an initrd.  Please note that it heavily depends on
distro how to prepare initrd.


initramfs-tools
---------------
The following script is a sample hook script for initramfs-tools.
TDXSEAM_SRCDIR are the directory in the host file system to store files related
to TDX MODULE.

::

  #! /bin/sh -e

  if [ -z "${TDXSEAM_SRCDIR}" ]; then
      TDXSEAM_SRCDIR=/lib/firmware/intel-seam
  fi
  if [ -z "${TDXSEAM_FILES}" ]; then
      TDXSEAM_FILES="np-seamldr.acm libtdx.so libtdx.so.sigstruct"
  fi
  TDXSEAM_DESTDIR=/lib/firmware/intel-seam

  PREREQ=""
  prereqs()
  {
      echo "$PREREQ"
  }

  case $1 in
      prereqs)
          prereqs
          exit 0
          ;;
  esac

  . /usr/share/initramfs-tools/hook-functions


  verbose()
  {
      if [ "${verbose}" = "y" ] ; then
          echo "I: tdx-seam: $*"
      fi
      :
  }

  verbose "using tdx seam module into early initramfs..."
  EFW_TMP=$(mktemp -d "${TMPDIR:-/var/tmp}/mkinitramfs-EFW_XXXXXXXXXX") || {
      echo "E: tdx-seam: cannot create temporary file" >&2
      exit 1
  }
  EFW_D="${EFW_TMP}/d"
  EFW_CPIO="${EFW_TMP}/early-initramfs.cpio"

  cleanup()
  {
      [ -d "${EFW_TMP}" ] && rm -fr "${EFW_TMP}" || true
  }

  errorout()
  {
      cleanup
      exit 1
  }

  mkdir -p ${EFW_D}/${TDXSEAM_DESTDIR} || errorout

  for f in ${TDXSEAM_FILES}; do
      verbose "Adding tdx-seam module ${TDXSEAM_SRCDIR}/${f} -> ${EFW_D}/${TDXSEAM_DESTDIR}/$(basename ${f})
  "
      cp ${TDXSEAM_SRCDIR}/${f} ${EFW_D}/${TDXSEAM_DESTDIR}/$(basename ${f}) || errorout
  done

  (cd ${EFW_D}; find . -type f -print0 | cpio --create --quiet --dereference --format newc --null -R 0:0 > ${EFW_CPIO}) || errorout
  prepend_earlyinitramfs "${EFW_CPIO}" || errorout

  cleanup
  exit 0

dracut
------
The following configuration is example that can be put under
/etc/dracut.conf.d/.

::

  compress=cat
  install_items+="/usr/lib/firmware/intel-seam/libtdx.so /usr/lib/firmware/intel-seam/libtdx.so.sigstruct /usr/lib/firmware/intel-seam/np-seamldr.acm"

References
==========
[1] Intel Trust Domain Extensions white papaer
https://software.intel.com/content/dam/develop/external/us/en/documents/tdx-whitepaper-final9-17.pdf
[2] Intel Trust Domain CPU Architectural Extensions
https://software.intel.com/content/dam/develop/external/us/en/documents-tps/intel-tdx-cpu-architectural-specification.pdf
[3] Intel Trust Domain Extensions Module(TDX module)
https://software.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1eas-v0.85.039.pdf
[4] SEAM Loader interface specification
https://software.intel.com/content/dam/develop/external/us/en/documents-tps/intel-tdx-seamldr-interface-specification.pdf
