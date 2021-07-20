.. SPDX-License-Identifier: GPL-2.0

============================
TDX(Trust Domain Extensions)
============================

Glossary
========
Citation from Intel Trust Domain Extensions Module(TDX module) specification.

ACM
  Authenticated Code Module:
  A code module that is designed to be loaded, verified, and executed by the CPU
  in on-chip memory(CRAM).

CMR
  Convertible Memory Range:
  A range of physical memory configured by BIOS and verified by MCHECK. MCHECK
  verification is intended to help ensure that a CMR may be used to hold TDX
  memory pages encrypted with a private HKID.

HKID
  Host Key ID:
  When MKTME is activated, HKID is a key identifier for an encryption key used
  by one or more memory controllers on the platform.

MKTME
  Multi-Key TME:
  This SoC capability adds support to the TME to allow software to use one or
  more separate keys for encryption of volatile or persistent memory
  encryption. When used with TDX, it can provide confidentiality via separate
  keys for memory used by TDs. MKTME can be used with and without TDX
  extensions.

SEAMLDR
  SEAM Loader:
  An ACM intended to load the Intel TDX module.

NP-SEAMLDR
  Non-Persistent SEAM Loader

P-SEAMLDR
  Persistent SEAM Loader

PAMT
  Physical Address Metadata Table:
  An internal, hidden data structure used by the Intel TDX module, which is
  intended to hold the metadata of physical pages.

SEAM
  Secure Arbitration Mode:
  Intel CPU Instruction Set Architecture (ISA) extensions that support the Intel
  TDX module: an isolated software module that facilitates the operation and
  management of Trust Domains.

TD
  Trust Domain:
  Trust Domains (TDs) are designed to be hardware isolated Virtual Machines
  (VMs) deployed using Intel Trust Domain Extensions (Intel TDX).

TDMR
  Trust Domain Memory Range:
  A range of memory, configured by the host VMM, that is covered by PAMT and is
  intended to hold TD private memory and TD control structures.

TDX
  Trust Domain Extensions:
  An architecture, based on the TDX Instruction Set Architecture (ISA)
  extensions and the Intel TDX module, which supports operation and management
  of Trust Domains.

TME
  Total Memory Encryption:
  A memory encryption/decryption engine using an ephemeral platform key designed
  to encrypt memory contents exposed externally from the SoC.

Loading TDX module
==================
Overview
--------
TDX requires the TDX firmware(a.k.a the TDX module) to load and initialize. the
loading process composed of the two steps The first TDX firmware loader(a.k.a
Non-Persistent SEAM Loader or NP-SEAMLDR) loads the second firmware loader(
Persistent SEAM Loader or P-SEAMLDR). and then P-SEAMLDR loads the TDX module
and verify the authenticity and the integrity of the TDX module with the
signature file of the TDX module.

Options to load the P-SEAMLDR and the TDX module
================================================
kernel boot parameters
----------------------
  tdx_host: on
        enable("on")/disable(other value the TDX module at kernel boot time as
        TDX host. By default "off".

  np_seamldr:
        path for np-seamloadr to launch.  By default
        "intel-seam/np-seamldr.acm".
        The kernel searches for <filename> in built-in firmware. If it failed, it
        seaches for lib/firmware/<filrname> in initrd.

  tdx_module:
        path for the TDX module to load.  By default "intel-seam/libtdx.so".
        The kernel searches for <file> in built-in firmware. If it failed, it
        seaches for lib/firmware/<filrname> in initrd.

  tdx_sigstruct:
        path for sigstruct for the TDX module. By default
        "intel-seam/libtdx.so.sigstruct".
        The kernel searches for <file> in built-in firmware. If it failed, it
        seaches for lib/firmware/<filrname> in initrd.

Sysfs ABI
=========
Please refer to
<file:Documentation/ABI/testing/sysfs-firmware-p_seamldr> and
<file:Documentation/ABI/testing/sysfs-firmware-tdx_module>.

Debugging loading the P-SEAMLDR and the TDX module
==================================================
boot-time trace
---------------
There are tracepoints to record SEAMCALL entry and exit.  (seam:seamcall_entry,
seam:seamcall_exit function events).  Enable ftrace and boot time tracing, and
update kernel command line to enable boot time tracepoint. An example kernel
command line looks like "trace_event=seam:*".  For details, please refer to
<fileDocumentation/trace/boottime-trace.rst>

After booting, the trace can be retrieved by
"cat /sys/kernel/debug/tracing/trace"::

        # tracer: nop
        #
        # entries-in-buffer/entries-written: 66450/66450   #P:224
        #
        #                                _-----=> irqs-off
        #                               / _----=> need-resched
        #                              | / _---=> hardirq/softirq
        #                              || / _--=> preempt-depth
        #                              ||| /     delay
        #           TASK-PID     CPU#  ||||   TIMESTAMP  FUNCTION
        #              | |         |   ||||      |         |
               swapper/0-1       [000] ...1    14.819509: seamcall_enter: op: SEAMLDR_INFO 1081185000 0 0 0 0 0
               swapper/0-1       [000] .N.1    14.847999: seamcall_exit: op: SEAMLDR_INFO err: TDX_SUCCESS(0) 1081185000 0 0 0 ffffffffb9e7ba67 fffffbfff73cf74c
                  <idle>-0       [000] dN.2    85.565879: seamcall_enter: op: SEAMLDR_INSTALL 10a7c67000 0 0 0 0 0
                  <idle>-0       [000] dN.2    85.594079: seamcall_exit: op: SEAMLDR_INSTALL err: TDX_SUCCESS(0) 10a7c67000 0 0 0 ffffffffb9e7ba67 fffffbfff73cf74c
                  <idle>-0       [001] dN.2    85.594088: seamcall_enter: op: SEAMLDR_INSTALL 10a7c67000 0 0 0 0 0
                  <idle>-0       [001] dN.2    85.622382: seamcall_exit: op: SEAMLDR_INSTALL err: TDX_SUCCESS(0) 10a7c67000 0 0 0 ffffffffb9e7ba67 fffffbfff73cf74c
                  <idle>-0       [002] dN.2    85.622389: seamcall_enter: op: SEAMLDR_INSTALL 10a7c67000 0 0 0 0 0
                ...
                  <idle>-0       [223] dN.2    92.096809: seamcall_enter: op: SEAMLDR_INSTALL 10a7c67000 0 0 0 0 0
                  <idle>-0       [223] dN.2    92.140551: seamcall_exit: op: SEAMLDR_INSTALL err: TDX_SUCCESS(0) 10a7c67000 0 0 0 ffffffffb9e7ba7f fffffbfff73cf74f
               swapper/0-1       [019] .N.2    92.140556: seamcall_enter: op: TDH_SYS_INIT 0 0 0 0 0 0
               swapper/0-1       [019] .N.2    92.166347: seamcall_exit: op: TDH_SYS_INIT err: TDX_SUCCESS(0) 0 0 0 0 0 fffffbfff73cf74c
               swapper/0-1       [019] .N.2    92.166348: seamcall_enter: op: TDH_SYS_LP_INIT 0 0 0 0 0 0
               swapper/0-1       [019] .N.2    92.191947: seamcall_exit: op: TDH_SYS_LP_INIT err: TDX_SUCCESS(0) 0 0 0 0 ffffffffb9e7ba67 fffffbfff73cf74c
               swapper/0-1       [019] .N.2    92.191948: seamcall_enter: op: TDH_SYS_INFO 133cd1000 400 133c9c400 20 0 0
               swapper/0-1       [019] .N.2    92.217539: seamcall_exit: op: TDH_SYS_INFO err: TDX_SUCCESS(0) 133cd1000 400 133c9c400 20 ffffffffb9e7ba67 fffffbfff73cf74c
               swapper/0-1       [031] d..2    92.344016: seamcall_enter: op: TDH_SYS_LP_INIT 0 0 0 0 0 0
                  <idle>-0       [006] d.h2    92.344018: seamcall_enter: op: TDH_SYS_LP_INIT 0 0 0 0 0 0

run-time trace
--------------
For run-time recording of trace event, there are several front end tool for
trace.  Record seam event (or seam:seamcall_entry or seam:seamcall_exit).  Here
is the example of trace-cmd::

  # record seam:* events. (both seamcall enter/exit events.)
  $ trace-cmd record -e seam
  <Ctrl^C>
  $ trace-cmd report

  # to record only seamcall enter event.
  $ trace-cmd record -e seam:seamcall_enter

  # to record only seamcall exit event.
  $ trace-cmd record -e seam:seamcall_exit


Early load of the NP-SEAMLDR and the TDX module
===============================================
If TDX is enabled(CONFIG_INTEL_TDX_HOST=y), a kernel can load the TDX module
from initrd.  The related files (np-seamldr.acm, libtdx.so and
libtdx.so.sigstruct) need to be stored in initrd(or compiled as built-in
firmware).  Here's an example of how to customize the preparation of an initrd.
Please note that it heavily depends on the distro how to prepare initrd.


initramfs-tools
---------------
The following script is a sample hook script for initramfs-tools.  Typically It
can be placed under /etc/initramfs-tools/hooks/.  TDXSEAM_SRCDIR is the
directory in the host file system to store files related to the TDX module.

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

  verbose "copying tdx module into early initramfs..."
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
The following configuration is an example that can be put under
/etc/dracut.conf.d/.

::

  compress=cat
  install_items+="/lib/firmware/intel-seam/libtdx.so /lib/firmware/intel-seam/libtdx.so.sigstruct /lib/firmware/intel-seam/np-seamldr.acm"
