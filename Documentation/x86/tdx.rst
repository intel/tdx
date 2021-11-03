.. SPDX-License-Identifier: GPL-2.0

============================
TDX(Trust Domain Extensions)
============================

Glossary
========
Mostly citation from Intel Trust Domain Extensions Module(TDX module)
specification.

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

MCHECK
  a part of microcode update:
  MCHECK checks memory configuration is properly set.  In a multiple socket
  system, MCHECK verifies each socket's view of the memory map.  It checks each
  socket view is consistent with the other sockets in the platform.  As a part
  of verification, MCHECK checks CMRs set by BIOS and securely stores the
  information.

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

SoC
  System on Chip:
  A whole system, including cores, uncore, interconnects etc., packaged as a
  single device

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

Initializing TDX module
=======================
Overview
--------
TDX requires the TDX firmware(a.k.a the TDX module) to initialize.

Options to initialize the TDX module
====================================
kernel boot parameters
----------------------
  tdx_host: on
        enable("on")/disable(other value the TDX module at kernel boot time as
        TDX host. By default "off".


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

Limitations
===========
For code simplicity, there are several limitations.  Those are future work.

device memory
-------------
The device memory, such as pmem, is not supported.  For example, users can use
'memmap=nn[KMG]!ss[KMG]' kernel parameter to reserve memory as legacy PMEM, and
use /dev/pmem* as KVM guest memory backend.

Enumerate those memories by device-specific way or walking through memory map,
and then take care of those device memories when constructing TDMR.

memory hotplug
--------------
On x86, the memory that TDX can use must be convertible and must be covered by
TDMRs when the TDX module is configured during kernel boot.  Currently, on x86,
the kernel converts all system memory to TDX memory during kernel boot, to avoid
having to modify the page allocator to distinguish TDX and non-TDX allocation.
Once the TDX module is configured with TDMRs, the memory that TDX can use is
fixed during the TDX module's life cycle, and new memory cannot be added.  This
means TDX doesn't support memory hotplug after it is enabled.

Therefore, the ACPI memory hotplug needs to be disabled, and the driver-managed
memory too (i.e. kmem-hot-added PMEM should be disabled too).  However, one
exception is, for x86 legacy PMEM reserved by 'memmap=nn!ss' kernel parameter,
if it was included in TDMRs during kernel boot (underneath x86 legacy PMEM is
still memory), it can be kmem-added again as system memory.  This case should
not be rejected.

CPU hotplug
-----------
Because TDX (TDX module specification 344425-002US [1]) doesn't support CPU
hotplug.  If the TDX module has been ever initialized, prohibit CPU hotplug.
Note that it's allowed to logically turn on/off(online/offline) CPUs.

Per CPU package configuration
-----------------------------
Encryption key configuration is per memory controller operation.  It means all
CPU packages must be configured.  Otherwise, TDX operations depending on it,
such as creating TDX guests, fail.  At least one CPU from the CPU package must
be kept online.
