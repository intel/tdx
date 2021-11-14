.. SPDX-License-Identifier: GPL-2.0

=====================================
Intel Trust Domain Extensions (TDX)
=====================================

Intel's Trust Domain Extensions (TDX) protects confidential guest VMs
from the host and physical attacks by isolating the guest register
state and by encrypting the guest memory. In TDX, a special TDX module
sits between the host and the guest, and runs in a special mode (SEAM)
and manages the guest/host separation.

Since the host cannot directly access guest registers or memory, much
normal functionality of a hypervisor (such as trapping MMIO, some MSRs,
some CPUIDs and some other instructions) has to be moved into the
guest. This is implemented using a Virtualization Exception (#VE) that
is handled by the kernel. The kernel then decides how to handle them,
usually by using hypercalls to initiate the needed operation on the
host.

#VE Exception:
==============

In TDX guests, #VE Exceptions are delivered to TDX guests in following
scenarios:

* Execution of certain instructions (see list below)
* Certain MSR accesses.
* CPUID usage (only for certain leafs)
* Shared memory access (including MMIO)

==== #VE (due to instruction execution) ====

Intel TDX dis-allows execution of certain instructions in non-root
mode. Execution of these instructions would lead to #VE or #GP.

Details are,

List of instructions that can cause #VE are,

* String I/O (INS, OUTS), IN, OUT
* HLT
* MONITOR, MWAIT
* WBINVD, INVD
* VMCALL

List of instructions that can cause #GP are,

* All VMX instructions: INVEPT, INVVPID, VMCLEAR, VMFUNC, VMLAUNCH,
  VMPTRLD, VMPTRST, VMREAD, VMRESUME, VMWRITE, VMXOFF, VMXON
* ENCLS, ENCLV
* GETSEC
* RSM
* ENQCMD

==== #VE (due to MSR access) ====

In TDX guest, MSR access behavior can be categorized as,

* Native supported (also called as context switched MSR)
  No special handling is required for these MSRs in TDX guest.
* #GP triggered
  Dis-allowed MSR read/write would lead to #GP.
* #VE triggered
  All MSRs that are not natively supported or dis-allowed
  (triggers #GP) will trigger #VE. To support access to
  these MSRs, it needs to be emulated using TDCALL.

For complete list of MSRs that fall under above category can be found
in Intel TDX Module Specification, sec "MSR Virtualization"

==== #VE (due to CPUID instruction) ====

#VE is triggered on CPUID leaf/sub-leaf combinations which are not part
of the CPUID virtualization table or on the request of guests for all
CPUID invocations (either from user or kernel space). Combinations of
CPUID leaf/sub-leaf which triggers #VE are configured by the VMM during
the TD initialization time (using TDH.MNG.INIT).

==== #VE on Memory Accesses ====

A TD guest is in control of whether its memory accesses are treated as
private or shared.  It selects the behavior with a bit in its page table
entries.

=== #VE on Shared Pages ===

Accesses to shared mappings can cause #VE's.  The hypervisor is in
control of when a #VE might occur, so the guest must be careful to only
reference shared pages when it is in a context that can safely handle
a #VE.

However, shared mapping content cannot be trusted since shared page
content is writable by the hypervisor.  This means that shared mappings
are never used for sensitive memory contents like stacks or kernel text.
 This means that the shared mapping property of inducing #VEs requires
essentially no special kernel handling in sensitive contexts like
syscall entry or NMIs.

=== #VE on Private Pages ===

Some accesses to private mappings may cause #VEs.  Before a mapping is
accepted (aka. in the SEPT_PENDING state), a reference would cause
a #VE.  But, after acceptance, references typically succeed.

The hypervisor can cause a private page reference to fail if it chooses
to move an accepted page to a "blocked" state.  However, if it does
this, a page access will not generate a #VE.  It will, instead, cause a
"TD Exit" where the hypervisor is required to handle the exception.

==== Linux #VE handler ====

Both user/kernel #VE exceptions are handled by the
tdx_handle_virt_exception() handler. If successfully handled,
instruction pointer is incremented to complete the handling process.
If failed to handle, it is treated as a regular exception and handled
via fixup handlers.

In TD guests, #VE nesting (a #VE triggered before handling the current
one or aka syscall gap issue) problem is handled by TDX Module ensuring
that interrupts, including NMIs, are blocked by the hardware starting
with #VE delivery until TDGETVEINFO is called and also under the
assumption that entry paths do not access TD-shared memory, MMIO
regions, or use #VE triggering MSRs, instructions, or CPUID leaves that
might generate #VE.

MMIO handling:
==============

In traditional VMs, MMIO is usually implemented by giving a guest
access to a mapping which will cause a VMEXIT on access and then the
VMM emulating the access. That's not possible in TDX guest because
VMEXIT will expose the register state to the host. TDX guests don't
trust the host and can't have its state exposed to the host.

In TDX the MMIO regions are instead configured to trigger a #VE
exception in the guest. The guest #VE handler then emulates the MMIO
instruction inside the guest and converts them into a controlled TDCALL
to the host, rather than completely exposing the state to the host.

MMIO addresses on x86 are just special physical addresses. They can be
accessed with any instruction that accesses memory. However, the
introduced instruction decoding method is limited. It is only designed
to decode instructions like those generated by io.h macros.

MMIO access via other means (like structure overlays) may result in
MMIO_DECODE_FAILED and an oops. Known offenders (like XAPIC) have been
disabled (maybe a pointer to the patch here).

Shared memory:
==============

Intel TDX doesn't allow the VMM to access guest private memory. Any
memory that is required for communication with VMM must be shared
explicitly by setting the bit in the page table entry. The shared bit
can be enumerated with TDX_GET_INFO.

After setting the shared bit, the conversion must be completed with
MapGPA hypercall. The call informs the VMM about the conversion between
private/shared mappings.

set_memory_decrypted() converts a range of pages to shared.
set_memory_encrypted() converts memory back to private.

Device drivers are the primary user of shared memory, but there's no
need in touching every driver. DMA buffers and ioremap()'ed regions are
converted to shared automatically.

TDX uses SWIOTLB for most of DMA allocations. The SWIOTLB buffer is
converted to shared on boot.

For coherent DMA allocation, the DMA buffer gets converted on the
allocation. Check force_dma_unencrypted() for details.

References
==========

More details about TDX SEAM (and its response for MSR, memory access,
IO, CPUID etc) can be found at,

https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf

More details about TDX hypercall and TDX module call ABI can be found
at,

https://www.intel.com/content/dam/develop/external/us/en/documents/intel-tdx-guest-hypervisor-communication-interface-1.0-344426-002.pdf

More details about TDVF requirements can be found at,

https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.01.pdf
