.. SPDX-License-Identifier: GPL-2.0

=====================================
Intel Trust Domain Extensions (TDX)
=====================================

Intel's Trust Domain Extensions (TDX) protect confidential guest VMs from
the host and physical attacks by isolating the guest register state and by
encrypting the guest memory. In TDX, a special module running in a special
mode sits between the host and the guest and manages the guest/host
separation.

TDX Host Kernel Support
=======================

TDX introduces a new CPU mode called Secure Arbitration Mode (SEAM) and
a new isolated range pointed by the SEAM Ranger Register (SEAMRR).  A
CPU-attested software module called 'the TDX module' runs inside the new
isolated range to provide the functionalities to manage and run protected
VMs.

TDX also leverages Intel Multi-Key Total Memory Encryption (MKTME) to
provide crypto-protection to the VMs.  TDX reserves part of MKTME KeyIDs
as TDX private KeyIDs, which are only accessible within the SEAM mode.
BIOS is responsible for partitioning legacy MKTME KeyIDs and TDX KeyIDs.

Before the TDX module can be used to create and run protected VMs, it
must be loaded into the isolated range and properly initialized.  The TDX
architecture doesn't require the BIOS to load the TDX module, but the
kernel assumes it is loaded by the BIOS.

TDX boot-time detection
-----------------------

The kernel detects TDX by detecting TDX private KeyIDs during kernel
boot.  Below dmesg shows when TDX is enabled by BIOS::

  [..] tdx: BIOS enabled: private KeyID range: [16, 64).

TDX module detection and initialization
---------------------------------------

There is no CPUID or MSR to detect the TDX module.  The kernel detects it
by initializing it.

The kernel talks to the TDX module via the new SEAMCALL instruction.  The
TDX module implements SEAMCALL leaf functions to allow the kernel to
initialize it.

Initializing the TDX module consumes roughly ~1/256th system RAM size to
use it as 'metadata' for the TDX memory.  It also takes additional CPU
time to initialize those metadata along with the TDX module itself.  Both
are not trivial.  The kernel initializes the TDX module at runtime on
demand.  The caller to call tdx_enable() to initialize the TDX module::

        ret = tdx_enable();
        if (ret)
                goto no_tdx;
        // TDX is ready to use

One step of initializing the TDX module requires at least one online cpu
for each package.  The caller needs to guarantee this otherwise the
initialization will fail.

Making SEAMCALL requires the CPU already being in VMX operation (VMXON
has been done).  For now tdx_enable() doesn't handle VMXON internally,
but depends on the caller to guarantee that.  So far only KVM calls
tdx_enable() and KVM already handles VMXON.

User can consult dmesg to see the presence of the TDX module, and whether
it has been initialized.

If the TDX module is not loaded, dmesg shows below::

  [..] tdx: TDX module is not loaded.

If the TDX module is initialized successfully, dmesg shows something
like below::

  [..] tdx: TDX module: attributes 0x0, vendor_id 0x8086, major_version 1, minor_version 0, build_date 20211209, build_num 160
  [..] tdx: 65667 pages allocated for PAMT.
  [..] tdx: TDX module initialized.

If the TDX module failed to initialize, dmesg also shows it failed to
initialize::

  [..] tdx: initialization failed ...

TDX Interaction to Other Kernel Components
------------------------------------------

TDX Memory Policy
~~~~~~~~~~~~~~~~~

TDX reports a list of "Convertible Memory Region" (CMR) to tell the
kernel which memory is TDX compatible.  The kernel needs to build a list
of memory regions (out of CMRs) as "TDX-usable" memory and pass those
regions to the TDX module.  Once this is done, those "TDX-usable" memory
regions are fixed during module's lifetime.

To keep things simple, currently the kernel simply guarantees all pages
in the page allocator are TDX memory.  Specifically, the kernel uses all
system memory in the core-mm at the time of initializing the TDX module
as TDX memory, and in the meantime, refuses to online any non-TDX-memory
in the memory hotplug.

This can be enhanced in the future, i.e. by allowing adding non-TDX
memory to a separate NUMA node.  In this case, the "TDX-capable" nodes
and the "non-TDX-capable" nodes can co-exist, but the kernel/userspace
needs to guarantee memory pages for TDX guests are always allocated from
the "TDX-capable" nodes.

Physical Memory Hotplug
~~~~~~~~~~~~~~~~~~~~~~~

Note TDX assumes convertible memory is always physically present during
machine's runtime.  A non-buggy BIOS should never support hot-removal of
any convertible memory.  This implementation doesn't handle ACPI memory
removal but depends on the BIOS to behave correctly.

CPU Hotplug
~~~~~~~~~~~

TDX doesn't support physical (ACPI) CPU hotplug.  During machine boot,
TDX verifies all boot-time present logical CPUs are TDX compatible before
enabling TDX.  A non-buggy BIOS should never support hot-add/removal of
physical CPU.  Currently the kernel doesn't handle physical CPU hotplug,
but depends on the BIOS to behave correctly.

Note TDX works with CPU logical online/offline, thus the kernel still
allows to offline logical CPU and online it again.

Kexec()
~~~~~~~

There are two problems in terms of using kexec() to boot to a new kernel
when the old kernel has enabled TDX: 1) Part of the memory pages are
still TDX private pages (i.e. metadata used by the TDX module, and any
TDX guest memory if kexec() is executed when there's live TDX guests).
2) There might be dirty cachelines associated with TDX private pages.

Because the hardware doesn't guarantee cache coherency among different
KeyIDs, the old kernel needs to flush cache (of TDX private pages)
before booting to the new kernel.  Also, the kernel doesn't convert all
TDX private pages back to normal because of below considerations:

1) Neither the kernel nor the TDX module has existing infrastructure to
   track which pages are TDX private page.
2) The number of TDX private pages can be large, and converting all of
   them (cache flush + using MOVDIR64B to clear the page) can be time
   consuming.
3) The new kernel will almost only use KeyID 0 to access memory.  KeyID
   0 doesn't support integrity-check, so it's OK.
4) The kernel doesn't (and may never) support MKTME.  If any 3rd party
   kernel ever supports MKTME, it can/should do MOVDIR64B to clear the
   page with the new MKTME KeyID (just like TDX does) before using it.

TDX Guest Support
=================
Since the host cannot directly access guest registers or memory, much
normal functionality of a hypervisor must be moved into the guest. This is
implemented using a Virtualization Exception (#VE) that is handled by the
guest kernel. A #VE is handled entirely inside the guest kernel, but some
require the hypervisor to be consulted.

TDX includes new hypercall-like mechanisms for communicating from the
guest to the hypervisor or the TDX module.

New TDX Exceptions
------------------

TDX guests behave differently from bare-metal and traditional VMX guests.
In TDX guests, otherwise normal instructions or memory accesses can cause
#VE or #GP exceptions.

Instructions marked with an '*' conditionally cause exceptions.  The
details for these instructions are discussed below.

Instruction-based #VE
~~~~~~~~~~~~~~~~~~~~~

- Port I/O (INS, OUTS, IN, OUT)
- HLT
- MONITOR, MWAIT
- WBINVD, INVD
- VMCALL
- RDMSR*,WRMSR*
- CPUID*

Instruction-based #GP
~~~~~~~~~~~~~~~~~~~~~

- All VMX instructions: INVEPT, INVVPID, VMCLEAR, VMFUNC, VMLAUNCH,
  VMPTRLD, VMPTRST, VMREAD, VMRESUME, VMWRITE, VMXOFF, VMXON
- ENCLS, ENCLU
- GETSEC
- RSM
- ENQCMD
- RDMSR*,WRMSR*

RDMSR/WRMSR Behavior
~~~~~~~~~~~~~~~~~~~~

MSR access behavior falls into three categories:

- #GP generated
- #VE generated
- "Just works"

In general, the #GP MSRs should not be used in guests.  Their use likely
indicates a bug in the guest.  The guest may try to handle the #GP with a
hypercall but it is unlikely to succeed.

The #VE MSRs are typically able to be handled by the hypervisor.  Guests
can make a hypercall to the hypervisor to handle the #VE.

The "just works" MSRs do not need any special guest handling.  They might
be implemented by directly passing through the MSR to the hardware or by
trapping and handling in the TDX module.  Other than possibly being slow,
these MSRs appear to function just as they would on bare metal.

CPUID Behavior
~~~~~~~~~~~~~~

For some CPUID leaves and sub-leaves, the virtualized bit fields of CPUID
return values (in guest EAX/EBX/ECX/EDX) are configurable by the
hypervisor. For such cases, the Intel TDX module architecture defines two
virtualization types:

- Bit fields for which the hypervisor controls the value seen by the guest
  TD.

- Bit fields for which the hypervisor configures the value such that the
  guest TD either sees their native value or a value of 0.  For these bit
  fields, the hypervisor can mask off the native values, but it can not
  turn *on* values.

A #VE is generated for CPUID leaves and sub-leaves that the TDX module does
not know how to handle. The guest kernel may ask the hypervisor for the
value with a hypercall.

#VE on Memory Accesses
----------------------

There are essentially two classes of TDX memory: private and shared.
Private memory receives full TDX protections.  Its content is protected
against access from the hypervisor.  Shared memory is expected to be
shared between guest and hypervisor and does not receive full TDX
protections.

A TD guest is in control of whether its memory accesses are treated as
private or shared.  It selects the behavior with a bit in its page table
entries.  This helps ensure that a guest does not place sensitive
information in shared memory, exposing it to the untrusted hypervisor.

#VE on Shared Memory
~~~~~~~~~~~~~~~~~~~~

Access to shared mappings can cause a #VE.  The hypervisor ultimately
controls whether a shared memory access causes a #VE, so the guest must be
careful to only reference shared pages it can safely handle a #VE.  For
instance, the guest should be careful not to access shared memory in the
#VE handler before it reads the #VE info structure (TDG.VP.VEINFO.GET).

Shared mapping content is entirely controlled by the hypervisor. The guest
should only use shared mappings for communicating with the hypervisor.
Shared mappings must never be used for sensitive memory content like kernel
stacks.  A good rule of thumb is that hypervisor-shared memory should be
treated the same as memory mapped to userspace.  Both the hypervisor and
userspace are completely untrusted.

MMIO for virtual devices is implemented as shared memory.  The guest must
be careful not to access device MMIO regions unless it is also prepared to
handle a #VE.

#VE on Private Pages
~~~~~~~~~~~~~~~~~~~~

An access to private mappings can also cause a #VE.  Since all kernel
memory is also private memory, the kernel might theoretically need to
handle a #VE on arbitrary kernel memory accesses.  This is not feasible, so
TDX guests ensure that all guest memory has been "accepted" before memory
is used by the kernel.

A modest amount of memory (typically 512M) is pre-accepted by the firmware
before the kernel runs to ensure that the kernel can start up without
being subjected to a #VE.

The hypervisor is permitted to unilaterally move accepted pages to a
"blocked" state. However, if it does this, page access will not generate a
#VE.  It will, instead, cause a "TD Exit" where the hypervisor is required
to handle the exception.

Linux #VE handler
-----------------

Just like page faults or #GP's, #VE exceptions can be either handled or be
fatal.  Typically, an unhandled userspace #VE results in a SIGSEGV.
An unhandled kernel #VE results in an oops.

Handling nested exceptions on x86 is typically nasty business.  A #VE
could be interrupted by an NMI which triggers another #VE and hilarity
ensues.  The TDX #VE architecture anticipated this scenario and includes a
feature to make it slightly less nasty.

During #VE handling, the TDX module ensures that all interrupts (including
NMIs) are blocked.  The block remains in place until the guest makes a
TDG.VP.VEINFO.GET TDCALL.  This allows the guest to control when interrupts
or a new #VE can be delivered.

However, the guest kernel must still be careful to avoid potential
#VE-triggering actions (discussed above) while this block is in place.
While the block is in place, any #VE is elevated to a double fault (#DF)
which is not recoverable.

MMIO handling
-------------

In non-TDX VMs, MMIO is usually implemented by giving a guest access to a
mapping which will cause a VMEXIT on access, and then the hypervisor
emulates the access.  That is not possible in TDX guests because VMEXIT
will expose the register state to the host. TDX guests don't trust the host
and can't have their state exposed to the host.

In TDX, MMIO regions typically trigger a #VE exception in the guest.  The
guest #VE handler then emulates the MMIO instruction inside the guest and
converts it into a controlled TDCALL to the host, rather than exposing
guest state to the host.

MMIO addresses on x86 are just special physical addresses. They can
theoretically be accessed with any instruction that accesses memory.
However, the kernel instruction decoding method is limited. It is only
designed to decode instructions like those generated by io.h macros.

MMIO access via other means (like structure overlays) may result in an
oops.

Shared Memory Conversions
-------------------------

All TDX guest memory starts out as private at boot.  This memory can not
be accessed by the hypervisor.  However, some kernel users like device
drivers might have a need to share data with the hypervisor.  To do this,
memory must be converted between shared and private.  This can be
accomplished using some existing memory encryption helpers:

 * set_memory_decrypted() converts a range of pages to shared.
 * set_memory_encrypted() converts memory back to private.

Device drivers are the primary user of shared memory, but there's no need
to touch every driver. DMA buffers and ioremap() do the conversions
automatically.

TDX uses SWIOTLB for most DMA allocations. The SWIOTLB buffer is
converted to shared on boot.

For coherent DMA allocation, the DMA buffer gets converted on the
allocation. Check force_dma_unencrypted() for details.

Attestation
===========

Attestation is used to verify the TDX guest trustworthiness to other
entities before provisioning secrets to the guest. For example, a key
server may want to use attestation to verify that the guest is the
desired one before releasing the encryption keys to mount the encrypted
rootfs or a secondary drive.

The TDX module records the state of the TDX guest in various stages of
the guest boot process using the build time measurement register (MRTD)
and runtime measurement registers (RTMR). Measurements related to the
guest initial configuration and firmware image are recorded in the MRTD
register. Measurements related to initial state, kernel image, firmware
image, command line options, initrd, ACPI tables, etc are recorded in
RTMR registers. For more details, as an example, please refer to TDX
Virtual Firmware design specification, section titled "TD Measurement".
At TDX guest runtime, the attestation process is used to attest to these
measurements.

The attestation process consists of two steps: TDREPORT generation and
Quote generation.

TDX guest uses TDCALL[TDG.MR.REPORT] to get the TDREPORT (TDREPORT_STRUCT)
from the TDX module. TDREPORT is a fixed-size data structure generated by
the TDX module which contains guest-specific information (such as build
and boot measurements), platform security version, and the MAC to protect
the integrity of the TDREPORT. A user-provided 64-Byte REPORTDATA is used
as input and included in the TDREPORT. Typically it can be some nonce
provided by attestation service so the TDREPORT can be verified uniquely.
More details about the TDREPORT can be found in Intel TDX Module
specification, section titled "TDG.MR.REPORT Leaf".

After getting the TDREPORT, the second step of the attestation process
is to send it to the Quoting Enclave (QE) to generate the Quote. TDREPORT
by design can only be verified on the local platform as the MAC key is
bound to the platform. To support remote verification of the TDREPORT,
TDX leverages Intel SGX Quoting Enclave to verify the TDREPORT locally
and convert it to a remotely verifiable Quote. Method of sending TDREPORT
to QE is implementation specific. Attestation software can choose
whatever communication channel available (i.e. vsock or TCP/IP) to
send the TDREPORT to QE and receive the Quote.

References
==========

TDX reference material is collected here:

https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html
