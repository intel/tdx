.. SPDX-License-Identifier: GPL-2.0

=========================================================
Intel Trusted Domain Extensions (TDX) host kernel support
=========================================================

Intel Trusted Domain Extensions (TDX) protects guest VMs from malicious
host and certain physical attacks. To support TDX, a new CPU mode called
Secure Arbitration Mode (SEAM) is added to Intel processors.

SEAM is an extension to the VMX architecture to define a new VMX root
operation called 'SEAM VMX root' and a new VMX non-root operation called
'VMX non-root'. Collectively, the SEAM VMX root and SEAM VMX non-root
execution modes are called operation in SEAM.

SEAM VMX root operation is designed to host a CPU-attested, software
module called 'Intel TDX module' to manage virtual machine (VM) guests
called Trust Domains (TD). The TDX module implements the functions to
build, tear down, and start execution of TD VMs. SEAM VMX root is also
designed to additionally host a CPU-attested, software module called the
'Intel Persistent SEAMLDR (Intel P-SEAMLDR)' module to load and update
the Intel TDX module.

The software in SEAM VMX root runs in the memory region defined by the
SEAM range register (SEAMRR). Access to this range is restricted to SEAM
VMX root operation. Code fetches outside of SEAMRR when in SEAM VMX root
operation are meant to be disallowed and lead to an unbreakable shutdown.

TDX leverages Intel Multi-Key Total Memory Encryption (MKTME) to crypto
protect TD guests. TDX reserves part of MKTME KeyID space as TDX private
KeyIDs, which can only be used by software runs in SEAM. The physical
address bits reserved for encoding TDX private KeyID are treated as
reserved bits when not in SEAM operation. The partitioning of MKTME
KeyIDs and TDX private KeyIDs is configured by BIOS.

Host kernel transits to either P-SEAMLDR or TDX module via the new
SEAMCALL instruction. SEAMCALLs are host-side interface functions
defined by P-SEAMLDR and TDX module around the new SEAMCALL instruction.
They are similar to a hypercall, except they are made by host kernel to
the SEAM software modules.

Before being able to manage TD guests, the TDX module must be loaded
into SEAMRR and properly initialized using SEAMCALLs defined by TDX
architecture. The current implementation assumes both P-SEAMLDR and
TDX module are loaded by BIOS before the kernel boots.

Detection and Initialization
----------------------------

The presence of SEAMRR is reported via a new SEAMRR bit (15) of the
IA32_MTRRCAP MSR. The SEAMRR range registers consist of a pair of MSRs:
IA32_SEAMRR_PHYS_BASE (0x1400) and IA32_SEAMRR_PHYS_MASK (0x1401).
SEAMRR is enabled when bit 3 of IA32_SEAMRR_PHYS_BASE is set and
bit 10/11 of IA32_SEAMRR_PHYS_MASK are set.

However, there is no CPUID or MSR for querying the presence of the TDX
module or the P-SEAMLDR. SEAMCALL fails with VMfailInvalid when SEAM
software is not loaded, so SEAMCALL can be used to detect P-SEAMLDR and
TDX module. SEAMLDR.INFO SEAMCALL is used to detect both P-SEAMLDR and
TDX module.  Success of the SEAMCALL means P-SEAMLDR is loaded, and the
P-SEAMLDR information returned by the SEAMCALL further tells whether TDX
module is loaded or not.

User can check whether the TDX module is initialized via dmesg:

  [..] tdx: P-SEAMLDR: version 0x0, vendor_id: 0x8086, build_date: 20211209, build_num 160, major 1, minor 0
  [..] tdx: TDX module detected.
  [..] tdx: TDX module: vendor_id 0x8086, major_version 1, minor_version 0, build_date 20211209, build_num 160
  [..] tdx: TDX module initialized.

Initializing TDX takes time (in seconds) and additional memory space (for
metadata). Both are affected by the size of total usable memory which the
TDX module is configured with. In particular, the TDX metadata consumes
~1/256 of TDX usable memory. This leads to a non-negligible burden as the
current implementation simply treats all E820 RAM ranges as TDX usable
memory (all system RAM meets the security requirements on the first
generation of TDX-capable platforms).

Therefore, kernel uses lazy TDX initialization to avoid such burden for
all users on a TDX-capable platform. The software component (e.g. KVM)
which wants to use TDX is expected to call two helpers below to detect
and initialize the TDX module until TDX is truly needed:

        if (tdx_detect())
                goto no_tdx;
        if (tdx_init())
                goto no_tdx;

TDX detection and initialization are done via SEAMCALLs which require the
CPU in VMX operation. The caller of the above two helpers should ensure
that condition.

Currently, only KVM is the only user of TDX and KVM already handles
entering/leaving VMX operation. Letting KVM initialize TDX on demand
avoids handling entering/leaving VMX operation, which isn't trivial, in
core-kernel.

In addition, a new kernel parameter 'tdx_host={on/off}' can be used to
force disabling the TDX capability by the admin.

TDX Memory Management
---------------------

TDX architecture manages TDX memory via below data structures:

1) Convertible Memory Regions (CMRs)

TDX provides increased levels of memory confidentiality and integrity.
This requires special hardware support for features like memory
encryption and storage of memory integrity checksums. A CMR represents a
memory range that meets those requirements and can be used as TDX memory.
The list of CMRs can be queried from TDX module.

2) TD Memory Regions (TDMRs)

The TDX module manages TDX usable memory via TD Memory Regions (TDMR).
Each TDMR has information of its base and size, its metadata (PAMT)'s
base and size, and an array of reserved areas to hold the memory region
address holes and PAMTs. TDMR must be 1G aligned and in 1G granularity.

Host kernel is responsible for choosing which convertible memory regions
(reside in CMRs) to use as TDX memory, and constructing a list of TDMRs
to cover all those memory regions, and configure the TDMRs to TDX module.

3) Physical Address Metadata Tables (PAMTs)

This metadata essentially serves as the 'struct page' for the TDX module,
recording things like which TD guest 'owns' a given page of memory. Each
TDMR has a dedicated PAMT.

PAMT is not reserved by the hardware upfront and must be allocated by the
kernel and given to the TDX module. PAMT for a given TDMR doesn't have
to be within that TDMR, but a PAMT must be within one CMR.  Additionally,
if a PAMT overlaps with a TDMR, the overlapping part must be marked as
reserved in that particular TDMR.

Kernel Policy of TDX Memory
---------------------------

The first generation of TDX essentially guarantees that all system RAM
memory regions (excluding the memory below 1MB) are covered by CMRs.
Currently, to avoid having to modify the page allocator to support both
TDX and non-TDX allocation, the kernel choose to use all system RAM as
TDX memory. A list of TDMRs are constructed based on all RAM entries in
e820 table and configured to the TDX module.

Limitations
-----------

1. Constructing TDMRs

Currently, the kernel tries to create one TDMR for each RAM entry in
e820. 'e820_table' is used to find all RAM entries to honor 'mem' and
'memmap' kernel command line. However, 'memmap' command line may also
result in many discrete RAM entries. TDX architecturally only supports a
limited number of TDMRs (currently 64). In this case, constructing TDMRs
may fail due to exceeding the maximum number of TDMRs. The user is
responsible for not doing so otherwise TDX may not be available. This
can be further enhanced by supporting merging adjacent TDMRs.

2. PAMT allocation

Currently, the kernel allocates PAMT for each TDMR separately using
alloc_contig_pages(). alloc_contig_pages() only guarantees the PAMT is
allocated from a given NUMA node, but doesn't have control over
allocating PAMT from a given TDMR range. This may result in all PAMTs
on one NUMA node being within one single TDMR. PAMTs overlapping with
a given TDMR must be put into the TDMR's reserved areas too. However TDX
only supports a limited number of reserved areas per TDMR (currently 16),
thus too many PAMTs in one NUMA node may result in constructing TDMR
failure due to exceeding TDMR's maximum reserved areas.

The user is responsible for not creating too many discrete RAM entries
on one NUMA node, which may result in having too many TDMRs on one node,
which eventually results in constructing TDMR failure due to exceeding
the maximum reserved areas. This can be further enhanced to support
per-NUMA-node PAMT allocation, which could reduce the number of PAMT to
1 for each node.

3. TDMR initialization

Currently, the kernel initialize TDMRs one by one. This may take couple
of seconds to finish on large memory systems (TBs). This can be further
enhanced by allowing initializing different TDMRs in parallel on multiple
cpus.

4. CPU hotplug

The first generation of TDX architecturally doesn't support ACPI CPU
hotplug. All logical cpus are enabled by BIOS in MADT table. Also, the
first generation of TDX-capable platforms don't support ACPI CPU hotplug
either. Since this physically cannot happen, currently kernel doesn't
have any check in ACPI CPU hotplug code path to disable it.

Also, only TDX module initialization requires all BIOS-enabled cpus are
online. After the initialization, any logical cpu can be brought down
and brought up to online again later. Therefore this series doesn't
change logical CPU hotplug either.

This can be enhanced when any future generation of TDX starts to support
ACPI cpu hotplug.

5. Memory hotplug

The first generation of TDX architecturally doesn't support memory
hotplug. The CMRs are generated by BIOS during boot and it is fixed
during machine's runtime.

However, the first generation of TDX-capable platforms don't support ACPI
memory hotplug. Since it physically cannot happen, currently kernel
doesn't have any check in ACPI memory hotplug code path to disable it.

A special case of memory hotplug is adding NVDIMM as system RAM using
kmem driver. However the first generation of TDX-capable platforms
cannot turn on TDX and NVDIMM simultaneously, so in practice this cannot
happen either.

Another case is admin can use 'memmap' kernel command line to create
legacy PMEMs and use them as TD guest memory, or theoretically, can use
kmem driver to add them as system RAM. Current implementation always
includes legacy PMEMs when constructing TDMRs so they are also TDX memory.
So legacy PMEMs can either be used as TD guest memory directly or can be
converted to system RAM via kmem driver.

This can be enhanced when future generation of TDX starts to support ACPI
memory hotplug, or NVDIMM and TDX can be enabled simultaneously on the
same platform.

6. Online CPUs

TDX initialization includes a step where certain SEAMCALL must be called
on every BIOS-enabled CPU (with a ACPI MADT entry marked as enabled).
Otherwise, the initialization process aborts at a later step.

The user should avoid using boot parameters (such as maxcpus, nr_cpus,
possible_cpus) or offlining CPUs before initializing TDX. Doing so will
lead to the mismatch between online CPUs and BIOS-enabled CPUs, resulting
TDX module initialization failure.

It is ok to offline CPUs after TDX initialization is completed.

7. Kexec

The TDX module can be initialized only once during its lifetime. The
first generation of TDX doesn't have interface to reset TDX module to
uninitialized state so it can be initialized again.

This implies:

  - If the old kernel fails to initialize TDX, the new kernel cannot
    use TDX too unless the new kernel fixes the bug which leads to
    initialization failure in the old kernel and can resume from where
    the old kernel stops. This requires certain coordination between
    the two kernels.

  - If the old kernel has initialized TDX successfully, the new kernel
    may be able to use TDX if the two kernels have exactly the same
    configurations on the TDX module. It further requires the new kernel
    to reserve the TDX metadata pages (allocated by the old kernel) in
    its page allocator. It also requires coordination between the two
    kernels. Furthermore, if kexec() is done when there are active TD
    guests running, the new kernel cannot use TDX because it's extremely
    hard for the old kernel to pass all TDX private pages to the new
    kernel.

Given that, the current implementation doesn't support TDX after kexec()
(except the old kernel hasn't initialized TDX at all).

The current implementation doesn't shut down TDX module but leaves it
open during kexec().  This is because shutting down TDX module requires
CPU being in VMX operation but there's no guarantee of this during
kexec(). Leaving the TDX module open is not the best case, but it is OK
since the new kernel won't be able to use TDX anyway (therefore TDX
module won't run at all).

This can be further enhanced when core-kernele (non-KVM) can handle
VMXON.

If TDX is ever enabled and/or used to run any TD guests, the cachelines
of TDX private memory, including PAMTs, used by TDX module need to be
flushed before transiting to the new kernel otherwise they may silently
corrupt the new kernel. Similar to SME, the current implementation
flushes cache in stop_this_cpu().

8. Initialization error

Currently, any error happened during TDX initialization moves the TDX
module to the SHUTDOWN state. No SEAMCALL is allowed in this state, and
the TDX module cannot be re-initialized without a hard reset.

This can be further enhanced to treat some errors as recoverable errors
and let the caller retry later. A more detailed state machine can be
added to record the internal state of TDX module, and the initialization
can resume from that state in the next try.

Specifically, there are three cases that can be treated as recoverable
error: 1) -ENOMEM (i.e. due to PAMT allocation); 2) TDH.SYS.CONFIG error
due to TDH.SYS.LP.INIT is not called on all cpus (i.e. due to offline
cpus); 3) -EPERM when the caller doesn't guarantee all cpus are in VMX
operation.
