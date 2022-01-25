.. SPDX-License-Identifier: GPL-2.0

=====================================
Intel Trusted Domain Extensions (TDX)
=====================================

1. Introduction

Intel Trusted Domain Extensions (TDX) protects guest VMs from malicious
host and certain physical attacks.  To support TDX, a new isolated CPU
mode called Secure Arbitration Mode (SEAM) is added to Intel processors.

SEAM is an extension to the VMX architecture to define a new, VMX root
operation called SEAM VMX root and a new VMX non-root operation called
SEAM VMX non-root. Collectively, the SEAM VMX root and SEAM VMX non-root
execution modes are called operation in SEAM.

SEAM VMX root operation is designed to host a CPU-attested, software
module called 'Intel TDX module' to manage virtual machine (VM) guests
called Trust Domains (TD). The TDX module implements the functions to
build, tear down, and start execution of TD VMs. SEAM VMX root is also
designed to additionally host a CPU-attested, software module called the
'Intel Persistent SEAMLDR (Intel P-SEAMLDR)' module to load and update
the Intel TDX module.

The TDX module and the P-SEAMLDR runs in the memory region defined by the
SEAM range register (SEAMRR), which is configured by the platform owner
and programmed by the BIOS. Access to this range is restricted to SEAM
VMX root operation. Code fetches outside of SEAMRR when in SEAM VMX root
operation are meant to be disallowed and lead to an unbreakable shutdown.

Intel TDX leverages Intel Multiple Key Total Memory Encryption (MKTME) to
provide crypto protection to TD guests. Intel TDX reserves part of MKTME
KeyID space as TDX private KeyIDs, which can only be used by software
module runs in SEAM. The physical address bits reserved for encoding TDX
private KeyID are meant to be treated as reserved bits when not in SEAM
operation. The partitioning of MKTME KeyIDs and TDX private KeyIDs is
configured by platform owner and programmed by BIOS.

Host kernel transits to TDX module or P-SEAMLDR via the new SEAMCALL
instruction, which is essentially a VMExit from VMX root mode to SEAM VMX
root mode. SEAMCALLs are leaf functions defined by the TDX module or the
P-SEAMLDR around the new SEAMCALL instruction.

Before being able to use TDX module to create TD guests, the TDX module
must be loaded into SEAMRR and properly initialized, using SEAMCALLs
defined by TDX archtecture. On Linux, both P-SEAMLDR and TDX module are
expected to be loaded by BIOS (for instance, using UEFI shell application).
However, kernel is expected to detect the TDX module, and initialize it.

2. TDX module initialization

Initializing the TDX module in general consists of below steps:

1) Global initialization;
2) Logical-CPU scope initialization;
3) Enumerate the TDX module capabilities and platform configuration;
4) Build the TDX usable memory ranges;
5) Reserve one TDX private KeyID as global KeyID to protect TDX module
   global metadata;
6) Configure the TDX module about TDX usable memory ranges and the
   global KeyID information;
7) Package-scope configuration for the global KeyID;
8) Initialize the TDX usable memory ranges based on 4).

The initialization consumes additional memory as TDX module's global
metadata (roughly 1/256th system RAM), and consumes additional time to
initialize TDX usable memory (upto seconds for large memory in TBs).
Kernel doesn't initialize the TDX module by default during kernel boot,
but provides two functions detect_tdx() and init_tdx() to allow TDX user
to initialize TDX when TDX is truly needed.  KVM is the first user of
TDX, and is supposed to initialize TDX.

Additionally, TDX module initialization is controlled by a new kernel
command line 'tdx_host={on|off}', and default value is off.

3. The presence of TDX

The presence of SEAMRR is reported via a new SEAMRR bit (15) of the
IA32_MTRRCAP MSR.  The SEAMRR range registers consist of a pair of MSRs:
IA32_SEAMRR_PHYS_BASE (0x1400) and IA32_SEAMRR_PHYS_MASK (0x1401). SEAMRR
is enabled when bit 3 of IA32_SEAMRR_PHYS_BASE is set, and bit 10 and 11
of IA32_SEAMRR_PHYS_MASK are set.

However, unfortunately there is no CPUID or MSR defined to query the
presence of the TDX module or the P-SEAMLDR.  Since the TDX module is
initialized on-demand, there's no CPU feature bit (i.e X86_FEATURE_TDX)
for TDX. User can check whether TDX has been enabled by kernel via dmesg:

  [..] p-seamldr: version 0x0, vendor_id: 0x8086, build_date: 20211209, build_num 160, major 1, minor 0
  [..] tdx: TDX module: vendor_id 0x8086, major_version 1, minor_version 0, build_date 20211209, build_num 160
  [..] tdx: TDX module successfully initialized

4. Memory management in TDX memory

TDX provides increased levels of memory confidentiality and integrity.
This requires special hardware support for features like memory
encryption and storage of memory integrity checksums. Not all memory
satisfies these requirements.

As a result, TDX introduced the concept of a "Convertible Memory Region"
(CMR). During boot, the firmware builds a list of all of the memory
ranges which can provide the TDX security guarantees. The list of these
ranges, along with TDX module information, is available to the kernel by
querying the TDX module.

In order to provide crypto protection to TD guests, the TDX architecture
also needs additional metadata to record things like which TD guest
"owns" a given page of memory. This metadata essentially serves as the
'struct page' for the TDX module. The space for this metadata is not
reserved by the hardware up front and must be allocated by the kernel
and given to the TDX module.

Since this metadata consumes space, the VMM can choose whether or not to
allocate it for a given area of convertible memory. If it chooses not
to, the memory cannot receive TDX protections and can not be used by TDX
guests as private memory.

For every TDX memory block that the VMM wants to use as TDX memory, it
sets up a "TD Memory Region" (TDMR). Each TDMR represents a physically
contiguous convertible range and must also have its own physically
contiguous metadata table, referred to as a Physical Address Metadata
Table (PAMT), to track status for each page in TDMR range.

Unlike a CMRs, each TDMR requires 1G granularity and alignment. To
support physical RAM areas that don't meet those strict requirements,
each TDMR permits a number of internal "reserved areas" which can be
placed over memory holes. If PAMT metadata is placed within a TDMR it
must be covered by one of these reserved areas.

Summerize the concepts:

 CMR - Firmware-enumerated physical ranges that support TDX. CMRs are 4K
       aligned.

TDMR - Physical address range which is chosen by the kernel to support
       TDX. 1G granularity and alignment required. Each TDMR has
       reserved areas where TDX memory holes and overlapping PAMTs can
       be put into.

PAMT - Physically contiguous TDX metadata. One table for each page size
       per TDMR. Roughly 1/256th of TDMR in size. 256G TDMR = ~1G PAMT.

As one step of initializing TDX module, kernel needs to configure TDX
module with an array of TDMRs which covers all memory regions that kernel
wants to use as TDX memory.

For the first generation of TDX, essentially all system RAM (except the
low 1MB) is convertible memory, and can be used by TDX. To avoid having
to change page allocator to distinguish TDX and non-TDX page allocation,
kernel simply converts all system RAM to TDX memory.

Kernel configures TDX memory information to TDX module via an array of
'TDMR'. Each TDMR has information to describe its address range, the
location of the PAMTs that used to track this TDMR's pages, and reserved
areas to represent which pages in this TDMR are usable or not-usable by
TDX.

To use all system RAM as TDX memory, kernel essentially builds an array
of TDMRs to cover all RAM entries in e820.  'e820_table', rather than
'e820_table_firmware' or 'e820_table_kexec', is used to find all RAM
entries to honor 'mem' and 'memmap' kernel command lines.  X86 Legacy
PMEMs (PRAM) are also considered as RAM as they are underneath RAM, and
may be used as TD guest memory.

5. Initialize TDX memory

After kernel configures the TDX module with TDMRs, those TDMRs need to
be initialized before kernel can use them as TD guest memory.  TDMR
initialization essentially is to initialize all PAMT entries to reflect
all pages' status, using a global TDX private KeyID reserved by kernel
and given to the TDX module.

The time of initializing TDMR is proportional to the size of the TDMR.
To avoid long latency caused in one SEAMCALL, the SEAMCALL to initialize
TDMR only initializes an (implementation specific) subset of PAMT entries
of one TDMR. Kernel needs to repeat this SEAMCALL until the entire TDMR
is initialized.

Although different TDMRs can be initialized in parallel on multiple cpus,
for simplicity, currently kernel initializes TDMRs one-by-one. It takes
~100ms on a 2-socket machine with 2.2GHz CPUs and 64GB memory when the
system is idle. Each SEAMCALL takes ~7us in average.

6. CPU hotplug and memory hotplug

For first genration of TDX, a machine capable of TDX supports neither
CPU hotplug nor memory hotplug. Therefore, kernel doesn't explicitly
handle them.

A special case of memory hotplug is adding NVDIMM as system RAM using
kmem driver. For real NVDIMM hotplug, the first generation of TDX
capable machine doesn't support NVDIMM, therefore it's not possible to
have both NVDIMM and TDX present on one single machine. For legacy PMEMs
enabled via 'memmap' kernel command line, they are also treated as TDX
memory when initializing the TDX module, therefore kmem driver can just
work with them normally.  There's no special handling for memory hotplug
for kmem driver.

Also, there's no special handling for memremap_pages(). It should
continue to work, as the pages added by memremap_pages() are added to
ZONE_DEVICE which isn't managed by page allocator, therefore it's fine
they are not included into TDMRs. For the case of using legacy PMEMs as
TD guest memory, it's also fine since they are always included into
TDMRs.

7. Implementation limitations

- Constructing TDMRs

Currently, kernel tries to create one TDMR for each RAM entry in e820.
'e820_table' is used to find all RAM entries to honor 'mem' and 'memmap'
kernel command line. However, 'memmap' command line may also result in
many discrete RAM entries. TDX architecturally only supports limited
number of TDMRs (currently 64). In this case, constructing TDMRs may fail
due to exceeding the maximum number of TDMRs. User is responsible for not
doing so otherwise TDX may not be available. This can be further enhanced
by supporting merging adjacent TDMRs.

- PAMT allocation

Currently kernel allocate PAMT for each TDMR separately using
alloc_contig_pages(). alloc_contig_pages() only guarantees the PAMT is
allocated from given NUMA node, but doesn't have control on allocating
PAMT from given TDMR range. This may result in all PAMTs on one NUMA node
being within one single TDMR. PAMTs overlapping with given TDMR must be
put into TDMR's reserved areas too. However TDX only supports a limited
number of reserved areas per TDMR (currently 16), thus too many PAMTs in
one NUMA node may result in constructing TDMR failure due to exceeding
TDMR's maximum reserved areas.

User is responsible for not creating too many discrete RAM entries on one
NUMA node, which may result in having too many TDMRs on one node, which
eventually results in constructing TDMR failure due to exceeding maximum
reserved areas. This can be further enhanced to support per-NUMA-node
PAMT allocation, which could reduce the number of PAMT to 1 for one node.

- TDMR initialization

Currently kernel initialize TDMRs one by one. This may takes couple of
seconds to finish on large memory systems (TBs). This can be further
enhanced by allowing initializing different TDMRs in parallel on multiple
cpus.

- Error handing during TDX module initialization

Currently any error happened during TDX module initialization results in
TDX module being shutdown. This can be enhanced to treat certain errors
as recoverable errors. A more detailed state machine can be added to
record the internal status of TDX module initialization. When recoverable
error happens, kernel doesn't put TDX module to shutdown, but just
return, and caller can retry later. Kernel can resume from the internal
state of last recoverable error.

There are at least two errors can be treated as recoverable error:

a. -ENOMEM (i.e. due to PAMT allocation failure);
b. Error due to any CPU being offline. TDX module initialization requires
   all cpus being online during the initialization.
