.. SPDX-License-Identifier: GPL-2.0

===================================
Intel Trust Dodmain Extensions(TDX)
===================================

Overview
========
TDX stands for Trust Domain Extensions which isolates VMs from
the virtual-machine manager (VMM)/hypervisor and any other software on
the platform. [1]
For details, the specifications, [2], [3], [4], [5], [6], [7], are
available.


API description
===============

KVM_MEMORY_ENCRYPT_OP
---------------------
:Type: vm ioctl, vcpu ioctl

For TDX operations, KVM_MEMORY_ENCRYPT_OP is re-purposed to be generic
ioctl with TDX specific sub ioctl command.

::

  /* Trust Domain eXtension sub-ioctl() commands. */
  enum kvm_tdx_cmd_id {
          KVM_TDX_CAPABILITIES = 0,
          KVM_TDX_INIT_VM,
          KVM_TDX_INIT_VCPU,
          KVM_TDX_INIT_MEM_REGION,
          KVM_TDX_FINALIZE_VM,

          KVM_TDX_CMD_NR_MAX,
  };

  struct kvm_tdx_cmd {
          __u32 id;             /* tdx_cmd_id */
          __u32 metadata;       /* sub comamnd specific */
          __u64 data;           /* sub command specific */
  };


KVM_TDX_CAPABILITIES
--------------------
:Type: vm ioctl

Subset of TDSYSINFO_STRCUCT retrieved by TDH.SYS.INFO TDX SEAM call will be
returned. Which describes about Intel TDX module.

- id: KVM_TDX_CAPABILITIES
- metadata: must be 0
- data: pointer to struct kvm_tdx_capabilities

::

  struct kvm_tdx_cpuid_config {
          __u32 leaf;
          __u32 sub_leaf;
          __u32 eax;
          __u32 ebx;
          __u32 ecx;
          __u32 edx;
  };

  struct kvm_tdx_capabilities {
          __u64 attrs_fixed0;
          __u64 attrs_fixed1;
          __u64 xfam_fixed0;
          __u64 xfam_fixed1;

          __u32 nr_cpuid_configs;
          struct kvm_tdx_cpuid_config cpuid_configs[0];
  };


KVM_TDX_INIT_VM
---------------
:Type: vm ioctl

Does additional VM initialization specific to TDX which corresponds to
TDH.MNG.INIT TDX SEAM call.

- id: KVM_TDX_INIT_VM
- metadata: must be 0
- data: pointer to struct kvm_tdx_init_vm
- reserved: must be 0

::

  struct kvm_tdx_init_vm {
          __u32 max_vcpus;
          __u32 reserved;
          __u64 attributes;
          __u64 cpuid;  /* pointer to struct kvm_cpuid2 */
          __u64 mrconfigid[6];          /* sha384 digest */
          __u64 mrowner[6];             /* sha384 digest */
          __u64 mrownerconfig[6];       /* sha348 digest */
          __u64 reserved[43];           /* must be zero for future extensibility */
  };


KVM_TDX_INIT_VCPU
-----------------
:Type: vcpu ioctl

Does additional VCPU initialization specific to TDX which corresponds to
TDH.VP.INIT TDX SEAM call.

- id: KVM_TDX_INIT_VCPU
- metadata: must be 0
- data: initial value of the guest TD VCPU RCX


KVM_TDX_INIT_MEM_REGION
-----------------------
:Type: vm ioctl

Encrypt a memory continuous region which corresponding to TDH.MEM.PAGE.ADD
TDX SEAM call.
If KVM_TDX_MEASURE_MEMORY_REGION flag is specified, it also extends measurement
which corresponds to TDH.MR.EXTEND TDX SEAM call.

- id: KVM_TDX_INIT_VCPU
- metadata: flags
            currently only KVM_TDX_MEASURE_MEMORY_REGION is defined
- data: pointer to struct kvm_tdx_init_mem_region

::

  #define KVM_TDX_MEASURE_MEMORY_REGION   (1UL << 0)

  struct kvm_tdx_init_mem_region {
          __u64 source_addr;
          __u64 gpa;
          __u64 nr_pages;
  };


KVM_TDX_FINALIZE_VM
-------------------
:Type: vm ioctl

Complete measurement of the initial TD contents and mark it ready to run
which corresponds to TDH.MR.FINALIZE

- id: KVM_TDX_FINALIZE_VM
- metadata: ignored
- data: ignored


KVM TDX creation flow
=====================
In addition to KVM normal flow, new TDX ioctls need to be called.  The control flow
looks like as follows.

#. system wide capability check
  * KVM_CAP_VM_TYPES: check if VM type is supported and if TDX_VM_TYPE is
    supported.

#. creating VM
  * KVM_CREATE_VM
  * KVM_TDX_CAPABILITIES: query if TDX is supported on the platform.
  * KVM_TDX_INIT_VM: pass TDX specific VM parameters.

#. creating VCPU
  * KVM_CREATE_VCPU
  * KVM_TDX_INIT_VCPU: pass TDX specific VCPU parameters.

#. initializing guest memory
  * allocate guest memory and initialize page same to normal KVM case
    In TDX case, parse and load TDVF into guest memory in addition.
  * KVM_TDX_INIT_MEM_REGION to add and measure guest pages.
    If the pages has contents above, those pages need to be added.
    Otherwise the contents will be lost and guest sees zero pages.
  * KVM_TDX_FINALIAZE_VM: Finalize VM and measurement
    This must be after KVM_TDX_INIT_MEM_REGION.

#. run vcpu

Design discussion
=================

Coexistence of normal(VMX) VM and TD VM
---------------------------------------
It's required to allow both legacy(normal VMX) VMs and new TD VMs to
coexist. Otherwise the benefits of VM flexibility would be eliminated.
The main issue for it is that the logic of kvm_x86_ops callbacks for
TDX is different from VMX. On the other hand, the variable,
kvm_x86_ops, is global single variable. Not per-VM, not per-vcpu.

Several points to be considered.
  . No or minimal overhead when TDX is disabled(CONFIG_INTEL_TDX_HOST=n).
  . Avoid overhead of indirect call via function pointers.
  . Contain the changes under arch/x86/kvm/vmx directory and share logic
    with VMX for maintenance.
    Even though the ways to operation on VM (VMX instruction vs TDX
    SEAM call) is different, the basic idea remains same. So, many
    logic can be shared.
  . Future maintenance
    The huge change of kvm_x86_ops in (near) future isn't expected.
    a centralized file is acceptable.

- Wrapping kvm x86_ops: The current choice
  Introduce dedicated file for arch/x86/kvm/vmx/main.c (the name,
  main.c, is just chosen to show main entry points for callbacks.) and
  wrapper functions around all the callbacks with
  "if (is-tdx) tdx-callback() else vmx-callback()".

  Pros:
  - No major change in common x86 KVM code. The change is (mostly)
    contained under arch/x86/kvm/vmx/.
  - When TDX is disabled(CONFIG_INTEL_TDX_HOST=n), the overhead is
    optimized out.
  - Micro optimization by avoiding function pointer.
  Cons:
  - Many boiler plates in arch/x86/kvm/vmx/main.c.

Alternative:
- Introduce another callback layer under arch/x86/kvm/vmx.
  Pros:
  - No major change in common x86 KVM code. The change is (mostly)
    contained under arch/x86/kvm/vmx/.
  - clear separation on callbacks.
  Cons:
  - overhead in VMX even when TDX is disabled(CONFIG_INTEL_TDX_HOST=n).

- Allow per-VM kvm_x86_ops callbacks instead of global kvm_x86_ops
  Pros:
  - clear separation on callbacks.
  Cons:
  - Big change in common x86 code.
  - overhead in common code even when TDX is
    disabled(CONFIG_INTEL_TDX_HOST=n).

- Introduce new directory arch/x86/kvm/tdx
  Pros:
  - It clarifies that TDX is different from VMX.
  Cons:
  - Given the level of code sharing, it complicates code sharing.

KVM MMU Changes
---------------
KVM MMU needs to be enhanced to handle Secure/Shared-EPT. The
high-level execution flow is mostly same to normal EPT case.
EPT violation/misconfiguration -> invoke TDP fault handler ->
resolve TDP fault -> resume execution. (or emulate MMIO)
The difference is, that S-EPT is operated(read/write) via TDX SEAM
call which is expensive instead of direct read/write EPT entry.
One bit of GPA (51 or 47 bit) is repurposed so that it means shared
with host(if set to 1) or private to TD(if cleared to 0).

- The current implementation
  . Reuse the existing MMU code with minimal update.  Because the
    execution flow is mostly same. But additional operation, TDX call
    for S-EPT, is needed. So add hooks for it to kvm_x86_ops.
  . For performance, minimize TDX SEAM call to operate on S-EPT. When
    getting corresponding S-EPT pages/entry from faulting GPA, don't
    use TDX SEAM call to read S-EPT entry. Instead create shadow copy
    in host memory.
    Repurpose the existing kvm_mmu_page as shadow copy of S-EPT and
    associate S-EPT to it.
  . Treats share bit as attributes. mask/unmask the bit where
    necessary to keep the existing traversing code works.
    Introduce kvm.arch.gfn_shared_mask and use "if (gfn_share_mask)"
    for special case.
    = 0 : for non-TDX case
    = 51 or 47 bit set for TDX case.

  Pros:
  - Large code reuse with minimal new hooks.
  - Execution path is same.
  Cons:
  - Complicates the existing code.
  - Repurpose kvm_mmu_page as shadow of Secure-EPT can be confusing.

Alternative:
- Replace direct read/write on EPT entry with TDX-SEAM call by
  introducing callbacks on EPT entry.
  Pros:
  - Straightforward.
  Cons:
  - Too many touching point.
  - Too slow due to TDX-SEAM call.
  - Overhead even when TDX is disabled(CONFIG_INTEL_TDX_HOST=n).

- Sprinkle "if (is-tdx)" for TDX special case
  Pros:
  - Straightforward.
  Cons:
  - The result is non-generic and ugly.
  - Put TDX specific logic into common KVM MMU code.

New KVM API, ioctl (sub)command, to manage TD VMs
-------------------------------------------------
Additional KVM API are needed to control TD VMs. The operations on TD
VMs are specific to TDX.

- Piggyback and repurpose KVM_MEMORY_ENCRYPT_OP
  Although not all operation isn't memory encryption, repupose to get
  TDX specific ioctls.
  Pros:
  - No major change in common x86 KVM code.
  Cons:
  - The operations aren't actually memory encryption, but operations
    on TD VMs.

Alternative:
- Introduce new ioctl for guest protection like
  KVM_GUEST_PROTECTION_OP and introduce subcommand for TDX.
  Pros:
  - Clean name.
  Cons:
  - One more new ioctl for guest protection.
  - Confusion with KVM_MEMORY_ENCRYPT_OP with KVM_GUEST_PROTECTION_OP.

- Rename KVM_MEMORY_ENCRYPT_OP to KVM_GUEST_PROTECTION_OP and keep
  KVM_MEMORY_ENCRYPT_OP as same value for user API for compatibility.
  "#define KVM_MEMORY_ENCRYPT_OP KVM_GUEST_PROTECTION_OP" for uapi
  compatibility.
  Pros:
  - No new ioctl with more suitable name.
  Cons:
  - May cause confusion to the existing user program.


References
==========

.. [1] TDX specification
   https://software.intel.com/content/www/us/en/develop/articles/intel-trust-domain-extensions.html
.. [2] Intel Trust Domain Extensions (Intel TDX)
   https://software.intel.com/content/dam/develop/external/us/en/documents/tdx-whitepaper-final9-17.pdf
.. [3] Intel CPU Architectural Extensions Specification
   https://software.intel.com/content/dam/develop/external/us/en/documents/intel-tdx-cpu-architectural-specification.pdf
.. [4] Intel TDX Module 1.0 EAS
   https://software.intel.com/content/dam/develop/external/us/en/documents/intel-tdx-module-1eas.pdf
.. [5] Intel TDX Loader Interface Specification
   https://software.intel.com/content/dam/develop/external/us/en/documents/intel-tdx-seamldr-interface-specification.pdf
.. [6] Intel TDX Guest-Hypervisor Communication Interface
   https://software.intel.com/content/dam/develop/external/us/en/documents/intel-tdx-guest-hypervisor-communication-interface.pdf
.. [7] Intel TDX Virtual Firmware Design Guide
   https://software.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.
.. [8] intel public github
   kvm TDX branch: https://github.com/intel/tdx/tree/kvm
   TDX guest branch: https://github.com/intel/tdx/tree/guest
.. [9] tdvf
    https://github.com/tianocore/edk2-staging/tree/TDVF
.. [10] KVM forum 2020: Intel Virtualization Technology Extensions to
     Enable Hardware Isolated VMs
     https://osseu2020.sched.com/event/eDzm/intel-virtualization-technology-extensions-to-enable-hardware-isolated-vms-sean-christopherson-intel
.. [11] Linux Security Summit EU 2020:
     Architectural Extensions for Hardware Virtual Machine Isolation
     to Advance Confidential Computing in Public Clouds - Ravi Sahita
     & Jun Nakajima, Intel Corporation
     https://osseu2020.sched.com/event/eDOx/architectural-extensions-for-hardware-virtual-machine-isolation-to-advance-confidential-computing-in-public-clouds-ravi-sahita-jun-nakajima-intel-corporation
.. [12] [RFCv2,00/16] KVM protected memory extension
     https://lkml.org/lkml/2020/10/20/66
