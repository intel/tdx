.. SPDX-License-Identifier: GPL-2.0

Design of TDP MMU for TDX support
=================================
This document describes a (high level) design for TDX support of KVM TDP MMU of
x86 KVM.

In this document, we use "TD" or "guest TD" to differentiate it from the current
"VM" (Virtual Machine), which is supported by KVM today.


Background of TDX
=================
TD private memory is designed to hold TD private content, encrypted by the CPU
using the TD ephemeral key.  An encryption engine holds a table of encryption
keys, and an encryption key is selected for each memory transaction based on a
Host Key Identifier (HKID).  By design, the host VMM does not have access to the
encryption keys.

In the first generation of MKTME, HKID is "stolen" from the physical address by
allocating a configurable number of bits from the top of the physical address.
The HKID space is partitioned into shared HKIDs for legacy MKTME accesses and
private HKIDs for SEAM-mode-only accesses.  We use 0 for the shared HKID on the
host so that MKTME can be opaque or bypassed on the host.

During TDX non-root operation (i.e. guest TD), memory accesses can be qualified
as either shared or private, based on the value of a new SHARED bit in the Guest
Physical Address (GPA).  The CPU translates shared GPAs using the usual VMX EPT
(Extended Page Table) or "Shared EPT" (in this document), which resides in the
host VMM memory.  The Shared EPT is directly managed by the host VMM - the same
as with the current VMX.  Since guest TDs usually require I/O, and the data
exchange needs to be done via shared memory, thus KVM needs to use the current
EPT functionality even for TDs.

The CPU translates private GPAs using a separate Secure EPT.  The Secure EPT
pages are encrypted and integrity-protected with the TD's ephemeral private key.
Secure EPT can be managed _indirectly_ by the host VMM, using the TDX interface
functions (SEAMCALLs), and thus conceptually Secure EPT is a subset of EPT
because not all functionalities are available.

Since the execution of such interface functions takes much longer time than
accessing memory directly, in KVM we use the existing TDP code to mirror the
Secure EPT for the TD. And we think there are at least two options today in
terms of the timing for executing such SEAMCALLs:

1. synchronous, i.e. while walking the TDP page tables, or
2. post-walk, i.e. record what needs to be done to the real Secure EPT during
   the walk, and execute SEAMCALLs later.

The option 1 seems to be more intuitive and simpler, but the Secure EPT
concurrency rules are different from the ones of the TDP or EPT. For example,
MEM.SEPT.RD acquire shared access to the whole Secure EPT tree of the target

Secure EPT(SEPT) operations
---------------------------
Secure EPT is an Extended Page Table for GPA-to-HPA translation of TD private
HPA.  A Secure EPT is designed to be encrypted with the TD's ephemeral private
key. SEPT pages are allocated by the host VMM via Intel TDX functions, but their
content is intended to be hidden and is not architectural.

Unlike the conventional EPT, the CPU can't directly read/write its entry.
Instead, TDX SEAMCALL API is used.  Several SEAMCALLs correspond to operation on
the EPT entry.

* TDH.MEM.SEPT.ADD():
  Add a secure EPT page from the secure EPT tree.  This corresponds to updating
  the non-leaf EPT entry with present bit set

* TDH.MEM.SEPT.REMOVE():
  Remove the secure page from the secure EPT tree.  There is no corresponding
  to the EPT operation.

* TDH.MEM.SEPT.RD():
  Read the secure EPT entry.  This corresponds to reading the EPT entry as
  memory.  Please note that this is much slower than direct memory reading.

* TDH.MEM.PAGE.ADD() and TDH.MEM.PAGE.AUG():
  Add a private page to the secure EPT tree.  This corresponds to updating the
  leaf EPT entry with present bit set.

* THD.MEM.PAGE.REMOVE():
  Remove a private page from the secure EPT tree.  There is no corresponding
  to the EPT operation.

* TDH.MEM.RANGE.BLOCK():
  This (mostly) corresponds to clearing the present bit of the leaf EPT entry.
  Note that the private page is still linked in the secure EPT.  To remove it
  from the secure EPT, TDH.MEM.SEPT.REMOVE() and TDH.MEM.PAGE.REMOVE() needs to
  be called.

* TDH.MEM.TRACK():
  Increment the TLB epoch counter. This (mostly) corresponds to EPT TLB flush.
  Note that the private page is still linked in the secure EPT.  To remove it
  from the secure EPT, tdh_mem_page_remove() needs to be called.


Adding private page
-------------------
The procedure of populating the private page looks as follows.

1. TDH.MEM.SEPT.ADD(512G level)
2. TDH.MEM.SEPT.ADD(1G level)
3. TDH.MEM.SEPT.ADD(2M level)
4. TDH.MEM.PAGE.AUG(4K level)

Those operations correspond to updating the EPT entries.

Dropping private page and TLB shootdown
---------------------------------------
The procedure of dropping the private page looks as follows.

1. TDH.MEM.RANGE.BLOCK(4K level)
   This mostly corresponds to clear the present bit in the EPT entry.  This
   prevents (or blocks) TLB entry from creating in the future.  Note that the
   private page is still linked in the secure EPT tree and the existing cache
   entry in the TLB isn't flushed.
2. TDH.MEM.TRACK(range) and TLB shootdown
   This mostly corresponds to the EPT TLB shootdown.  Because all vcpus share
   the same Secure EPT, all vcpus need to flush TLB.
   * TDH.MEM.TRACK(range) by one vcpu.  It increments the global internal TLB
     epoch counter.
   * send IPI to remote vcpus
   * Other vcpu exits to VMM from guest TD and then re-enter. TDH.VP.ENTER().
   * TDH.VP.ENTER() checks the TLB epoch counter and If its TLB is old, flush
     TLB.
   Note that only single vcpu issues tdh_mem_track().
   Note that the private page is still linked in the secure EPT tree, unlike the
   conventional EPT.
3. TDH.MEM.PAGE.PROMOTE, TDH.MEM.PAGEDEMOTE(), TDH.MEM.PAGE.RELOCATE(), or
   TDH.MEM.PAGE.REMOVE()
   There is no corresponding operation to the conventional EPT.
   * When changing page size (e.g. 4K <-> 2M) TDH.MEM.PAGE.PROMOTE() or
     TDH.MEM.PAGE.DEMOTE() is used.  During those operation, the guest page is
     kept referenced in the Secure EPT.
   * When migrating page, TDH.MEM.PAGE.RELOCATE().  This requires both source
     page and destination page.
   * when destroying TD, TDH.MEM.PAGE.REMOVE() removes the private page from the
     secure EPT tree.  In this case TLB shootdown is not needed because vcpus
     don't run any more.

The basic idea for TDX support
==============================
Because shared EPT is the same as the existing EPT, use the existing logic for
shared EPT.  On the other hand, secure EPT requires additional operations
instead of directly reading/writing of the EPT entry.

On EPT violation, The KVM mmu walks down the EPT tree from the root, determines
the EPT entry to operate, and updates the entry. If necessary, a TLB shootdown
is done.  Because it's very slow to directly walk secure EPT by TDX SEAMCALL,
TDH.MEM.SEPT.RD(), the mirror of secure EPT is created and maintained.  Add
hooks to KVM MMU to reuse the existing code.

EPT violation on shared GPA
---------------------------
(1) EPT violation on shared GPA or zapping shared GPA
    walk down shared EPT tree (the existing code)
        |
        |
        V
shared EPT tree (CPU refers.)
(2) update the EPT entry. (the existing code)
    TLB shootdown in the case of zapping.


EPT violation on private GPA
----------------------------
(1) EPT violation on private GPA or zapping private GPA
    walk down the mirror of secure EPT tree (mostly same as the existing code)
        |
        |
        V
mirror of secure EPT tree (KVM MMU software only. reuse of the existing code)
(2) update the (mirrored) EPT entry. (mostly same as the existing code)
(3) call the hooks with what EPT entry is changed
        |
        NEW: hooks in KVM MMU
        |
        V
secure EPT root(CPU refers)
(4) the TDX backend calls necessary TDX SEAMCALLs to update real secure EPT.

The major modification is to add hooks for the TDX backend for additional
operations and to pass down which EPT, shared EPT, or private EPT is used, and
twist the behavior if we're operating on private EPT.

The following depicts the relationship.
::

                    KVM                             |       TDX module
                     |                              |           |
        -------------+----------                    |           |
        |                      |                    |           |
        V                      V                    |           |
     shared GPA           private GPA               |           |
  CPU shared EPT pointer  KVM private EPT pointer   |  CPU secure EPT pointer
        |                      |                    |           |
        |                      |                    |           |
        V                      V                    |           V
  shared EPT                private EPT<-------mirror----->Secure EPT
        |                      |                    |           |
        |                      \--------------------+------\    |
        |                                           |      |    |
        V                                           |      V    V
  shared guest page                                 |    private guest page
                                                    |
                                                    |
                              non-encrypted memory  |    encrypted memory
                                                    |

shared EPT: CPU and KVM walk with shared GPA
            Maintained by the existing code
private EPT: KVM walks with private GPA
             Maintained by the twisted existing code
secure EPT: CPU walks with private GPA.
            Maintained by TDX module with TDX SEAMCALLs via hooks


Tracking private EPT page
=========================
Shared EPT pages are managed by struct kvm_mmu_page.  They are linked in a list
structure.  When necessary, the list is traversed to operate on.  Private EPT
pages have different characteristics.  For example, private pages can't be
swapped out.  When shrinking memory, we'd like to traverse only shared EPT pages
and skip private EPT pages.  Likewise, page migration isn't supported for
private pages (yet).  Introduce an additional list to track shared EPT pages and
track private EPT pages independently.

At the beginning of EPT violation, the fault handler knows fault GPA, thus it
knows which EPT to operate on, private or shared.  If it's private EPT,
an additional task is done.  Something like "if (private) { callback a hook }".
Since the fault handler has deep function calls, it's cumbersome to hold the
information of which EPT is operating.  Options to mitigate it are

1. Pass the information as an argument for the function call.
2. Record the information in struct kvm_mmu_page somehow.
3. Record the information in vcpu structure.

Option 2 was chosen.  Because option 1 requires modifying all the functions.  It
would affect badly to the normal case.  Option 3 doesn't work well because in
some cases, we need to walk both private and shared EPT.

The role of the EPT page can be utilized and one bit can be curved out from
unused bits in struct kvm_mmu_page_role.  When allocating the EPT page,
initialize the information. Mostly struct kvm_mmu_page is available because
we're operating on EPT pages.


The conversion of private GPA and shared GPA
============================================
A page of a given GPA can be assigned to only private GPA xor shared GPA at one
time.  The GPA can't be accessed simultaneously via both private GPA and shared
GPA.  On guest startup, all the GPAs are assigned as private.  Guest converts
the range of GPA to shared (or private) from private (or shared) by MapGPA
hypercall.  MapGPA hypercall takes the start GPA and the size of the region.  If
the given start GPA is shared, VMM converts the region into shared (if it's
already shared, nop).  If the start GPA is private, VMM converts the region into
private.  It implies the guest won't access the unmapped region. private(or
shared) region after converting to shared(or private).

If the guest TD triggers an EPT violation on the already converted region, the
access won't be allowed (loop in EPT violation) until other vcpu converts back
the region.

KVM MMU records which GPA is allowed to access, private or shared.  It steals
software usable bit from MMU present mask.  SEPT_PRIVATE_PROHIBIT.  The bit is
recorded in both shared EPT and the mirror of secure EPT.

* If SEPT_PRIVATE_PROHIBIT cleared in the shared EPT and the mirror of secure EPT:
  Private GPA is allowed. Shared GPA is not allowed.

* SEPT_PRIVATE_PROHIBIT set in the shared EPT and the mirror of secure EPT:
  Private GPA is not allowed. Shared GPA is allowed.

The default is that SEPT_PRIVATE_PROHIBIT is cleared so that the existing KVM
MMU code (mostly) works.

The reason why the bit is recorded in both shared and private EPT is to optimize
for EPT violation path by penalizing MapGPA hypercall.

The state machine of EPT entry
------------------------------
(private EPT entry, shared EPT entry) =
        (non-present, non-present):             private mapping is allowed
        (present, non-present):                 private mapping is mapped
        (non-present | PRIVATE_PROHIBIT, non-present | PRIVATE_PROHIBIT):
                                                shared mapping is allowed
        (non-present | PRIVATE_PROHIBIT, present | PRIVATE_PROHIBIT):
                                                shared mapping is mapped
        (present | PRIVATE_PROHIBIT, any)       invalid combination

* map_gpa(private GPA): Mark the region that private GPA is allowed(NEW)
        private EPT entry: clear PRIVATE_PROHIBIT
          present: nop
          non-present: nop
          non-present | PRIVATE_PROHIBIT -> non-present (clear PRIVATE_PROHIBIT)

        shared EPT entry: zap the entry, clear PRIVATE_PROHIBIT
          present: invalid
          non-present -> non-present: nop
          present | PRIVATE_PROHIBIT -> non-present
          non-present | PRIVATE_PROHIBIT -> non-present

* map_gpa(shared GPA): Mark the region that shared GPA is allowed(NEW)
        private EPT entry: zap and set PRIVATE_PROHIBIT
          present     -> non-present | PRIVATE_PROHIBIT
          non-present -> non-present | PRIVATE_PROHIBIT
          non-present | PRIVATE_PROHIBIT: nop

        shared EPT entry: set PRIVATE_PROHIBIT
          present: invalid
          non-present -> non-present | PRIVATE_PROHIBIT
          present | PRIVATE_PROHIBIT -> present | PRIVATE_PROHIBIT: nop
          non-present | PRIVATE_PROHIBIT -> non-present | PRIVATE_PROHIBIT: nop

* map(private GPA)
        private EPT entry
          present: nop
          non-present -> present
          non-present | PRIVATE_PROHIBIT: nop. looping on EPT violation(NEW)

        shared EPT entry: nop

* map(shared GPA)
        private EPT entry: nop

        shared EPT entry
          present: invalid
          present | PRIVATE_PROHIBIT: nop
          non-present | PRIVATE_PROHIBIT -> present | PRIVATE_PROHIBIT
          non-present: nop. looping on EPT violation(NEW)

* zap(private GPA)
        private EPT entry: zap the entry with keeping PRIVATE_PROHIBIT
          present -> non-present
          present | PRIVATE_PROHIBIT: invalid
          non-present: nop as is_shadow_present_pte() is checked
          non-present | PRIVATE_PROHIBIT: nop as is_shadow_present_pte() is
                                          checked

        shared EPT entry: nop

* zap(shared GPA)
        private EPT entry: nop

        shared EPT entry: zap
          any -> non-present
          present: invalid
          present | PRIVATE_PROHIBIT -> non-present | PRIVATE_PROHIBIT
          non-present: nop as is_shadow_present_pte() is checked
          non-present | PRIVATE_PROHIBIT: nop as is_shadow_present_pte() is
                                          checked


The original TDP MMU and race condition
=======================================
Because vcpus share the EPT, once the EPT entry is zapped, we need to shootdown
TLB.  Send IPI to remote vcpus.  Remote vcpus flush their down TLBs.  Until TLB
shootdown is done, vcpus may reference the zapped guest page.

TDP MMU uses read lock of mmu_lock to mitigate vcpu contention.  When read lock
is obtained, it depends on the atomic update of the EPT entry.  (On the other
hand legacy MMU uses write lock.)  When vcpu is populating/zapping the EPT entry
with a read lock held, other vcpu may be populating or zapping the same EPT
entry at the same time.

To avoid the race condition, the entry is frozen.  It means the EPT entry is set
to the special value, REMOVED_SPTE which clears the present bit.  And then after
TLB shootdown, update the EPT entry to the final value.

Concurrent zapping
------------------
1. read lock
2. freeze the EPT entry (atomically set the value to REMOVED_SPTE)
   If other vcpu froze the entry, restart page fault.
3. TLB shootdown
   * send IPI to remote vcpus
   * TLB flush (local and remote)
   For each entry update, TLB shootdown is needed because of the
   concurrency.
4. atomically set the EPT entry to the final value
5. read unlock

Concurrent populating
---------------------
In the case of populating the non-present EPT entry, atomically update the EPT
entry.
1. read lock
2. atomically update the EPT entry
   If other vcpu frozen the entry or updated the entry, restart page fault.
3. read unlock

In the case of updating the present EPT entry (e.g. page migration), the
operation is split into two.  Zapping the entry and populating the entry.
1. read lock
2. zap the EPT entry.  follow the concurrent zapping case.
3. populate the non-present EPT entry.
4. read unlock

Non-concurrent batched zapping
------------------------------
In some cases, zapping the ranges is done exclusively with a write lock held.
In this case, the TLB shootdown is batched into one.

1. write lock
2. zap the EPT entries by traversing them
3. TLB shootdown
4. write unlock


For Secure EPT, TDX SEAMCALLs are needed in addition to updating the mirrored
EPT entry.

TDX concurrent zapping
----------------------
Add a hook for TDX SEAMCALLs at the step of the TLB shootdown.

1. read lock
2. freeze the EPT entry(set the value to REMOVED_SPTE)
3. TLB shootdown via a hook
   * TLB.MEM.RANGE.BLOCK()
   * TLB.MEM.TRACK()
   * send IPI to remote vcpus
4. set the EPT entry to the final value
5. read unlock

TDX concurrent populating
-------------------------
TDX SEAMCALLs are required in addition to operating the mirrored EPT entry.  The
frozen entry is utilized by following the zapping case to avoid the race
condition.  A hook can be added.

1. read lock
2. freeze the EPT entry
3. hook
   * TDH_MEM_SEPT_ADD() for non-leaf or TDH_MEM_PAGE_AUG() for leaf.
4. set the EPT entry to the final value
5. read unlock

Without freezing the entry, the following race can happen.  Suppose two vcpus
are faulting on the same GPA and the 2M and 4K level entries aren't populated
yet.

* vcpu 1: update 2M level EPT entry
* vcpu 2: update 4K level EPT entry
* vcpu 2: TDX SEAMCALL to update 4K secure EPT entry => error
* vcpu 1: TDX SEAMCALL to update 2M secure EPT entry


TDX non-concurrent batched zapping
----------------------------------
For simplicity, the procedure of concurrent populating is utilized.  The
procedure can be optimized later.


Co-existing with unmapping guest private memory
===============================================
TODO.  This needs to be addressed.


Restrictions or future work
===========================
The following features aren't supported yet at the moment.

* optimizing non-concurrent zap
* Large page
* Page migration
