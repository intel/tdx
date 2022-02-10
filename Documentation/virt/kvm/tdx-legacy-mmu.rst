.. SPDX-License-Identifier: GPL-2.0

Design of legacy MMU for TDX support
====================================
This document describes a (high level) design for TDX support of KVM legacy MMU
of x86 KVM.

The idea of legacy MMU support is the same as the TDX TDP MMU.  This document
describes the difference between the TDP MMU design.  Please refer to the TDP
MMU case first.  tdx-tdp-mmu.rst.


Race condition
==============
The legacy MMU code is write-protected by mmu_lock.  No concurrent zapping or
populating happens.


rmap and PRIVATE_PROHIBIT, PRIVATE_ZAPPED
=========================================
The legacy MMU uses rmap in deep.  It's difficult to change the state machine of
the EPT entry than the TDP MMU.  At the moment, it's not optimized by recording
PRIVATE_PROHIBIT in both shared and private EPTs as TDX the TDP MMU.  Use the
TDP MMU for performance.

Unlike the TDP MMU, TLB flush is closely tied to rmap.  It's difficult to touch
TLB flush execution path.  At the moment PRIVATE_ZAPPED is necessary for legacy
MMU.  Although it would be possible to eliminate the necessity of PRIVATE_ZAPPED
from legacy MMU, it's not tried.  Switch to the TDP MMU.


The usage of SEPT_PRIVATE_PROHIBIT
==================================
The meaning of SEPT_PRIVATE_PROHIBIT is the same as the TDP MMU case.  The
difference is the bit is recorded only in private EPT.  Not in shared EPT.

MapGPA hypercall is implemented to record SEPT_PRIVATE_PROHIBIT in the private
EPT.  When resolving EPT violation on shared GPA, the private EPT is consulted.

The state machine of EPT entry
------------------------------
it causes the state machine difference to record SEPT_PRIVATE_PROHIBIT in only
private EPT.

(private EPT entry, shared EPT entry) =
        (non-present, non-present):             private mapping is allowed
        (present, non-present):                 private mapping is mapped
        (non-present | PRIVATE_PROHIBIT, non-present):
                                                shared mapping is allowed
        (non-present | PRIVATE_PROHIBIT, present):
                                                shared mapping is mapped
        (present, present):                     invalid combination


* map_gpa(private GPA): Mark the region that private GPA is allowed(NEW)
        private EPT entry: clear PRIVATE_PROHIBIT
          present: nop
          non-present: nop
          non-present | PRIVATE_PROHIBIT -> non-present (clear PRIVATE_PROHIBIT)

        shared EPT entry: zap the entry
          any -> non-present

* map_gpa(shared GPA): Mark the region that shared GPA is allowed(NEW)
        private EPT entry: zap and set PRIVATE_PROHIBIT
          present     -> non-present | PRIVATE_PROHIBIT
          non-present -> non-present | PRIVATE_PROHIBIT
          non-present | PRIVATE_PROHIBIT: nop

        shared EPT entry: nop

* map(private GPA)
        private EPT entry
          present: nop
          non-present -> present
          non-present | PRIVATE_PROHIBIT: nop. looping on EPT violation(NEW)

        shared EPT entry: nop
          If the shared EPT entry has the present bit set, PRIVATE_PROHIBIT in
          the corresponding private EPT entry is set.

* map(shared GPA)
        private EPT entry: nop
          It's consulted to check if shared GPA is allowed with
          PRIVATE_PROHIBIT.  If shared GPA is not allowed(PRIVATE_PROHIBIT
          cleared), loop in EPT violation on shared GPA.

        shared EPT entry
          present: nop
          non-present -> present

* zap(private GPA)
        private EPT entry: zap the entry with keeping PRIVATE_PROHIBIT
          present -> non-present
          non-present: nop as is_shadow_prsent_pte() is checked
          non-present | PRIVATE_PROHIBIT: nop as is_shadow_prsent_pte() is
                                          checked

        shared EPT entry: nop

* zap(shared GPA)
        private EPT entry: nop

        shared EPT entry: zap
          any -> non-present
