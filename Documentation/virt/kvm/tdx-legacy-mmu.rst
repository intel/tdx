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


rmap and PRIVATE_ZAPPED
=======================
The legacy MMU uses rmap in deep.  It's difficult to change the state machine of
the EPT entry than the TDP MMU.

Unlike the TDP MMU, TLB flush is closely tied to rmap.  It's difficult to touch
TLB flush execution path.  At the moment PRIVATE_ZAPPED is necessary for legacy
MMU.  Although it would be possible to eliminate the necessity of PRIVATE_ZAPPED
from legacy MMU, it's not tried.  Switch to the TDP MMU.
