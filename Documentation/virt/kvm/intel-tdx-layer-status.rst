.. SPDX-License-Identifier: GPL-2.0

===================================
Intel Trust Dodmain Extensions(TDX)
===================================

Layer status
============
What qemu can do
----------------
- TDX VM TYPE is exposed to Qemu.
- Qemu can create/destroy guest of TDX vm type.
- Qemu can create/destroy vcpu of TDX vm type.

Patch Layer status
------------------
  Patch layer                          Status
* TDX, VMX coexistence:                 Applied
* TDX architectural definitions:        Applied
* TD VM creation/destruction:           Applied
* TD vcpu creation/destruction:         Applied
* TDX EPT violation:                    Not yet
* TD finalization:                      Not yet
* TD vcpu enter/exit:                   Not yet
* TD vcpu interrupts/exit/hypercall:    Not yet

* KVM MMU GPA stolen bits:              Applied
* KVM TDP refactoring for TDX:          Applying
* KVM TDP MMU hooks:                    Not yet
* KVM TDP MMU MapGPA:                   Not yet
