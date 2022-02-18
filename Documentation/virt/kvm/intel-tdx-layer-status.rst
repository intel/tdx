.. SPDX-License-Identifier: GPL-2.0

===================================
Intel Trust Dodmain Extensions(TDX)
===================================

Layer status
============
What qemu can do
----------------
- TDX VM TYPE is exposed to Qemu.
- Qemu can try to create VM of TDX VM type and then fails.

Patch Layer status
------------------
  Patch layer                          Status
* TDX, VMX coexistence:                 Applied
* TDX architectural definitions:        Applied
* TD VM creation/destruction:           Applying
* TD vcpu creation/destruction:         Not yet
* TDX EPT violation:                    Not yet
* TD finalization:                      Not yet
* TD vcpu enter/exit:                   Not yet
* TD vcpu interrupts/exit/hypercall:    Not yet

* KVM MMU GPA stolen bits:              Not yet
* KVM TDP refactoring for TDX:          Not yet
* KVM TDP MMU hooks:                    Not yet
* KVM TDP MMU MapGPA:                   Not yet
