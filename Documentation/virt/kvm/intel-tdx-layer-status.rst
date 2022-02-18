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
- Qemu can populate initial guest memory image.

Patch Layer status
------------------
  Patch layer                          Status

* TDX, VMX coexistence:                 Applied
* TDX architectural definitions:        Applied
* TD VM creation/destruction:           Applied
* TD vcpu creation/destruction:         Applying
* TDX EPT violation:                    Not yet
* TD finalization:                      Not yet
* TD vcpu enter/exit:                   Not yet
* TD vcpu interrupts/exit/hypercall:    Not yet
