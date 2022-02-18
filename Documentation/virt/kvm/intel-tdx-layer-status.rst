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
- Qemu can populate initial guest memory image.

Patch Layer status
------------------
  Patch layer                          Status

* TDX, VMX coexistence:                 Applied
* TDX architectural definitions:        Applied
* TD VM creation/destruction:           Applied
* TD vcpu creation/destruction:         Applied
* TDX EPT violation:                    Applying
* TD finalization:                      Not yet
* TD vcpu enter/exit:                   Not yet
* TD vcpu interrupts/exit/hypercall:    Not yet

