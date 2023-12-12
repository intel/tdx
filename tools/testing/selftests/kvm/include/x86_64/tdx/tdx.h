/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_TDX_TDX_H
#define SELFTEST_TDX_TDX_H

#include <stdint.h>

#define TDG_VP_VMCALL_INSTRUCTION_IO 30

uint64_t tdg_vp_vmcall_instruction_io(uint64_t port, uint64_t size,
				      uint64_t write, uint64_t *data);

#endif // SELFTEST_TDX_TDX_H
