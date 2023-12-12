// SPDX-License-Identifier: GPL-2.0-only

#include "tdx/tdcall.h"
#include "tdx/tdx.h"

uint64_t tdg_vp_vmcall_instruction_io(uint64_t port, uint64_t size,
				      uint64_t write, uint64_t *data)
{
	uint64_t ret;
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = TDG_VP_VMCALL_INSTRUCTION_IO,
		.r12 = size,
		.r13 = write,
		.r14 = port,
	};

	if (write)
		args.r15 = *data;

	ret = __tdx_hypercall(&args, write ? 0 : TDX_HCALL_HAS_OUTPUT);

	if (!write)
		*data = args.r11;

	return ret;
}
