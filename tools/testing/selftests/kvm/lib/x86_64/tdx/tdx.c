// SPDX-License-Identifier: GPL-2.0-only

#include <string.h>

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

void tdg_vp_vmcall_report_fatal_error(uint64_t error_code, uint64_t data_gpa)
{
	struct tdx_hypercall_args args;

	memset(&args, 0, sizeof(struct tdx_hypercall_args));

	if (data_gpa)
		error_code |= 0x8000000000000000;

	args.r11 = TDG_VP_VMCALL_REPORT_FATAL_ERROR;
	args.r12 = error_code;
	args.r13 = data_gpa;

	__tdx_hypercall(&args, 0);
}

uint64_t tdg_vp_vmcall_get_td_vmcall_info(uint64_t *r11, uint64_t *r12,
					uint64_t *r13, uint64_t *r14)
{
	uint64_t ret;
	struct tdx_hypercall_args args = {
		.r11 = TDG_VP_VMCALL_GET_TD_VM_CALL_INFO,
		.r12 = 0,
	};

	ret = __tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT);

	if (r11)
		*r11 = args.r11;
	if (r12)
		*r12 = args.r12;
	if (r13)
		*r13 = args.r13;
	if (r14)
		*r14 = args.r14;

	return ret;
}

uint64_t tdg_vp_vmcall_instruction_rdmsr(uint64_t index, uint64_t *ret_value)
{
	uint64_t ret;
	struct tdx_hypercall_args args = {
		.r11 = TDG_VP_VMCALL_INSTRUCTION_RDMSR,
		.r12 = index,
	};

	ret = __tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT);

	if (ret_value)
		*ret_value = args.r11;

	return ret;
}

uint64_t tdg_vp_vmcall_instruction_wrmsr(uint64_t index, uint64_t value)
{
	struct tdx_hypercall_args args = {
		.r11 = TDG_VP_VMCALL_INSTRUCTION_WRMSR,
		.r12 = index,
		.r13 = value,
	};

	return __tdx_hypercall(&args, 0);
}

uint64_t tdg_vp_vmcall_instruction_hlt(uint64_t interrupt_blocked_flag)
{
	struct tdx_hypercall_args args = {
		.r11 = TDG_VP_VMCALL_INSTRUCTION_HLT,
		.r12 = interrupt_blocked_flag,
	};

	return __tdx_hypercall(&args, 0);
}

uint64_t tdg_vp_vmcall_ve_request_mmio_read(uint64_t address, uint64_t size,
					uint64_t *data_out)
{
	uint64_t ret;
	struct tdx_hypercall_args args = {
		.r11 = TDG_VP_VMCALL_VE_REQUEST_MMIO,
		.r12 = size,
		.r13 = TDG_VP_VMCALL_VE_REQUEST_MMIO_READ,
		.r14 = address,
	};

	ret = __tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT);

	if (data_out)
		*data_out = args.r11;

	return ret;
}

uint64_t tdg_vp_vmcall_ve_request_mmio_write(uint64_t address, uint64_t size,
					uint64_t data_in)
{
	struct tdx_hypercall_args args = {
		.r11 = TDG_VP_VMCALL_VE_REQUEST_MMIO,
		.r12 = size,
		.r13 = TDG_VP_VMCALL_VE_REQUEST_MMIO_WRITE,
		.r14 = address,
		.r15 = data_in,
	};

	return __tdx_hypercall(&args, 0);
}

uint64_t tdg_vp_vmcall_instruction_cpuid(uint32_t eax, uint32_t ecx,
					uint32_t *ret_eax, uint32_t *ret_ebx,
					uint32_t *ret_ecx, uint32_t *ret_edx)
{
	uint64_t ret;
	struct tdx_hypercall_args args = {
		.r11 = TDG_VP_VMCALL_INSTRUCTION_CPUID,
		.r12 = eax,
		.r13 = ecx,
	};


	ret = __tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT);

	if (ret_eax)
		*ret_eax = args.r12;
	if (ret_ebx)
		*ret_ebx = args.r13;
	if (ret_ecx)
		*ret_ecx = args.r14;
	if (ret_edx)
		*ret_edx = args.r15;

	return ret;
}
