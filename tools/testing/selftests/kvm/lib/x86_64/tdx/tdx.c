// SPDX-License-Identifier: GPL-2.0-only

#include <string.h>

#include "tdx/tdcall.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"

void handle_userspace_tdg_vp_vmcall_exit(struct kvm_vcpu *vcpu)
{
	struct kvm_vm *vm = vcpu->vm;
	struct kvm_tdx_vmcall *vmcall_info = &vcpu->run->tdx.u.vmcall;
	uint64_t vmcall_subfunction = vmcall_info->subfunction;

	switch (vmcall_subfunction) {
	case TDG_VP_VMCALL_REPORT_FATAL_ERROR:
		vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
		vcpu->run->system_event.ndata = 3;
		vcpu->run->system_event.data[0] =
			TDG_VP_VMCALL_REPORT_FATAL_ERROR;
		vcpu->run->system_event.data[1] = vmcall_info->in_r12;
		vcpu->run->system_event.data[2] = vmcall_info->in_r13;
		vmcall_info->status_code = 0;
		break;
	case TDG_VP_VMCALL_MAP_GPA:
		{
		uint64_t gpa = vmcall_info->in_r12 & ~vm->arch.s_bit;
		bool shared_to_private = !(vm->arch.s_bit &
					   vmcall_info->in_r12);
		handle_memory_conversion(vm, gpa, vmcall_info->in_r13,
					 shared_to_private);
		vmcall_info->status_code = 0;
		break;
		}
	default:
		TEST_FAIL("TD VMCALL subfunction %lu is unsupported.\n",
			  vmcall_subfunction);
	}
}

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

uint64_t tdg_vp_info(uint64_t *rcx, uint64_t *rdx,
		     uint64_t *r8, uint64_t *r9,
		     uint64_t *r10, uint64_t *r11)
{
	uint64_t ret;
	struct tdx_module_output out;

	memset(&out, 0, sizeof(struct tdx_module_output));

	ret = __tdx_module_call(TDG_VP_INFO, 0, 0, 0, 0, &out);

	if (rcx)
		*rcx = out.rcx;
	if (rdx)
		*rdx = out.rdx;
	if (r8)
		*r8 = out.r8;
	if (r9)
		*r9 = out.r9;
	if (r10)
		*r10 = out.r10;
	if (r11)
		*r11 = out.r11;

	return ret;
}

uint64_t tdg_vp_vmcall_map_gpa(uint64_t address, uint64_t size, uint64_t *data_out)
{
	uint64_t ret;
	struct tdx_hypercall_args args = {
		.r11 = TDG_VP_VMCALL_MAP_GPA,
		.r12 = address,
		.r13 = size
	};

	ret = __tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT);

	if (data_out)
		*data_out = args.r11;
	return ret;
}
