/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_TDX_TDX_H
#define SELFTEST_TDX_TDX_H

#include <stdint.h>
#include "kvm_util.h"

#define TDG_VP_INFO 1
#define TDG_MEM_PAGE_ACCEPT 6

#define TDG_VP_VMCALL_GET_TD_VM_CALL_INFO 0x10000
#define TDG_VP_VMCALL_MAP_GPA 0x10001
#define TDG_VP_VMCALL_INSTRUCTION_IO 30
#define TDG_VP_VMCALL_REPORT_FATAL_ERROR 0x10003

#define TDG_VP_VMCALL_INSTRUCTION_CPUID 10
#define TDG_VP_VMCALL_INSTRUCTION_HLT 12
#define TDG_VP_VMCALL_INSTRUCTION_IO 30
#define TDG_VP_VMCALL_INSTRUCTION_RDMSR 31
#define TDG_VP_VMCALL_INSTRUCTION_WRMSR 32
#define TDG_VP_VMCALL_VE_REQUEST_MMIO 48

void handle_userspace_tdg_vp_vmcall_exit(struct kvm_vcpu *vcpu);

uint64_t tdg_vp_vmcall_instruction_io(uint64_t port, uint64_t size,
				      uint64_t write, uint64_t *data);
void tdg_vp_vmcall_report_fatal_error(uint64_t error_code, uint64_t data_gpa);
uint64_t tdg_vp_vmcall_get_td_vmcall_info(uint64_t *r11, uint64_t *r12,
					uint64_t *r13, uint64_t *r14);
uint64_t tdg_vp_vmcall_instruction_rdmsr(uint64_t index, uint64_t *ret_value);
uint64_t tdg_vp_vmcall_instruction_wrmsr(uint64_t index, uint64_t value);
uint64_t tdg_vp_vmcall_instruction_hlt(uint64_t interrupt_blocked_flag);
uint64_t tdg_vp_vmcall_ve_request_mmio_read(uint64_t address, uint64_t size,
					uint64_t *data_out);
uint64_t tdg_vp_vmcall_ve_request_mmio_write(uint64_t address, uint64_t size,
					uint64_t data_in);
uint64_t tdg_vp_vmcall_instruction_cpuid(uint32_t eax, uint32_t ecx,
					uint32_t *ret_eax, uint32_t *ret_ebx,
					uint32_t *ret_ecx, uint32_t *ret_edx);
uint64_t tdg_vp_info(uint64_t *rcx, uint64_t *rdx,
		     uint64_t *r8, uint64_t *r9,
		     uint64_t *r10, uint64_t *r11);
uint64_t tdg_vp_vmcall_map_gpa(uint64_t address, uint64_t size, uint64_t *data_out);
uint64_t tdg_mem_page_accept(uint64_t gpa, uint8_t level);

#endif // SELFTEST_TDX_TDX_H
