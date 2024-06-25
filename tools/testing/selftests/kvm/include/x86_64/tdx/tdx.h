/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_TDX_TDX_H
#define SELFTEST_TDX_TDX_H

#include <stdint.h>
#include "kvm_util.h"

#define TDG_VP_VMCALL_GET_TD_VM_CALL_INFO 0x10000
#define TDG_VP_VMCALL_INSTRUCTION_IO 30
#define TDG_VP_VMCALL_REPORT_FATAL_ERROR 0x10003

#define TDG_VP_VMCALL_INSTRUCTION_IO 30
#define TDG_VP_VMCALL_INSTRUCTION_RDMSR 31
#define TDG_VP_VMCALL_INSTRUCTION_WRMSR 32

void handle_userspace_tdg_vp_vmcall_exit(struct kvm_vcpu *vcpu);

uint64_t tdg_vp_vmcall_instruction_io(uint64_t port, uint64_t size,
				      uint64_t write, uint64_t *data);
void tdg_vp_vmcall_report_fatal_error(uint64_t error_code, uint64_t data_gpa);
uint64_t tdg_vp_vmcall_get_td_vmcall_info(uint64_t *r11, uint64_t *r12,
					uint64_t *r13, uint64_t *r14);
uint64_t tdg_vp_vmcall_instruction_rdmsr(uint64_t index, uint64_t *ret_value);
uint64_t tdg_vp_vmcall_instruction_wrmsr(uint64_t index, uint64_t value);
#endif // SELFTEST_TDX_TDX_H
