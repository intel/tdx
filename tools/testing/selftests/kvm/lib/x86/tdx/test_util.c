// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kvm_util.h"
#include "tdx/tdcall.h"
#include "tdx/tdx.h"
#include "tdx/test_util.h"

void tdx_test_assert_io(struct kvm_vcpu *vcpu, uint16_t port, uint8_t size,
			uint8_t direction)
{
	TEST_ASSERT(vcpu->run->exit_reason == KVM_EXIT_IO,
		    "Got exit_reason other than KVM_EXIT_IO: %u (%s)\n",
		    vcpu->run->exit_reason,
		    exit_reason_str(vcpu->run->exit_reason));

	TEST_ASSERT(vcpu->run->exit_reason == KVM_EXIT_IO &&
		    vcpu->run->io.port == port &&
		    vcpu->run->io.size == size &&
		    vcpu->run->io.direction == direction,
		    "Got unexpected IO exit values: %u (%s) %u %u %u\n",
		    vcpu->run->exit_reason,
		    exit_reason_str(vcpu->run->exit_reason),
		    vcpu->run->io.port, vcpu->run->io.size,
		    vcpu->run->io.direction);
}

void tdx_test_check_guest_failure(struct kvm_vcpu *vcpu)
{
	if (vcpu->run->exit_reason == KVM_EXIT_SYSTEM_EVENT)
		TEST_FAIL("Guest reported error. error code: %lld (0x%llx)\n",
			  vcpu->run->system_event.data[0],
			  vcpu->run->system_event.data[0]);
}

int run_in_new_process(void (*func)(void))
{
	int wstatus;
	pid_t ret;

	if (fork() == 0) {
		func();
		exit(0);
	}
	ret = wait(&wstatus);
	if (ret == -1)
		return -1;

	if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus))
		return -1;
	else if (WIFSIGNALED(wstatus))
		return -1;

	return 0;
}

bool is_tdx_enabled(void)
{
	return !!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM));
}

void tdx_test_success(void)
{
	uint64_t code = 0;

	tdg_vp_vmcall_instruction_io(TDX_TEST_SUCCESS_PORT,
				     TDX_TEST_SUCCESS_SIZE,
				     TDG_VP_VMCALL_INSTRUCTION_IO_WRITE, &code);
}

/*
 * Assert that tdx_test_success() was called in the guest.
 */
void tdx_test_assert_success(struct kvm_vcpu *vcpu)
{
	TEST_ASSERT((vcpu->run->exit_reason == KVM_EXIT_IO) &&
		    (vcpu->run->io.port == TDX_TEST_SUCCESS_PORT) &&
		    (vcpu->run->io.size == TDX_TEST_SUCCESS_SIZE) &&
		    (vcpu->run->io.direction == TDG_VP_VMCALL_INSTRUCTION_IO_WRITE),
		    "Unexpected exit values while waiting for test completion: %u (%s) %d %d %d\n",
		    vcpu->run->exit_reason,
		    exit_reason_str(vcpu->run->exit_reason),
		    vcpu->run->io.port, vcpu->run->io.size,
		    vcpu->run->io.direction);
}

void tdx_test_fatal_with_data(uint64_t error_code, uint64_t data_gpa)
{
	tdg_vp_vmcall_report_fatal_error(error_code, data_gpa);
}

void tdx_test_fatal(uint64_t error_code)
{
	tdx_test_fatal_with_data(error_code, 0);
}

uint64_t tdx_test_report_to_user_space(uint32_t data)
{
	/* Upcast data to match tdg_vp_vmcall_instruction_io signature */
	uint64_t data_64 = data;

	return tdg_vp_vmcall_instruction_io(TDX_TEST_REPORT_PORT,
					TDX_TEST_REPORT_SIZE,
					TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					&data_64);
}

uint64_t tdx_test_send_64bit(uint64_t port, uint64_t data)
{
	uint64_t data_hi = (data >> 32) & 0xFFFFFFFF;
	uint64_t data_lo = data & 0xFFFFFFFF;
	uint64_t err;

	err = tdg_vp_vmcall_instruction_io(port, 4,
					   TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					   &data_lo);
	if (err)
		return err;

	return tdg_vp_vmcall_instruction_io(port, 4,
					    TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					    &data_hi);
}

uint64_t tdx_test_report_64bit_to_user_space(uint64_t data)
{
	return tdx_test_send_64bit(TDX_TEST_REPORT_PORT, data);
}

uint64_t tdx_test_read_64bit(struct kvm_vcpu *vcpu, uint64_t port)
{
	uint32_t lo, hi;
	uint64_t res;

	tdx_test_assert_io(vcpu, port, 4, TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	lo = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	vcpu_run(vcpu);

	tdx_test_assert_io(vcpu, port, 4, TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	hi = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	res = hi;
	res = (res << 32) | lo;
	return res;
}

uint64_t tdx_test_read_64bit_report_from_guest(struct kvm_vcpu *vcpu)
{
	return tdx_test_read_64bit(vcpu, TDX_TEST_REPORT_PORT);
}
