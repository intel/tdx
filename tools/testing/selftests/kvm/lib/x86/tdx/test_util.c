// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kvm_util.h"
#include "tdx/tdx.h"
#include "tdx/test_util.h"

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
