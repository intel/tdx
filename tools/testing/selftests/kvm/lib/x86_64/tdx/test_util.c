// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kvm_util_base.h"
#include "tdx/tdx.h"
#include "tdx/test_util.h"

void run_in_new_process(void (*func)(void))
{
	if (fork() == 0) {
		func();
		exit(0);
	}
	wait(NULL);
}

bool is_tdx_enabled(void)
{
	return !!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_PROTECTED_VM));
}

void tdx_test_success(void)
{
	uint64_t code = 0;

	tdg_vp_vmcall_instruction_io(TDX_TEST_SUCCESS_PORT,
				     TDX_TEST_SUCCESS_SIZE,
				     TDG_VP_VMCALL_INSTRUCTION_IO_WRITE, &code);
}
