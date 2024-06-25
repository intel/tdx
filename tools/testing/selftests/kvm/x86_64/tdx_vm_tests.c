// SPDX-License-Identifier: GPL-2.0-only

#include <signal.h>
#include "kvm_util.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"
#include "test_util.h"

void guest_code_lifecycle(void)
{
	tdx_test_success();
}

void verify_td_lifecycle(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_code_lifecycle);
	td_finalize(vm);

	printf("Verifying TD lifecycle:\n");

	vcpu_run(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

void guest_code_report_fatal_error(void)
{
uint64_t err;

	/*
	 * Note: err should follow the GHCI spec definition:
	 * bits 31:0 should be set to 0.
	 * bits 62:32 are used for TD-specific extended error code.
	 * bit 63 is used to mark additional information in shared memory.
	 */
	err = 0x0BAAAAAD00000000;
	if (err)
		tdx_test_fatal(err);

	tdx_test_success();
}

void verify_report_fatal_error(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_code_report_fatal_error);
	td_finalize(vm);

	printf("Verifying report_fatal_error:\n");

	td_vcpu_run(vcpu);

	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	TEST_ASSERT_EQ(vcpu->run->system_event.ndata, 3);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[0], TDG_VP_VMCALL_REPORT_FATAL_ERROR);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[1], 0x0BAAAAAD00000000);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[2], 0);

	vcpu_run(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

int main(int argc, char **argv)
{
	setbuf(stdout, NULL);

	if (!is_tdx_enabled()) {
		print_skip("TDX is not supported by the KVM");
		exit(KSFT_SKIP);
	}

	run_in_new_process(&verify_td_lifecycle);
	run_in_new_process(&verify_report_fatal_error);

	return 0;
}
