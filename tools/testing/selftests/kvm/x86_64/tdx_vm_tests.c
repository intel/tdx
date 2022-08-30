// SPDX-License-Identifier: GPL-2.0-only

#include <fcntl.h>
#include <limits.h>
#include <kvm_util.h>
#include "../lib/x86_64/tdx.h"
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <test_util.h>
#include <unistd.h>
#include <processor.h>
#include <time.h>
#include <sys/mman.h>
#include<sys/wait.h>

#define CHECK_GUEST_COMPLETION(VCPU)								\
	(TEST_ASSERT(										\
		((VCPU)->run->exit_reason == KVM_EXIT_IO) &&					\
		((VCPU)->run->io.port == TDX_SUCCESS_PORT) &&					\
		((VCPU)->run->io.size == 4) &&							\
		((VCPU)->run->io.direction == TDX_IO_WRITE),					\
		"Unexpected exit values while waiting for test complition: %u (%s) %d %d %d\n",	\
		(VCPU)->run->exit_reason, exit_reason_str((VCPU)->run->exit_reason),		\
		(VCPU)->run->io.port, (VCPU)->run->io.size, (VCPU)->run->io.direction))

/*
 * There might be multiple tests we are running and if one test fails, it will
 * prevent the subsequent tests to run due to how tests are failing with
 * TEST_ASSERT function. The run_in_new_process function will run a test in a
 * new process context and wait for it to finish or fail to prevent TEST_ASSERT
 * to kill the main testing process.
 */
void run_in_new_process(void (*func)(void))
{
	if (fork() == 0) {
		func();
		exit(0);
	}
	wait(NULL);
}

/*
 * Verify that the TDX  is supported by the KVM.
 */
bool is_tdx_enabled(void)
{
	return !!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM));
}

/*
 * Do a dummy io exit to verify that the TD has been initialized correctly and
 * guest can run some code inside.
 */
TDX_GUEST_FUNCTION(guest_dummy_exit)
{
	tdvmcall_success();
}

/*
 * TD lifecycle test will create a TD which runs a dumy IO exit to verify that
 * the guest TD has been created correctly.
 */
void verify_td_lifecycle(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	printf("Verifying TD lifecycle:\n");
	/* Create a TD VM with no memory.*/
	vm = vm_create_tdx();

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vcpu = vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_dummy_exit,
			     TDX_FUNCTION_SIZE(guest_dummy_exit), 0);
	finalize_td_memory(vm);

	vcpu_run(vcpu);
	CHECK_GUEST_COMPLETION(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

int main(int argc, char **argv)
{
	if (!is_tdx_enabled()) {
		print_skip("TDX is not supported by the KVM");
		exit(KSFT_SKIP);
	}

	run_in_new_process(&verify_td_lifecycle);

	return 0;
}
