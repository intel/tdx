// SPDX-License-Identifier: GPL-2.0-only

#include <fcntl.h>
#include <limits.h>
#include <kvm_util.h>
#include "../lib/kvm_util_internal.h"
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
	uint64_t data;

	data = 0xAB;
	tdvmcall_io(TDX_TEST_PORT, 1, 1, &data);
}

/*
 * TD lifecycle test will create a TD which runs a dumy IO exit to verify that
 * the guest TD has been created correctly.
 */
void  verify_td_lifecycle(void)
{
	struct kvm_vm *vm;
	struct kvm_run *run;

	printf("Verifying TD lifecycle:\n");
	/* Create a TD VM with no memory.*/
	vm = __vm_create(VM_MODE_DEFAULT, 0, O_RDWR, KVM_X86_TDX_VM);

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_dummy_exit,
			     TDX_FUNCTION_SIZE(guest_dummy_exit), 0);
	finalize_td_memory(vm);

	run = vcpu_state(vm, 0);
	vcpu_run(vm, 0);
	TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
		    "Got exit_reason other than KVM_EXIT_IO: %u (%s)\n",
		    run->exit_reason,
		    exit_reason_str(run->exit_reason));

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}
int main(int argc, char **argv)
{
	if (!is_tdx_enabled()) {
		printf("TDX is not supported by the KVM\n"
		       "Skipping the TDX tests.\n");
		return 0;
	}

	run_in_new_process(&verify_td_lifecycle);

	return 0;
}
