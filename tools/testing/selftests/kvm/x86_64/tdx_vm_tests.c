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

#define CHECK_IO(VCPU, PORT, SIZE, DIR)							\
	do {										\
		TEST_ASSERT((VCPU)->run->exit_reason == KVM_EXIT_IO,			\
			    "Got exit_reason other than KVM_EXIT_IO: %u (%s)\n",	\
			    (VCPU)->run->exit_reason,					\
			    exit_reason_str((VCPU)->run->exit_reason));			\
											\
		TEST_ASSERT(((VCPU)->run->exit_reason == KVM_EXIT_IO) &&		\
			    ((VCPU)->run->io.port == (PORT)) &&				\
			    ((VCPU)->run->io.size == (SIZE)) &&				\
			    ((VCPU)->run->io.direction == (DIR)),			\
			    "Got an unexpected IO exit values: %u (%s) %d %d %d\n",	\
			    (VCPU)->run->exit_reason,					\
			    exit_reason_str((VCPU)->run->exit_reason),			\
			    (VCPU)->run->io.port, (VCPU)->run->io.size,			\
			    (VCPU)->run->io.direction);					\
	} while (0)

#define CHECK_GUEST_FAILURE(VCPU)							\
	do {										\
		if ((VCPU)->run->exit_reason == KVM_EXIT_SYSTEM_EVENT)			\
			TEST_FAIL("Guest reported error. error code: %lld (0x%llx)\n",	\
				  (VCPU)->run->system_event.data[1],			\
				  (VCPU)->run->system_event.data[1]);			\
	} while (0)

static uint64_t read_64bit_from_guest(struct kvm_vcpu *vcpu, uint64_t port)
{
	uint32_t lo, hi;
	uint64_t res;

	CHECK_IO(vcpu, port, 4, TDX_IO_WRITE);
	lo = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	vcpu_run(vcpu);

	CHECK_IO(vcpu, port, 4, TDX_IO_WRITE);
	hi = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	res = hi;
	res = (res << 32) | lo;
	return res;
}


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
 * Find a specific CPUID entry.
 */
static struct kvm_cpuid_entry2 *
find_cpuid_entry(struct tdx_cpuid_data cpuid_data, uint32_t function,
		 uint32_t index)
{
	struct kvm_cpuid_entry2 *e;
	int i;

	for (i = 0; i < cpuid_data.cpuid.nent; i++) {
		e = &cpuid_data.entries[i];

		if (e->function == function &&
		    (e->index == index ||
		     !(e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)))
			return e;
	}
	return NULL;
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

/*
 * Verifies TDX_REPORT_FATAL_ERROR functionality.
 */
TDX_GUEST_FUNCTION(guest_code_report_fatal_error)
{
	uint64_t err;
	/* Note: err should follow the GHCI spec definition:
	 * bits 31:0 should be set to 0.
	 * bits 62:32 are used for TD-specific extended error code.
	 * bit 63 is used to mark additional information in shared memory.
	 */
	err = 0x0BAAAAAD00000000;

	if (err)
		tdvmcall_fatal(err);

	tdvmcall_success();
}

void verify_report_fatal_error(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	printf("Verifying report_fatal_error:\n");
	/* Create a TD VM with no memory.*/
	vm = vm_create_tdx();

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vcpu = vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_code_report_fatal_error,
			     TDX_FUNCTION_SIZE(guest_code_report_fatal_error),
			     0);
	finalize_td_memory(vm);

	vcpu_run(vcpu);
	ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	ASSERT_EQ(vcpu->run->system_event.ndata, 3);
	ASSERT_EQ(vcpu->run->system_event.data[0], TDX_REPORT_FATAL_ERROR);
	ASSERT_EQ(vcpu->run->system_event.data[1], 0x0BAAAAAD00000000);
	ASSERT_EQ(vcpu->run->system_event.data[2], 0);

	vcpu_run(vcpu);
	CHECK_GUEST_COMPLETION(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies IO functionality by writing a |value| to a predefined port.
 * Verifies that the read value is |value| + 1 from the same port.
 * If all the tests are passed then write a value to port TDX_TEST_PORT
 */
TDX_GUEST_FUNCTION(guest_io_exit)
{
	uint64_t data_out, data_in, delta;
	uint64_t ret;

	data_out = 0xAB;

	ret = tdvmcall_io(TDX_TEST_PORT, 1, TDX_IO_WRITE, &data_out);
	if (ret)
		tdvmcall_fatal(ret);

	ret = tdvmcall_io(TDX_TEST_PORT, 1, TDX_IO_READ, &data_in);
	if (ret)
		tdvmcall_fatal(ret);

	delta = data_in - data_out;
	if (delta != 1)
		tdvmcall_fatal(ret);

	tdvmcall_success();
}

void verify_td_ioexit(void)
{
	struct kvm_vcpu *vcpu;
	uint32_t port_data;
	struct kvm_vm *vm;

	printf("Verifying TD IO Exit:\n");
	/* Create a TD VM with no memory.*/
	vm = vm_create_tdx();

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vcpu = vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_io_exit,
			     TDX_FUNCTION_SIZE(guest_io_exit), 0);
	finalize_td_memory(vm);

	/* Wait for guest to do a IO write */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	CHECK_IO(vcpu, TDX_TEST_PORT, 1, TDX_IO_WRITE);
	port_data = *(uint8_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	printf("\t ... IO WRITE: OK\n");

	/*
	 * Wait for the guest to do a IO read. Provide the previos written data
	 * + 1 back to the guest
	 */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	CHECK_IO(vcpu, TDX_TEST_PORT, 1, TDX_IO_READ);
	*(uint8_t *)((void *)vcpu->run + vcpu->run->io.data_offset) = port_data + 1;

	printf("\t ... IO READ: OK\n");

	/*
	 * Wait for the guest to complete execution successfully. The read
	 * value is checked within the guest.
	 */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	CHECK_GUEST_COMPLETION(vcpu);

	printf("\t ... IO verify read/write values: OK\n");
	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies CPUID functionality by reading CPUID values in guest. The guest
 * will then send the values to userspace using an IO write to be checked
 * against the expected values.
 */
TDX_GUEST_FUNCTION(guest_code_cpuid)
{
	uint64_t err;
	uint32_t eax, ebx, edx, ecx;

	// Read CPUID leaf 0x1.
	cpuid(1, &eax, &ebx, &ecx, &edx);

	err = tdvm_report_to_user_space(ebx);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_to_user_space(ecx);
	if (err)
		tdvmcall_fatal(err);

	tdvmcall_success();
}

void verify_td_cpuid(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint32_t ebx, ecx;
	struct kvm_cpuid_entry2 *cpuid_entry;
	struct tdx_cpuid_data cpuid_data;
	uint32_t guest_clflush_line_size;
	uint32_t guest_max_addressable_ids, host_max_addressable_ids;
	uint32_t guest_sse3_enabled;
	uint32_t guest_fma_enabled;
	uint32_t guest_initial_apic_id;
	int ret;

	printf("Verifying TD CPUID:\n");
	/* Create a TD VM with no memory.*/
	vm = vm_create_tdx();

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vcpu = vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_code_cpuid,
			     TDX_FUNCTION_SIZE(guest_code_cpuid), 0);
	finalize_td_memory(vm);

	/* Wait for guest to report ebx value */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	CHECK_IO(vcpu, TDX_DATA_REPORT_PORT, 4, TDX_IO_WRITE);
	ebx = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	/* Wait for guest to report either ecx value or error */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	CHECK_IO(vcpu, TDX_DATA_REPORT_PORT, 4, TDX_IO_WRITE);
	ecx = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	/* Wait for guest to complete execution */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	CHECK_GUEST_COMPLETION(vcpu);

	/* Verify the CPUID values we got from the guest. */
	printf("\t ... Verifying CPUID values from guest\n");

	/* Get KVM CPUIDs for reference */
	memset(&cpuid_data, 0, sizeof(cpuid_data));
	cpuid_data.cpuid.nent = KVM_MAX_CPUID_ENTRIES;
	ret = ioctl(vm->kvm_fd, KVM_GET_SUPPORTED_CPUID, &cpuid_data);
	TEST_ASSERT(!ret, "KVM_GET_SUPPORTED_CPUID failed\n");
	cpuid_entry = find_cpuid_entry(cpuid_data, 1, 0);
	TEST_ASSERT(cpuid_entry, "CPUID entry missing\n");

	host_max_addressable_ids = (cpuid_entry->ebx >> 16) & 0xFF;

	guest_sse3_enabled = ecx & 0x1;  // Native
	guest_clflush_line_size = (ebx >> 8) & 0xFF;  // Fixed
	guest_max_addressable_ids = (ebx >> 16) & 0xFF;  // As Configured
	guest_fma_enabled = (ecx >> 12) & 0x1;  // As Configured (if Native)
	guest_initial_apic_id = (ebx >> 24) & 0xFF;  // Calculated

	ASSERT_EQ(guest_sse3_enabled, 1);
	ASSERT_EQ(guest_clflush_line_size, 8);
	ASSERT_EQ(guest_max_addressable_ids, host_max_addressable_ids);

	/* TODO: This only tests the native value. To properly test
	 * "As Configured (if Native)" we need to override this value
	 * in the TD params
	 */
	ASSERT_EQ(guest_fma_enabled, 1);

	/* TODO: guest_initial_apic_id is calculated based on the number of
	 * VCPUs in the TD. From the spec: "Virtual CPU index, starting from 0
	 * and allocated sequentially on each successful TDH.VP.INIT"
	 * To test non-trivial values we either need a TD with multiple VCPUs
	 * or to pick a different calculated value.
	 */
	ASSERT_EQ(guest_initial_apic_id, 0);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies get_td_vmcall_info functionality.
 */
TDX_GUEST_FUNCTION(guest_code_get_td_vmcall_info)
{
	uint64_t err;
	uint64_t r11, r12, r13, r14;

	err = tdvmcall_get_td_vmcall_info(&r11, &r12, &r13, &r14);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_64bit_to_user_space(r11);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_64bit_to_user_space(r12);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_64bit_to_user_space(r13);
	if (err)
		tdvmcall_fatal(err);

	err = tdvm_report_64bit_to_user_space(r14);
	if (err)
		tdvmcall_fatal(err);

	tdvmcall_success();
}

void verify_get_td_vmcall_info(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t r11, r12, r13, r14;

	printf("Verifying TD get vmcall info:\n");
	/* Create a TD VM with no memory.*/
	vm = vm_create_tdx();

	/* Allocate TD guest memory and initialize the TD.*/
	initialize_td(vm);

	/* Initialize the TD vcpu and copy the test code to the guest memory.*/
	vcpu = vm_vcpu_add_tdx(vm, 0);

	/* Setup and initialize VM memory */
	prepare_source_image(vm, guest_code_get_td_vmcall_info,
			     TDX_FUNCTION_SIZE(guest_code_get_td_vmcall_info),
			     0);
	finalize_td_memory(vm);

	/* Wait for guest to report r11 value */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	r11 = read_64bit_from_guest(vcpu, TDX_DATA_REPORT_PORT);

	/* Wait for guest to report r12 value */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	r12 = read_64bit_from_guest(vcpu, TDX_DATA_REPORT_PORT);

	/* Wait for guest to report r13 value */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	r13 = read_64bit_from_guest(vcpu, TDX_DATA_REPORT_PORT);

	/* Wait for guest to report r14 value */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
	r14 = read_64bit_from_guest(vcpu, TDX_DATA_REPORT_PORT);

	ASSERT_EQ(r11, 0);
	ASSERT_EQ(r12, 0);
	ASSERT_EQ(r13, 0);
	ASSERT_EQ(r14, 0);

	/* Wait for guest to complete execution */
	vcpu_run(vcpu);
	CHECK_GUEST_FAILURE(vcpu);
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
	run_in_new_process(&verify_report_fatal_error);
	run_in_new_process(&verify_td_ioexit);
	run_in_new_process(&verify_td_cpuid);
	run_in_new_process(&verify_get_td_vmcall_info);

	return 0;
}
