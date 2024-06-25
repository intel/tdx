// SPDX-License-Identifier: GPL-2.0-only

#include <signal.h>
#include "kvm_util.h"
#include "processor.h"
#include "tdx/tdcall.h"
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

#define TDX_IOEXIT_TEST_PORT 0x50

/*
 * Verifies IO functionality by writing a |value| to a predefined port.
 * Verifies that the read value is |value| + 1 from the same port.
 * If all the tests are passed then write a value to port TDX_TEST_PORT
 */
void guest_ioexit(void)
{
	uint64_t data_out, data_in, delta;
	uint64_t ret;

	data_out = 0xAB;
	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 1,
					TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					&data_out);
	if (ret)
		tdx_test_fatal(ret);

	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 1,
					TDG_VP_VMCALL_INSTRUCTION_IO_READ,
					&data_in);
	if (ret)
		tdx_test_fatal(ret);

	delta = data_in - data_out;
	if (delta != 1)
		tdx_test_fatal(ret);

	tdx_test_success();
}

void verify_td_ioexit(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	uint32_t port_data;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_ioexit);
	td_finalize(vm);

	printf("Verifying TD IO Exit:\n");

	/* Wait for guest to do a IO write */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IOEXIT_TEST_PORT, 1,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	port_data = *(uint8_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	printf("\t ... IO WRITE: OK\n");

	/*
	 * Wait for the guest to do a IO read. Provide the previous written data
	 * + 1 back to the guest
	 */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IOEXIT_TEST_PORT, 1,
			TDG_VP_VMCALL_INSTRUCTION_IO_READ);
	*(uint8_t *)((void *)vcpu->run + vcpu->run->io.data_offset) = port_data + 1;

	printf("\t ... IO READ: OK\n");

	/*
	 * Wait for the guest to complete execution successfully. The read
	 * value is checked within the guest.
	 */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	printf("\t ... IO verify read/write values: OK\n");
	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies CPUID functionality by reading CPUID values in guest. The guest
 * will then send the values to userspace using an IO write to be checked
 * against the expected values.
 */
void guest_code_cpuid(void)
{
	uint64_t err;
	uint32_t ebx, ecx;

	/* Read CPUID leaf 0x1 */
	asm volatile (
		"cpuid"
		: "=b" (ebx), "=c" (ecx)
		: "a" (0x1)
		: "edx");

	err = tdx_test_report_to_user_space(ebx);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_to_user_space(ecx);
	if (err)
		tdx_test_fatal(err);

	tdx_test_success();
}

void verify_td_cpuid(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	uint32_t ebx, ecx;
	const struct kvm_cpuid_entry2 *cpuid_entry;
	uint32_t guest_clflush_line_size;
	uint32_t guest_max_addressable_ids, host_max_addressable_ids;
	uint32_t guest_sse3_enabled;
	uint32_t guest_fma_enabled;
	uint32_t guest_initial_apic_id;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_code_cpuid);
	td_finalize(vm);

	printf("Verifying TD CPUID:\n");

	/* Wait for guest to report ebx value */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_TEST_REPORT_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	ebx = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	/* Wait for guest to report either ecx value or error */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_TEST_REPORT_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	ecx = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	/* Wait for guest to complete execution */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	/* Verify the CPUID values we got from the guest. */
	printf("\t ... Verifying CPUID values from guest\n");

	/* Get KVM CPUIDs for reference */
	cpuid_entry = get_cpuid_entry(kvm_get_supported_cpuid(), 1, 0);
	TEST_ASSERT(cpuid_entry, "CPUID entry missing\n");

	host_max_addressable_ids = (cpuid_entry->ebx >> 16) & 0xFF;

	guest_sse3_enabled = ecx & 0x1;  // Native
	guest_clflush_line_size = (ebx >> 8) & 0xFF;  // Fixed
	guest_max_addressable_ids = (ebx >> 16) & 0xFF;  // As Configured
	guest_fma_enabled = (ecx >> 12) & 0x1;  // As Configured (if Native)
	guest_initial_apic_id = (ebx >> 24) & 0xFF;  // Calculated

	TEST_ASSERT_EQ(guest_sse3_enabled, 1);
	TEST_ASSERT_EQ(guest_clflush_line_size, 8);
	TEST_ASSERT_EQ(guest_max_addressable_ids, host_max_addressable_ids);

	/* TODO: This only tests the native value. To properly test
	 * "As Configured (if Native)" we need to override this value
	 * in the TD params
	 */
	TEST_ASSERT_EQ(guest_fma_enabled, 1);

	/* TODO: guest_initial_apic_id is calculated based on the number of
	 * VCPUs in the TD. From the spec: "Virtual CPU index, starting from 0
	 * and allocated sequentially on each successful TDH.VP.INIT"
	 * To test non-trivial values we either need a TD with multiple VCPUs
	 * or to pick a different calculated value.
	 */
	TEST_ASSERT_EQ(guest_initial_apic_id, 0);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies get_td_vmcall_info functionality.
 */
void guest_code_get_td_vmcall_info(void)
{
	uint64_t err;
	uint64_t r11, r12, r13, r14;

	err = tdg_vp_vmcall_get_td_vmcall_info(&r11, &r12, &r13, &r14);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_64bit_to_user_space(r11);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_64bit_to_user_space(r12);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_64bit_to_user_space(r13);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_64bit_to_user_space(r14);
	if (err)
		tdx_test_fatal(err);

	tdx_test_success();
}

void verify_get_td_vmcall_info(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	uint64_t r11, r12, r13, r14;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_code_get_td_vmcall_info);
	td_finalize(vm);

	printf("Verifying TD get vmcall info:\n");

	/* Wait for guest to report r11 value */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	r11 = tdx_test_read_64bit_report_from_guest(vcpu);

	/* Wait for guest to report r12 value */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	r12 = tdx_test_read_64bit_report_from_guest(vcpu);

	/* Wait for guest to report r13 value */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	r13 = tdx_test_read_64bit_report_from_guest(vcpu);

	/* Wait for guest to report r14 value */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	r14 = tdx_test_read_64bit_report_from_guest(vcpu);

	TEST_ASSERT_EQ(r11, 0);
	TEST_ASSERT_EQ(r12, 0);
	TEST_ASSERT_EQ(r13, 0);
	TEST_ASSERT_EQ(r14, 0);

	/* Wait for guest to complete execution */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
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
	run_in_new_process(&verify_td_ioexit);
	run_in_new_process(&verify_td_cpuid);
	run_in_new_process(&verify_get_td_vmcall_info);

	return 0;
}
