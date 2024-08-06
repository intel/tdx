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
	tdx_filter_cpuid(vm, vcpu->cpuid);
	cpuid_entry = vcpu_get_cpuid_entry(vcpu, 1);
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
	TEST_ASSERT_EQ(guest_fma_enabled, (cpuid_entry->ecx >> 12) & 0x1);

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

#define TDX_IO_WRITES_TEST_PORT 0x51

/*
 * Verifies IO functionality by writing values of different sizes
 * to the host.
 */
void guest_io_writes(void)
{
	uint64_t byte_1 = 0xAB;
	uint64_t byte_2 = 0xABCD;
	uint64_t byte_4 = 0xFFABCDEF;
	uint64_t ret;

	ret = tdg_vp_vmcall_instruction_io(TDX_IO_WRITES_TEST_PORT, 1,
					TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					&byte_1);
	if (ret)
		tdx_test_fatal(ret);

	ret = tdg_vp_vmcall_instruction_io(TDX_IO_WRITES_TEST_PORT, 2,
					TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					&byte_2);
	if (ret)
		tdx_test_fatal(ret);

	ret = tdg_vp_vmcall_instruction_io(TDX_IO_WRITES_TEST_PORT, 4,
					TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					&byte_4);
	if (ret)
		tdx_test_fatal(ret);

	// Write an invalid number of bytes.
	ret = tdg_vp_vmcall_instruction_io(TDX_IO_WRITES_TEST_PORT, 5,
					TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					&byte_4);
	if (ret)
		tdx_test_fatal(ret);

	tdx_test_success();
}

void verify_guest_writes(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	uint8_t byte_1;
	uint16_t byte_2;
	uint32_t byte_4;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_io_writes);
	td_finalize(vm);

	printf("Verifying guest writes:\n");

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IO_WRITES_TEST_PORT, 1,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	byte_1 = *(uint8_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IO_WRITES_TEST_PORT, 2,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	byte_2 = *(uint16_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IO_WRITES_TEST_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	byte_4 = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	TEST_ASSERT_EQ(byte_1, 0xAB);
	TEST_ASSERT_EQ(byte_2, 0xABCD);
	TEST_ASSERT_EQ(byte_4, 0xFFABCDEF);

	td_vcpu_run(vcpu);
	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[1], TDG_VP_VMCALL_INVALID_OPERAND);

	td_vcpu_run(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

#define TDX_IO_READS_TEST_PORT 0x52

/*
 * Verifies IO functionality by reading values of different sizes
 * from the host.
 */
void guest_io_reads(void)
{
	uint64_t data;
	uint64_t ret;

	ret = tdg_vp_vmcall_instruction_io(TDX_IO_READS_TEST_PORT, 1,
					TDG_VP_VMCALL_INSTRUCTION_IO_READ,
					&data);
	if (ret)
		tdx_test_fatal(ret);
	if (data != 0xAB)
		tdx_test_fatal(1);

	ret = tdg_vp_vmcall_instruction_io(TDX_IO_READS_TEST_PORT, 2,
					TDG_VP_VMCALL_INSTRUCTION_IO_READ,
					&data);
	if (ret)
		tdx_test_fatal(ret);
	if (data != 0xABCD)
		tdx_test_fatal(2);

	ret = tdg_vp_vmcall_instruction_io(TDX_IO_READS_TEST_PORT, 4,
					TDG_VP_VMCALL_INSTRUCTION_IO_READ,
					&data);
	if (ret)
		tdx_test_fatal(ret);
	if (data != 0xFFABCDEF)
		tdx_test_fatal(4);

	// Read an invalid number of bytes.
	ret = tdg_vp_vmcall_instruction_io(TDX_IO_READS_TEST_PORT, 5,
					TDG_VP_VMCALL_INSTRUCTION_IO_READ,
					&data);
	if (ret)
		tdx_test_fatal(ret);

	tdx_test_success();
}

void verify_guest_reads(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_io_reads);
	td_finalize(vm);

	printf("Verifying guest reads:\n");

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IO_READS_TEST_PORT, 1,
			TDG_VP_VMCALL_INSTRUCTION_IO_READ);
	*(uint8_t *)((void *)vcpu->run + vcpu->run->io.data_offset) = 0xAB;

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IO_READS_TEST_PORT, 2,
			TDG_VP_VMCALL_INSTRUCTION_IO_READ);
	*(uint16_t *)((void *)vcpu->run + vcpu->run->io.data_offset) = 0xABCD;

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IO_READS_TEST_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_READ);
	*(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset) = 0xFFABCDEF;

	td_vcpu_run(vcpu);
	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[1], TDG_VP_VMCALL_INVALID_OPERAND);

	td_vcpu_run(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Define a filter which denies all MSR access except the following:
 * MSR_X2APIC_APIC_ICR: Allow read/write access (allowed by default)
 * MSR_IA32_MISC_ENABLE: Allow read access
 * MSR_IA32_POWER_CTL: Allow write access
 */
#define MSR_X2APIC_APIC_ICR 0x830
static u64 tdx_msr_test_allow_bits = 0xFFFFFFFFFFFFFFFF;
struct kvm_msr_filter tdx_msr_test_filter = {
	.flags = KVM_MSR_FILTER_DEFAULT_DENY,
	.ranges = {
		{
			.flags = KVM_MSR_FILTER_READ,
			.nmsrs = 1,
			.base = MSR_IA32_MISC_ENABLE,
			.bitmap = (uint8_t *)&tdx_msr_test_allow_bits,
		}, {
			.flags = KVM_MSR_FILTER_WRITE,
			.nmsrs = 1,
			.base = MSR_IA32_POWER_CTL,
			.bitmap = (uint8_t *)&tdx_msr_test_allow_bits,
		},
	},
};

/*
 * Verifies MSR read functionality.
 */
void guest_msr_read(void)
{
	uint64_t data;
	uint64_t ret;

	ret = tdg_vp_vmcall_instruction_rdmsr(MSR_X2APIC_APIC_ICR, &data);
	if (ret)
		tdx_test_fatal(ret);

	ret = tdx_test_report_64bit_to_user_space(data);
	if (ret)
		tdx_test_fatal(ret);

	ret = tdg_vp_vmcall_instruction_rdmsr(MSR_IA32_MISC_ENABLE, &data);
	if (ret)
		tdx_test_fatal(ret);

	ret = tdx_test_report_64bit_to_user_space(data);
	if (ret)
		tdx_test_fatal(ret);

	/* We expect this call to fail since MSR_IA32_POWER_CTL is write only */
	ret = tdg_vp_vmcall_instruction_rdmsr(MSR_IA32_POWER_CTL, &data);
	if (ret) {
		ret = tdx_test_report_64bit_to_user_space(ret);
		if (ret)
			tdx_test_fatal(ret);
	} else {
		tdx_test_fatal(-99);
	}

	tdx_test_success();
}

void verify_guest_msr_reads(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	uint64_t data;
	int ret;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);

	/*
	 * Set explicit MSR filter map to control access to the MSR registers
	 * used in the test.
	 */
	printf("\t ... Setting test MSR filter\n");
	ret = kvm_check_cap(KVM_CAP_X86_USER_SPACE_MSR);
	TEST_ASSERT(ret, "KVM_CAP_X86_USER_SPACE_MSR is unavailable");
	vm_enable_cap(vm, KVM_CAP_X86_USER_SPACE_MSR, KVM_MSR_EXIT_REASON_FILTER);

	ret = kvm_check_cap(KVM_CAP_X86_MSR_FILTER);
	TEST_ASSERT(ret, "KVM_CAP_X86_MSR_FILTER is unavailable");

	ret = ioctl(vm->fd, KVM_X86_SET_MSR_FILTER, &tdx_msr_test_filter);
	TEST_ASSERT(ret == 0,
		    "KVM_X86_SET_MSR_FILTER failed, ret: %i errno: %i (%s)",
		    ret, errno, strerror(errno));

	vcpu = td_vcpu_add(vm, 0, guest_msr_read);
	td_finalize(vm);

	printf("Verifying guest msr reads:\n");

	printf("\t ... Setting test MSR values\n");
	/* Write arbitrary to the MSRs. */
	vcpu_set_msr(vcpu, MSR_X2APIC_APIC_ICR, 4);
	vcpu_set_msr(vcpu, MSR_IA32_MISC_ENABLE, 5);
	vcpu_set_msr(vcpu, MSR_IA32_POWER_CTL, 6);

	printf("\t ... Running guest\n");
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	data = tdx_test_read_64bit_report_from_guest(vcpu);
	TEST_ASSERT_EQ(data, 4);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	data = tdx_test_read_64bit_report_from_guest(vcpu);
	TEST_ASSERT_EQ(data, 5);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	data = tdx_test_read_64bit_report_from_guest(vcpu);
	TEST_ASSERT_EQ(data, TDG_VP_VMCALL_INVALID_OPERAND);

	td_vcpu_run(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies MSR write functionality.
 */
void guest_msr_write(void)
{
	uint64_t ret;

	ret = tdg_vp_vmcall_instruction_wrmsr(MSR_X2APIC_APIC_ICR, 4);
	if (ret)
		tdx_test_fatal(ret);

	/* We expect this call to fail since MSR_IA32_MISC_ENABLE is read only */
	ret = tdg_vp_vmcall_instruction_wrmsr(MSR_IA32_MISC_ENABLE, 5);
	if (ret) {
		ret = tdx_test_report_64bit_to_user_space(ret);
		if (ret)
			tdx_test_fatal(ret);
	} else {
		tdx_test_fatal(-99);
	}


	ret = tdg_vp_vmcall_instruction_wrmsr(MSR_IA32_POWER_CTL, 6);
	if (ret)
		tdx_test_fatal(ret);

	tdx_test_success();
}

void verify_guest_msr_writes(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	uint64_t data;
	int ret;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);

	/*
	 * Set explicit MSR filter map to control access to the MSR registers
	 * used in the test.
	 */
	printf("\t ... Setting test MSR filter\n");
	ret = kvm_check_cap(KVM_CAP_X86_USER_SPACE_MSR);
	TEST_ASSERT(ret, "KVM_CAP_X86_USER_SPACE_MSR is unavailable");
	vm_enable_cap(vm, KVM_CAP_X86_USER_SPACE_MSR, KVM_MSR_EXIT_REASON_FILTER);

	ret = kvm_check_cap(KVM_CAP_X86_MSR_FILTER);
	TEST_ASSERT(ret, "KVM_CAP_X86_MSR_FILTER is unavailable");

	ret = ioctl(vm->fd, KVM_X86_SET_MSR_FILTER, &tdx_msr_test_filter);
	TEST_ASSERT(ret == 0,
		    "KVM_X86_SET_MSR_FILTER failed, ret: %i errno: %i (%s)",
		    ret, errno, strerror(errno));

	vcpu = td_vcpu_add(vm, 0, guest_msr_write);
	td_finalize(vm);

	printf("Verifying guest msr writes:\n");

	printf("\t ... Running guest\n");
	/* Only the write to MSR_IA32_MISC_ENABLE should trigger an exit */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	data = tdx_test_read_64bit_report_from_guest(vcpu);
	TEST_ASSERT_EQ(data, TDG_VP_VMCALL_INVALID_OPERAND);

	td_vcpu_run(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	printf("\t ... Verifying MSR values writen by guest\n");

	TEST_ASSERT_EQ(vcpu_get_msr(vcpu, MSR_X2APIC_APIC_ICR), 4);
	TEST_ASSERT_EQ(vcpu_get_msr(vcpu, MSR_IA32_MISC_ENABLE), 0x1800);
	TEST_ASSERT_EQ(vcpu_get_msr(vcpu, MSR_IA32_POWER_CTL), 6);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies HLT functionality.
 */
void guest_hlt(void)
{
	uint64_t ret;
	uint64_t interrupt_blocked_flag;

	interrupt_blocked_flag = 0;
	ret = tdg_vp_vmcall_instruction_hlt(interrupt_blocked_flag);
	if (ret)
		tdx_test_fatal(ret);

	tdx_test_success();
}

void _verify_guest_hlt(int signum);

void wake_me(int interval)
{
	struct sigaction action;

	action.sa_handler = _verify_guest_hlt;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;

	TEST_ASSERT(sigaction(SIGALRM, &action, NULL) == 0,
		    "Could not set the alarm handler!");

	alarm(interval);
}

void _verify_guest_hlt(int signum)
{
	struct kvm_vm *vm;
	static struct kvm_vcpu *vcpu;

	/*
	 * This function will also be called by SIGALRM handler to check the
	 * vCPU MP State. If vm has been initialized, then we are in the signal
	 * handler. Check the MP state and let the guest run again.
	 */
	if (vcpu != NULL) {
		struct kvm_mp_state mp_state;

		vcpu_mp_state_get(vcpu, &mp_state);
		TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_HALTED);

		/* Let the guest to run and finish the test.*/
		mp_state.mp_state = KVM_MP_STATE_RUNNABLE;
		vcpu_mp_state_set(vcpu, &mp_state);
		return;
	}

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_hlt);
	td_finalize(vm);

	printf("Verifying HLT:\n");

	printf("\t ... Running guest\n");

	/* Wait 1 second for guest to execute HLT */
	wake_me(1);
	td_vcpu_run(vcpu);

	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

void verify_guest_hlt(void)
{
	_verify_guest_hlt(0);
}

/* Pick any address that was not mapped into the guest to test MMIO */
#define TDX_MMIO_TEST_ADDR 0x200000000

void guest_mmio_reads(void)
{
	uint64_t mmio_test_addr = TDX_MMIO_TEST_ADDR | tdx_s_bit;
	uint64_t data;
	uint64_t ret;

	ret = tdg_vp_vmcall_ve_request_mmio_read(mmio_test_addr, 1, &data);
	if (ret)
		tdx_test_fatal(ret);
	if (data != 0x12)
		tdx_test_fatal(1);

	ret = tdg_vp_vmcall_ve_request_mmio_read(mmio_test_addr, 2, &data);
	if (ret)
		tdx_test_fatal(ret);
	if (data != 0x1234)
		tdx_test_fatal(2);

	ret = tdg_vp_vmcall_ve_request_mmio_read(mmio_test_addr, 4, &data);
	if (ret)
		tdx_test_fatal(ret);
	if (data != 0x12345678)
		tdx_test_fatal(4);

	ret = tdg_vp_vmcall_ve_request_mmio_read(mmio_test_addr, 8, &data);
	if (ret)
		tdx_test_fatal(ret);
	if (data != 0x1234567890ABCDEF)
		tdx_test_fatal(8);

	// Read an invalid number of bytes.
	ret = tdg_vp_vmcall_ve_request_mmio_read(mmio_test_addr, 10, &data);
	if (ret)
		tdx_test_fatal(ret);

	tdx_test_success();
}

/*
 * Varifies guest MMIO reads.
 */
void verify_mmio_reads(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_mmio_reads);
	td_finalize(vm);

	printf("Verifying TD MMIO reads:\n");

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_MMIO(vcpu, TDX_MMIO_TEST_ADDR, 1, TDG_VP_VMCALL_VE_REQUEST_MMIO_READ);
	*(uint8_t *)vcpu->run->mmio.data = 0x12;

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_MMIO(vcpu, TDX_MMIO_TEST_ADDR, 2, TDG_VP_VMCALL_VE_REQUEST_MMIO_READ);
	*(uint16_t *)vcpu->run->mmio.data = 0x1234;

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_MMIO(vcpu, TDX_MMIO_TEST_ADDR, 4, TDG_VP_VMCALL_VE_REQUEST_MMIO_READ);
	*(uint32_t *)vcpu->run->mmio.data = 0x12345678;

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_MMIO(vcpu, TDX_MMIO_TEST_ADDR, 8, TDG_VP_VMCALL_VE_REQUEST_MMIO_READ);
	*(uint64_t *)vcpu->run->mmio.data = 0x1234567890ABCDEF;

	td_vcpu_run(vcpu);
	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[1], TDG_VP_VMCALL_INVALID_OPERAND);

	td_vcpu_run(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

void guest_mmio_writes(void)
{
	uint64_t mmio_test_addr = TDX_MMIO_TEST_ADDR | tdx_s_bit;
	uint64_t ret;

	ret = tdg_vp_vmcall_ve_request_mmio_write(mmio_test_addr, 1, 0x12);
	if (ret)
		tdx_test_fatal(ret);

	ret = tdg_vp_vmcall_ve_request_mmio_write(mmio_test_addr, 2, 0x1234);
	if (ret)
		tdx_test_fatal(ret);

	ret = tdg_vp_vmcall_ve_request_mmio_write(mmio_test_addr, 4, 0x12345678);
	if (ret)
		tdx_test_fatal(ret);

	ret = tdg_vp_vmcall_ve_request_mmio_write(mmio_test_addr, 8, 0x1234567890ABCDEF);
	if (ret)
		tdx_test_fatal(ret);

	// Write across page boundary.
	ret = tdg_vp_vmcall_ve_request_mmio_write(PAGE_SIZE - 1, 8, 0);
	if (ret)
		tdx_test_fatal(ret);

	tdx_test_success();
}

/*
 * Varifies guest MMIO writes.
 */
void verify_mmio_writes(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	uint8_t byte_1;
	uint16_t byte_2;
	uint32_t byte_4;
	uint64_t byte_8;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_mmio_writes);
	td_finalize(vm);

	printf("Verifying TD MMIO writes:\n");

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_MMIO(vcpu, TDX_MMIO_TEST_ADDR, 1, TDG_VP_VMCALL_VE_REQUEST_MMIO_WRITE);
	byte_1 = *(uint8_t *)(vcpu->run->mmio.data);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_MMIO(vcpu, TDX_MMIO_TEST_ADDR, 2, TDG_VP_VMCALL_VE_REQUEST_MMIO_WRITE);
	byte_2 = *(uint16_t *)(vcpu->run->mmio.data);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_MMIO(vcpu, TDX_MMIO_TEST_ADDR, 4, TDG_VP_VMCALL_VE_REQUEST_MMIO_WRITE);
	byte_4 = *(uint32_t *)(vcpu->run->mmio.data);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_MMIO(vcpu, TDX_MMIO_TEST_ADDR, 8, TDG_VP_VMCALL_VE_REQUEST_MMIO_WRITE);
	byte_8 = *(uint64_t *)(vcpu->run->mmio.data);

	TEST_ASSERT_EQ(byte_1, 0x12);
	TEST_ASSERT_EQ(byte_2, 0x1234);
	TEST_ASSERT_EQ(byte_4, 0x12345678);
	TEST_ASSERT_EQ(byte_8, 0x1234567890ABCDEF);

	td_vcpu_run(vcpu);
	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[1], TDG_VP_VMCALL_INVALID_OPERAND);

	td_vcpu_run(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Verifies CPUID TDVMCALL functionality.
 * The guest will then send the values to userspace using an IO write to be
 * checked against the expected values.
 */
void guest_code_cpuid_tdcall(void)
{
	uint64_t err;
	uint32_t eax, ebx, ecx, edx;

	// Read CPUID leaf 0x1 from host.
	err = tdg_vp_vmcall_instruction_cpuid(/*eax=*/1, /*ecx=*/0,
					&eax, &ebx, &ecx, &edx);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_to_user_space(eax);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_to_user_space(ebx);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_to_user_space(ecx);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_to_user_space(edx);
	if (err)
		tdx_test_fatal(err);

	tdx_test_success();
}

void verify_td_cpuid_tdcall(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	uint32_t eax, ebx, ecx, edx;
	const struct kvm_cpuid_entry2 *tmp;
	struct kvm_cpuid_entry2 cpuid_entry;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_code_cpuid_tdcall);
	td_finalize(vm);

	printf("Verifying TD CPUID TDVMCALL:\n");

	/* Wait for guest to report CPUID values */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_TEST_REPORT_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	eax = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_TEST_REPORT_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	ebx = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_TEST_REPORT_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	ecx = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_TEST_REPORT_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	edx = *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	/* Get KVM CPUIDs for reference */
	tmp = get_cpuid_entry(kvm_get_supported_cpuid(), 1, 0);
	TEST_ASSERT(tmp, "CPUID entry missing\n");

	cpuid_entry = *tmp;
	__tdx_mask_cpuid_features(&cpuid_entry);

	TEST_ASSERT_EQ(cpuid_entry.eax, eax);
	// Mask lapic ID when comparing ebx.
	TEST_ASSERT_EQ(cpuid_entry.ebx & ~0xFF000000, ebx & ~0xFF000000);
	TEST_ASSERT_EQ(cpuid_entry.ecx, ecx);
	TEST_ASSERT_EQ(cpuid_entry.edx, edx);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Shared variables between guest and host for host reading private mem test
 */
static uint64_t tdx_test_host_read_private_mem_addr;
#define TDX_HOST_READ_PRIVATE_MEM_PORT_TEST 0x53

void guest_host_read_priv_mem(void)
{
	uint64_t ret;
	uint64_t placeholder = 0;

	/* Set value */
	*((uint32_t *) tdx_test_host_read_private_mem_addr) = 0xABCD;

	/* Exit so host can read value */
	ret = tdg_vp_vmcall_instruction_io(
		TDX_HOST_READ_PRIVATE_MEM_PORT_TEST, 4,
		TDG_VP_VMCALL_INSTRUCTION_IO_WRITE, &placeholder);
	if (ret)
		tdx_test_fatal(ret);

	/* Update guest_var's value and have host reread it. */
	*((uint32_t *) tdx_test_host_read_private_mem_addr) = 0xFEDC;

	tdx_test_success();
}

void verify_host_reading_private_mem(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	vm_vaddr_t test_page;
	uint64_t *host_virt;
	uint64_t first_host_read;
	uint64_t second_host_read;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_host_read_priv_mem);

	test_page = vm_vaddr_alloc_page(vm);
	TEST_ASSERT(test_page < BIT_ULL(32),
		"Test address should fit in 32 bits so it can be sent to the guest");

	host_virt = addr_gva2hva(vm, test_page);
	TEST_ASSERT(host_virt != NULL,
		"Guest address not found in guest memory regions\n");

	tdx_test_host_read_private_mem_addr = test_page;
	sync_global_to_guest(vm, tdx_test_host_read_private_mem_addr);

	td_finalize(vm);

	printf("Verifying host's behavior when reading TD private memory:\n");

	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_HOST_READ_PRIVATE_MEM_PORT_TEST,
		4, TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	printf("\t ... Guest's variable contains 0xABCD\n");

	/* Host reads guest's variable. */
	first_host_read = *host_virt;
	printf("\t ... Host's read attempt value: %lu\n", first_host_read);

	/* Guest updates variable and host rereads it. */
	td_vcpu_run(vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
	printf("\t ... Guest's variable updated to 0xFEDC\n");

	second_host_read = *host_virt;
	printf("\t ... Host's second read attempt value: %lu\n",
		second_host_read);

	TEST_ASSERT(first_host_read == second_host_read,
		"Host did not read a fixed pattern\n");

	printf("\t ... Fixed pattern was returned to the host\n");

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

/*
 * Do a TDG.VP.INFO call from the guest
 */
void guest_tdcall_vp_info(void)
{
	uint64_t err;
	uint64_t rcx, rdx, r8, r9, r10, r11;

	err = tdg_vp_info(&rcx, &rdx, &r8, &r9, &r10, &r11);
	if (err)
		tdx_test_fatal(err);

	/* return values to user space host */
	err = tdx_test_report_64bit_to_user_space(rcx);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_64bit_to_user_space(rdx);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_64bit_to_user_space(r8);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_64bit_to_user_space(r9);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_64bit_to_user_space(r10);
	if (err)
		tdx_test_fatal(err);

	err = tdx_test_report_64bit_to_user_space(r11);
	if (err)
		tdx_test_fatal(err);

	tdx_test_success();
}

/*
 * TDG.VP.INFO call from the guest. Verify the right values are returned
 */
void verify_tdcall_vp_info(void)
{
	const int num_vcpus = 2;
	struct kvm_vcpu *vcpus[num_vcpus];
	struct kvm_vm *vm;

	uint64_t rcx, rdx, r8, r9, r10, r11;
	uint32_t ret_num_vcpus, ret_max_vcpus;
	uint64_t attributes;
	uint32_t i;
	const struct kvm_cpuid_entry2 *cpuid_entry;
	int max_pa = -1;

	vm = td_create();

#define TDX_TDPARAM_ATTR_SEPT_VE_DISABLE_BIT	(1UL << 28)
	/* Setting attributes parameter used by TDH.MNG.INIT to 0x50000000 */
	attributes = TDX_TDPARAM_ATTR_SEPT_VE_DISABLE_BIT;

	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, attributes);

	for (i = 0; i < num_vcpus; i++)
		vcpus[i] = td_vcpu_add(vm, i, guest_tdcall_vp_info);

	td_finalize(vm);

	printf("Verifying TDG.VP.INFO call:\n");

	/* Get KVM CPUIDs for reference */
	cpuid_entry = get_cpuid_entry(kvm_get_supported_cpuid(), 0x80000008, 0);
	TEST_ASSERT(cpuid_entry, "CPUID entry missing\n");
	max_pa = cpuid_entry->eax & 0xff;
	TEST_ASSERT_EQ((1UL << (max_pa - 1)), tdx_s_bit);

	for (i = 0; i < num_vcpus; i++) {
		struct kvm_vcpu *vcpu = vcpus[i];

		/* Wait for guest to report rcx value */
		td_vcpu_run(vcpu);
		TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
		rcx = tdx_test_read_64bit_report_from_guest(vcpu);

		/* Wait for guest to report rdx value */
		td_vcpu_run(vcpu);
		TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
		rdx = tdx_test_read_64bit_report_from_guest(vcpu);

		/* Wait for guest to report r8 value */
		td_vcpu_run(vcpu);
		TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
		r8 = tdx_test_read_64bit_report_from_guest(vcpu);

		/* Wait for guest to report r9 value */
		td_vcpu_run(vcpu);
		TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
		r9 = tdx_test_read_64bit_report_from_guest(vcpu);

		/* Wait for guest to report r10 value */
		td_vcpu_run(vcpu);
		TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
		r10 = tdx_test_read_64bit_report_from_guest(vcpu);

		/* Wait for guest to report r11 value */
		td_vcpu_run(vcpu);
		TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
		r11 = tdx_test_read_64bit_report_from_guest(vcpu);

		ret_num_vcpus = r8 & 0xFFFFFFFF;
		ret_max_vcpus = (r8 >> 32) & 0xFFFFFFFF;

		/* first bits 5:0 of rcx represent the GPAW */
		TEST_ASSERT_EQ(rcx & 0x3F, max_pa);
		/* next 63:6 bits of rcx is reserved and must be 0 */
		TEST_ASSERT_EQ(rcx >> 6, 0);
		TEST_ASSERT_EQ(rdx, attributes);
		TEST_ASSERT_EQ(ret_num_vcpus, num_vcpus);
		TEST_ASSERT_EQ(ret_max_vcpus, 512);
		/* VCPU_INDEX = i */
		TEST_ASSERT_EQ(r9, i);
		/*
		 * verify reserved bits are 0
		 * r10 bit 0 (SYS_RD) indicates that the TDG.SYS.RD/RDM/RDALL
		 * functions are available and can be either 0 or 1.
		 */
		TEST_ASSERT_EQ(r10 & ~1, 0);
		TEST_ASSERT_EQ(r11, 0);

		/* Wait for guest to complete execution */
		td_vcpu_run(vcpu);

		TDX_TEST_CHECK_GUEST_FAILURE(vcpu);
		TDX_TEST_ASSERT_SUCCESS(vcpu);

		printf("\t ... Guest completed run on VCPU=%u\n", i);
	}

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
	run_in_new_process(&verify_guest_writes);
	run_in_new_process(&verify_guest_reads);
	run_in_new_process(&verify_guest_msr_writes);
	run_in_new_process(&verify_guest_msr_reads);
	run_in_new_process(&verify_guest_hlt);
	run_in_new_process(&verify_mmio_reads);
	run_in_new_process(&verify_mmio_writes);
	run_in_new_process(&verify_td_cpuid_tdcall);
	run_in_new_process(&verify_host_reading_private_mem);
	run_in_new_process(&verify_tdcall_vp_info);

	return 0;
}
