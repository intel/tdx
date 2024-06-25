/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_TDX_TEST_UTIL_H
#define SELFTEST_TDX_TEST_UTIL_H

#include <stdbool.h>

#include "tdcall.h"

#define TDX_TEST_SUCCESS_PORT 0x30
#define TDX_TEST_SUCCESS_SIZE 4

#define TDX_TEST_REPORT_PORT 0x31
#define TDX_TEST_REPORT_SIZE 4

/*
 * Assert that some IO operation involving tdg_vp_vmcall_instruction_io() was
 * called in the guest.
 */
void tdx_test_assert_io(struct kvm_vcpu *vcpu, uint16_t port, uint8_t size,
			uint8_t direction);

/*
 * Check and report if there was some failure in the guest, either an exception
 * like a triple fault, or if a tdx_test_fatal() was hit.
 */
void tdx_test_check_guest_failure(struct kvm_vcpu *vcpu);

/*
 * Run a test in a new process.
 *
 * There might be multiple tests we are running and if one test fails, it will
 * prevent the subsequent tests to run due to how tests are failing with
 * TEST_ASSERT function. The run_in_new_process function will run a test in a
 * new process context and wait for it to finish or fail to prevent TEST_ASSERT
 * to kill the main testing process.
 */
int run_in_new_process(void (*func)(void));

/*
 * Verify that the TDX is supported by KVM.
 */
bool is_tdx_enabled(void);

/*
 * Report test success to userspace.
 *
 * Use tdx_test_assert_success() to assert that this function was called in the
 * guest.
 */
void tdx_test_success(void);
void tdx_test_assert_success(struct kvm_vcpu *vcpu);

/*
 * Report an error with @error_code to userspace.
 *
 * Return value from tdg_vp_vmcall_report_fatal_error is ignored since execution
 * is not expected to continue beyond this point.
 */
void tdx_test_fatal(uint64_t error_code);

/*
 * Report an error with @error_code to userspace.
 *
 * @data_gpa may point to an optional shared guest memory holding the error
 * string.
 *
 * Return value from tdg_vp_vmcall_report_fatal_error is ignored since execution
 * is not expected to continue beyond this point.
 */
void tdx_test_fatal_with_data(uint64_t error_code, uint64_t data_gpa);

/*
 * Report a 32 bit value from the guest to user space using TDG.VP.VMCALL
 * <Instruction.IO> call. Data is reported on port TDX_TEST_REPORT_PORT.
 */
uint64_t tdx_test_report_to_user_space(uint32_t data);

#endif // SELFTEST_TDX_TEST_UTIL_H
