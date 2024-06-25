/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_TDX_TEST_UTIL_H
#define SELFTEST_TDX_TEST_UTIL_H

#include <stdbool.h>

#include "tdcall.h"

#define TDX_TEST_SUCCESS_PORT 0x30
#define TDX_TEST_SUCCESS_SIZE 4

#define TDX_TEST_REPORT_PORT 0x31
#define TDX_TEST_REPORT_SIZE 4

/**
 * Assert that some IO operation involving tdg_vp_vmcall_instruction_io() was
 * called in the guest.
 */
#define TDX_TEST_ASSERT_IO(VCPU, PORT, SIZE, DIR)			\
	do {								\
		TEST_ASSERT((VCPU)->run->exit_reason == KVM_EXIT_IO,	\
			"Got exit_reason other than KVM_EXIT_IO: %u (%s)\n", \
			(VCPU)->run->exit_reason,			\
			exit_reason_str((VCPU)->run->exit_reason));	\
									\
		TEST_ASSERT(((VCPU)->run->exit_reason == KVM_EXIT_IO) && \
			((VCPU)->run->io.port == (PORT)) &&		\
			((VCPU)->run->io.size == (SIZE)) &&		\
			((VCPU)->run->io.direction == (DIR)),		\
			"Got unexpected IO exit values: %u (%s) %d %d %d\n", \
			(VCPU)->run->exit_reason,			\
			exit_reason_str((VCPU)->run->exit_reason),	\
			(VCPU)->run->io.port, (VCPU)->run->io.size,	\
			(VCPU)->run->io.direction);			\
	} while (0)

/**
 * Check and report if there was some failure in the guest, either an exception
 * like a triple fault, or if a tdx_test_fatal() was hit.
 */
#define TDX_TEST_CHECK_GUEST_FAILURE(VCPU)				\
	do {								\
		if ((VCPU)->run->exit_reason == KVM_EXIT_SYSTEM_EVENT)	\
			TEST_FAIL("Guest reported error. error code: %lld (0x%llx)\n", \
				(VCPU)->run->system_event.data[1],	\
				(VCPU)->run->system_event.data[1]);	\
	} while (0)

/**
 * Assert that tdx_test_success() was called in the guest.
 */
#define TDX_TEST_ASSERT_SUCCESS(VCPU)					\
	(TEST_ASSERT(							\
		((VCPU)->run->exit_reason == KVM_EXIT_IO) &&		\
		((VCPU)->run->io.port == TDX_TEST_SUCCESS_PORT) &&	\
		((VCPU)->run->io.size == TDX_TEST_SUCCESS_SIZE) &&	\
		((VCPU)->run->io.direction ==				\
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE),		\
		"Unexpected exit values while waiting for test completion: %u (%s) %d %d %d\n", \
		(VCPU)->run->exit_reason,				\
		exit_reason_str((VCPU)->run->exit_reason),		\
		(VCPU)->run->io.port, (VCPU)->run->io.size,		\
		(VCPU)->run->io.direction))

/**
 * Run a test in a new process.
 *
 * There might be multiple tests we are running and if one test fails, it will
 * prevent the subsequent tests to run due to how tests are failing with
 * TEST_ASSERT function. The run_in_new_process function will run a test in a
 * new process context and wait for it to finish or fail to prevent TEST_ASSERT
 * to kill the main testing process.
 */
void run_in_new_process(void (*func)(void));

/**
 * Verify that the TDX is supported by KVM.
 */
bool is_tdx_enabled(void);

/**
 * Report test success to userspace.
 *
 * Use TDX_TEST_ASSERT_SUCCESS() to assert that this function was called in the
 * guest.
 */
void tdx_test_success(void);

/**
 * Report an error with @error_code to userspace.
 *
 * Return value from tdg_vp_vmcall_report_fatal_error is ignored since execution
 * is not expected to continue beyond this point.
 */
void tdx_test_fatal(uint64_t error_code);

/**
 * Report an error with @error_code to userspace.
 *
 * @data_gpa may point to an optional shared guest memory holding the error
 * string.
 *
 * Return value from tdg_vp_vmcall_report_fatal_error is ignored since execution
 * is not expected to continue beyond this point.
 */
void tdx_test_fatal_with_data(uint64_t error_code, uint64_t data_gpa);

/**
 * Report a 32 bit value from the guest to user space using TDG.VP.VMCALL
 * <Instruction.IO> call. Data is reported on port TDX_TEST_REPORT_PORT.
 */
uint64_t tdx_test_report_to_user_space(uint32_t data);

#endif // SELFTEST_TDX_TEST_UTIL_H
