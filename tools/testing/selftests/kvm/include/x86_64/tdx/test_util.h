/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_TDX_TEST_UTIL_H
#define SELFTEST_TDX_TEST_UTIL_H

#include <stdbool.h>

#include "tdcall.h"

#define TDX_TEST_SUCCESS_PORT 0x30
#define TDX_TEST_SUCCESS_SIZE 4

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

#endif // SELFTEST_TDX_TEST_UTIL_H
