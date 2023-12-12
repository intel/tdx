/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_TDX_TEST_UTIL_H
#define SELFTEST_TDX_TEST_UTIL_H

#include <stdbool.h>

#include "tdcall.h"

#define TDX_TEST_SUCCESS_PORT 0x30
#define TDX_TEST_SUCCESS_SIZE 4

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

#endif // SELFTEST_TDX_TEST_UTIL_H
