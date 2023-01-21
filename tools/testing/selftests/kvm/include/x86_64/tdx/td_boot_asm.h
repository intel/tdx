/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_TDX_TD_BOOT_ASM_H
#define SELFTEST_TDX_TD_BOOT_ASM_H

/*
 * GPA where TD boot parameters wil lbe loaded.
 *
 * TD_BOOT_PARAMETERS_GPA is arbitrarily chosen to
 *
 * + be within the 4GB address space
 * + provide enough contiguous memory for the struct td_boot_parameters such
 *   that there is one struct td_per_vcpu_parameters for KVM_MAX_VCPUS
 */
#define TD_BOOT_PARAMETERS_GPA 0xffff0000

#endif  // SELFTEST_TDX_TD_BOOT_ASM_H
