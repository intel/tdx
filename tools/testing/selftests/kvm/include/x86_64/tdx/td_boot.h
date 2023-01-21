/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_TDX_TD_BOOT_H
#define SELFTEST_TDX_TD_BOOT_H

#include <stdint.h>
#include "tdx/td_boot_asm.h"

/*
 * Layout for boot section (not to scale)
 *
 *                                  GPA
 * ┌─────────────────────────────┬──0x1_0000_0000 (4GB)
 * │   Boot code trampoline      │
 * ├─────────────────────────────┼──0x0_ffff_fff0: Reset vector (16B below 4GB)
 * │   Boot code                 │
 * ├─────────────────────────────┼──td_boot will be copied here, so that the
 * │                             │  jmp to td_boot is exactly at the reset vector
 * │   Empty space               │
 * │                             │
 * ├─────────────────────────────┤
 * │                             │
 * │                             │
 * │   Boot parameters           │
 * │                             │
 * │                             │
 * └─────────────────────────────┴──0x0_ffff_0000: TD_BOOT_PARAMETERS_GPA
 */
#define FOUR_GIGABYTES_GPA (4ULL << 30)

/**
 * The exact memory layout for LGDT or LIDT instructions.
 */
struct __packed td_boot_parameters_dtr {
	uint16_t limit;
	uint32_t base;
};

/**
 * The exact layout in memory required for a ljmp, including the selector for
 * changing code segment.
 */
struct __packed td_boot_parameters_ljmp_target {
	uint32_t eip_gva;
	uint16_t code64_sel;
};

/**
 * Allows each vCPU to be initialized with different eip and esp.
 */
struct __packed td_per_vcpu_parameters {
	uint32_t esp_gva;
	struct td_boot_parameters_ljmp_target ljmp_target;
};

/**
 * Boot parameters for the TD.
 *
 * Unlike a regular VM, we can't ask KVM to set registers such as esp, eip, etc
 * before boot, so to run selftests, these registers' values have to be
 * initialized by the TD.
 *
 * This struct is loaded in TD private memory at TD_BOOT_PARAMETERS_GPA.
 *
 * The TD boot code will read off parameters from this struct and set up the
 * vcpu for executing selftests.
 */
struct __packed td_boot_parameters {
	uint32_t cr0;
	uint32_t cr3;
	uint32_t cr4;
	struct td_boot_parameters_dtr gdtr;
	struct td_boot_parameters_dtr idtr;
	struct td_per_vcpu_parameters per_vcpu[];
};

extern void td_boot(void);
extern void reset_vector(void);
extern void td_boot_code_end(void);

#define TD_BOOT_CODE_SIZE (td_boot_code_end - td_boot)

#endif /* SELFTEST_TDX_TD_BOOT_H */
