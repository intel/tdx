/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Confidential Computing Platform Capability checks
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#ifndef _LINUX_CC_PLATFORM_H
#define _LINUX_CC_PLATFORM_H

#include <linux/types.h>
#include <linux/stddef.h>

/**
 * enum cc_attr - Confidential computing attributes
 *
 * These attributes represent confidential computing features that are
 * currently active.
 */
enum cc_attr {
	/**
	 * @CC_ATTR_MEM_ENCRYPT: Memory encryption is active
	 *
	 * The platform/OS is running with active memory encryption. This
	 * includes running either as a bare-metal system or a hypervisor
	 * and actively using memory encryption or as a guest/virtual machine
	 * and actively using memory encryption.
	 *
	 * Examples include SME, SEV and SEV-ES.
	 */
	CC_ATTR_MEM_ENCRYPT,

	/**
	 * @CC_ATTR_HOST_MEM_ENCRYPT: Host memory encryption is active
	 *
	 * The platform/OS is running as a bare-metal system or a hypervisor
	 * and actively using memory encryption.
	 *
	 * Examples include SME.
	 */
	CC_ATTR_HOST_MEM_ENCRYPT,

	/**
	 * @CC_ATTR_GUEST_MEM_ENCRYPT: Guest memory encryption is active
	 *
	 * The platform/OS is running as a guest/virtual machine and actively
	 * using memory encryption.
	 *
	 * Examples include SEV and SEV-ES.
	 */
	CC_ATTR_GUEST_MEM_ENCRYPT,

	/**
	 * @CC_ATTR_GUEST_STATE_ENCRYPT: Guest state encryption is active
	 *
	 * The platform/OS is running as a guest/virtual machine and actively
	 * using memory encryption and register state encryption.
	 *
	 * Examples include SEV-ES.
	 */
	CC_ATTR_GUEST_STATE_ENCRYPT,

	/**
	 * @CC_ATTR_GUEST_UNROLL_STRING_IO: String I/O is implemented with
	 *                                  IN/OUT instructions
	 *
	 * The platform/OS is running as a guest/virtual machine and uses
	 * IN/OUT instructions in place of string I/O.
	 *
	 * Examples include TDX guest & SEV.
	 */
	CC_ATTR_GUEST_UNROLL_STRING_IO,

	/**
	 * @CC_ATTR_SEV_SNP: Guest SNP is active.
	 *
	 * The platform/OS is running as a guest/virtual machine and actively
	 * using AMD SEV-SNP features.
	 */
	CC_ATTR_GUEST_SEV_SNP,

	/**
	 * @CC_ATTR_HOTPLUG_DISABLED: Hotplug is not supported or disabled.
	 *
	 * The platform/OS is running as a guest/virtual machine does not
	 * support CPU hotplug feature.
	 *
	 * Examples include TDX Guest.
	 */
	CC_ATTR_HOTPLUG_DISABLED,

	/**
	 * @CC_ATTR_GUEST_DEVICE_FILTER: Filter device enumeration as per
	 * platform specific allow list.
	 *
	 * The platform/OS is running as a guest/virtual machine and allows or
	 * dis-allows device enumeration as per platform specific allow list.
	 *
	 * Examples include TDX guest.
	 */

	CC_ATTR_GUEST_DEVICE_FILTER,
	/**
	 * @CC_ATTR_GUEST_HARDENED: Filter out unnecessary and not-hardened
	 * device drivers.
	 *
	 * Examples include TDX guest.
	 */
	CC_ATTR_GUEST_HARDENED,

	/*
	 * @CC_ATTR_GUEST_SECURE_TIME: Use secured TSC and disable kvmclock.
	 *
	 * The platform/OS is running as a guest/virtual machine and use
	 * secured TSC and disable kvmclock.
	 *
	 * Examples include TDX guest.
	 */
	CC_ATTR_GUEST_SECURE_TIME,

	/**
	 * @CC_ATTR_GUEST_CPUID_FILTER: Enable CPUID based XEN/KVM filter
	 *
	 * The platform/OS is running as a guest/virtual machine and uses
	 * CPUID to disable XEN and other KVM features.
	 *
	 * Examples include TDX guest.
	 */
	CC_ATTR_GUEST_CPUID_FILTER,

	/**
	 * @CC_ATTR_GUEST_RAND_LOOP: Make RDRAND/RDSEED loop forever to
	 * harden the random number generation.
	 *
	 * The platform/OS is running as a guest/virtual machine and
	 * harden the random number generation.
	 *
	 * Examples include TDX guest.
	 */
	CC_ATTR_GUEST_RAND_LOOP,
};

#ifdef CONFIG_ARCH_HAS_CC_PLATFORM

/**
 * cc_platform_has() - Checks if the specified cc_attr attribute is active
 * @attr: Confidential computing attribute to check
 *
 * The cc_platform_has() function will return an indicator as to whether the
 * specified Confidential Computing attribute is currently active.
 *
 * Context: Any context
 * Return:
 * * TRUE  - Specified Confidential Computing attribute is active
 * * FALSE - Specified Confidential Computing attribute is not active
 */
bool cc_platform_has(enum cc_attr attr);

#else	/* !CONFIG_ARCH_HAS_CC_PLATFORM */

static inline bool cc_platform_has(enum cc_attr attr) { return false; }

#endif	/* CONFIG_ARCH_HAS_CC_PLATFORM */

#endif	/* _LINUX_CC_PLATFORM_H */
