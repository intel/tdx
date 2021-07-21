/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_PROTECTED_GUEST_H
#define _LINUX_PROTECTED_GUEST_H 1

/* Protected Guest Feature Flags (leave 0-0xfff for vendor specific flags) */

/* 0-ff is reserved for Intel specific flags */
#define PR_GUEST_TDX				0x0000

/* 100-1ff is reserved for AMD specific flags */
#define PR_GUEST_SEV				0x0100

/* Support for guest encryption */
#define PR_GUEST_MEM_ENCRYPT			0x1000
/* Encryption support is active */
#define PR_GUEST_MEM_ENCRYPT_ACTIVE		0x1001
/* Support for unrolled string IO */
#define PR_GUEST_UNROLL_STRING_IO		0x1002
/* Support for host memory encryption */
#define PR_GUEST_HOST_MEM_ENCRYPT		0x1003
/* Support for shared mapping initialization (after early init) */
#define PR_GUEST_SHARED_MAPPING_INIT		0x1004
/* Support for driver filter */
#define PR_GUEST_DRIVER_FILTER			0x1005
/* Do not use paravirtual time */
#define PR_GUEST_SECURE_TIME			0x1006
/* Support for filtering some CPUIDs */
#define PR_GUEST_CPUID_FILTER			0x1007
/* Limit PCI probing to simple virtual cases */
#define PR_GUEST_LIMIT_PCI			0x1008


#ifdef CONFIG_ARCH_HAS_PROTECTED_GUEST
#include <asm/protected_guest.h>
#else
static inline bool prot_guest_has(unsigned long flag) { return false; }
#endif

/* Suppress error messages generated due to driver filter */
#define pg_filter_suppress_err(fmt, ...)		\
do {							\
	if (!prot_guest_has(PR_GUEST_DRIVER_FILTER))	\
		pr_err(fmt, ##__VA_ARGS__);		\
} while (0)

#endif /* _LINUX_PROTECTED_GUEST_H */
