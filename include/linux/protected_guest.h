/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Protected Guest (and Host) Capability checks
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#ifndef _PROTECTED_GUEST_H
#define _PROTECTED_GUEST_H

#ifndef __ASSEMBLY__

#define PATTR_MEM_ENCRYPT		0	/* Encrypted memory */
#define PATTR_HOST_MEM_ENCRYPT		1	/* Host encrypted memory */
#define PATTR_GUEST_MEM_ENCRYPT		2	/* Guest encrypted memory */
#define PATTR_GUEST_PROT_STATE		3	/* Guest encrypted state */

/* 0x800 - 0x8ff reserved for AMD */
#define PATTR_SME			0x800
#define PATTR_SEV			0x801
#define PATTR_SEV_ES			0x802

/* 0x900 - 0x9ff reserved for Intel */
#define PATTR_GUEST_TDX			0x900

#ifdef CONFIG_ARCH_HAS_PROTECTED_GUEST

#include <asm/protected_guest.h>

#else	/* !CONFIG_ARCH_HAS_PROTECTED_GUEST */

static inline bool prot_guest_has(unsigned int attr) { return false; }

#endif	/* CONFIG_ARCH_HAS_PROTECTED_GUEST */

#endif	/* __ASSEMBLY__ */

#endif	/* _PROTECTED_GUEST_H */
