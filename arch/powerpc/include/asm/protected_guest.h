/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Protected Guest (and Host) Capability checks
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#ifndef _POWERPC_PROTECTED_GUEST_H
#define _POWERPC_PROTECTED_GUEST_H

#include <asm/svm.h>

#ifndef __ASSEMBLY__

static inline bool prot_guest_has(unsigned int attr)
{
	switch (attr) {
	case PATTR_MEM_ENCRYPT:
		return is_secure_guest();

	default:
		return false;
	}
}

#endif	/* __ASSEMBLY__ */

#endif	/* _POWERPC_PROTECTED_GUEST_H */
