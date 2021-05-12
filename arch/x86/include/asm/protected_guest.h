/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Protected Guest (and Host) Capability checks
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#ifndef _X86_PROTECTED_GUEST_H
#define _X86_PROTECTED_GUEST_H

#include <linux/mem_encrypt.h>

#include <asm/processor.h>
#include <asm/tdx.h>

#ifndef __ASSEMBLY__

static inline bool prot_guest_has(unsigned int attr)
{
	if (sme_me_mask)
		return amd_prot_guest_has(attr);
	else if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		return tdx_prot_guest_has(attr);

	return false;
}

#endif	/* __ASSEMBLY__ */

#endif	/* _X86_PROTECTED_GUEST_H */
