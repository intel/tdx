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
#include <linux/device.h>

#ifndef __ASSEMBLY__

static inline bool prot_guest_has(unsigned int attr)
{
	if (sme_me_mask)
		return amd_prot_guest_has(attr);
	else if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		return tdx_prot_guest_has(attr);

	return false;
}

static inline bool prot_guest_authorized(struct device *dev, char *dev_str)
{
	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return tdx_guest_authorized(dev, dev_str);

	return dev->authorized;
}

#endif	/* __ASSEMBLY__ */

#endif	/* _X86_PROTECTED_GUEST_H */
