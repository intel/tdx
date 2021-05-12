/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_PROTECTED_GUEST_H
#define _ASM_X86_PROTECTED_GUEST_H 1

#include <asm/processor.h>
#include <asm/tdx.h>
#include <asm/sev.h>

static inline bool prot_guest_has(unsigned long flag)
{
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		return tdx_prot_guest_has(flag);
	else if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD)
		return sev_prot_guest_has(flag);

	return false;
}

#endif /* _ASM_X86_PROTECTED_GUEST_H */
