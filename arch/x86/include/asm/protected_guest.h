/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_PROTECTED_GUEST_H
#define _ASM_X86_PROTECTED_GUEST_H 1

static inline bool prot_guest_has(unsigned long flag)
{
	return false;
}

#endif /* _ASM_X86_PROTECTED_GUEST_H */
