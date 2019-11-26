/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#include <linux/cpu.h>
#include <asm/tdx.h>
#include <asm/vmx.h>

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

static void tdx_get_info(void)
{
	register long rcx asm("rcx");
	register long rdx asm("rdx");
	register long r8 asm("r8");
	long ret;

	asm volatile(TDCALL
		     : "=a"(ret), "=c"(rcx), "=r"(rdx), "=r"(r8)
		     : "a"(TDINFO)
		     : "r9", "r10", "r11", "memory");
	BUG_ON(ret);

	td_info.gpa_width = rcx & GENMASK(5, 0);
	td_info.attributes = rdx;
}

void __init tdx_early_init(void)
{
	if (!__is_tdx_guest())
		return;

	tdx_get_info();
}
