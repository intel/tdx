// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2020 Intel Corporation */

#include <asm/tdx.h>
#include <linux/cpu.h>
#include <asm/tdx.h>
#include <asm/vmx.h>

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

bool is_tdx_guest(void)
{
	return static_cpu_has(X86_FEATURE_TDX_GUEST);
}
EXPORT_SYMBOL_GPL(is_tdx_guest);

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
	bool tdx_forced;

	tdx_forced = cmdline_find_option_bool(boot_command_line, "tdx_guest");

	if (tdx_forced)
		pr_info("Force enabling TDX feature\n");

	if (!cpuid_has_tdx_guest() && !tdx_forced)
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	tdx_get_info();

	pr_info("TDX guest is initialized\n");
}
