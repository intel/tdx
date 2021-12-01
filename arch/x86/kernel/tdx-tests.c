/*
 * Test for x86 debugging facilities
 *
 * Loosely based on the kvm-unit-tests/x86/debug.c by
 *
 * Copyright (c) Siemens AG, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/printk.h>
#include <linux/kdebug.h>
#include <linux/types.h>
#include <asm/debugreg.h>

static volatile unsigned long db_addr[10], dr6[10];
static volatile unsigned int n;

static void report(bool cond, const char *fmt, ...)
{
	struct va_format vaf;
	va_list ap;

	va_start(ap, fmt);
	vaf.fmt = fmt;
	vaf.va = &ap;
	pr_info("KVM-debug: %s: %pV\n", cond ? "PASS" : "FAIL", &vaf);
	va_end(ap);
}

static int kvm_unit_test_debug_notify(struct notifier_block *nb, unsigned long val, void *data)
{
	struct die_args *args = data;
	struct pt_regs *regs = args->regs;

	if (val != DIE_DEBUG)
		return NOTIFY_DONE;

	db_addr[n] = regs->ip;

	/* Original test likes to see DR6_RESERVED set, so oblige */
	dr6[n] = *(unsigned long *)args->err | DR6_RESERVED;

	if (dr6[n] & 0x1)
		regs->flags |= X86_EFLAGS_RF;

	if (++n >= 10) {
		regs->flags &= ~X86_EFLAGS_TF;
		set_debugreg(0x00000400, 7);
	}

	return NOTIFY_STOP;
}

static struct notifier_block kvm_unit_test_debug_notifier = {
	.notifier_call	= kvm_unit_test_debug_notify,
	.priority	= -INT_MAX,
};

int __init kvm_unit_test_debug_init(void)
{
	unsigned long start;

	register_die_notifier(&kvm_unit_test_debug_notifier);

	/*
	 * cpuid and rdmsr (among others) trigger VM exits and are then
	 * emulated. Test that single stepping works on emulated instructions.
	 * 
	 * With TDX, there are 2 possibilities: instruction is either emulated
	 * by the TDX module or the #VE handler. In the former case, it's the
	 * job of the TDX module to raise #DB.
	 */
	n = 0;

	set_debugreg(0, 6);
	/* First, test #VE emulated instructions: CPUID 0x5 and RDMSR 0x8b */
	asm volatile(
		"pushf\n\t"
		"pop %%rax\n\t"
		"and $~(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"lea (%%rip),%0\n\t"
		"popf\n\t"
		"movl $0x5,%%eax\n\t"
		"cpuid\n\t"
		"movl $0x8b,%%ecx\n\t"
		"rdmsr\n\t"
		"popf\n\t"
		: "=r" (start) : : "rax", "ebx", "ecx", "edx");
	report(n == 5 &&
	       db_addr[0] == start + 6 && dr6[0] == 0xffff4ff0 &&
	       db_addr[1] == start + 6 + 2 && dr6[1] == 0xffff4ff0 &&
	       db_addr[2] == start + 6 + 2 + 5 && dr6[2] == 0xffff4ff0 &&
	       db_addr[3] == start + 6 + 2 + 5 + 2 && dr6[3] == 0xffff4ff0 &&
	       db_addr[4] == start + 6 + 2 + 5 + 2 + 1 && dr6[4] == 0xffff4ff0,
	       "single step #VE emulated instructions");

	n = 0;
	set_debugreg(0, 6);
	/* Second, test #VE emulated CPUID 0x0 (as in the original unit test) */
	asm volatile(
		"pushf\n\t"
		"pop %%rax\n\t"
		"and $~(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"lea (%%rip),%0\n\t"
		"popf\n\t"
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		"popf\n\t"
		: "=r" (start) : : "rax", "ebx", "ecx", "edx");
	report(n == 3 &&
	       db_addr[0] == start + 4 && dr6[0] == 0xffff4ff0 &&
	       db_addr[1] == start + 4 + 2 && dr6[1] == 0xffff4ff0 &&
	       db_addr[2] == start + 4 + 2 + 1 && dr6[2] == 0xffff4ff0,
	       "single step TDX module emulated CPUID 0");

	n = 0;
	set_debugreg(0, 6);
	/* Third, test #VE emulated RDMSR 0x1a0 (as in the original unit test) */
	asm volatile(
		"pushf\n\t"
		"pop %%rax\n\t"
		"and $~(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"lea (%%rip),%0\n\t"
		"popf\n\t"
		"movl $0x1a0,%%ecx\n\t"
		"rdmsr\n\t"
		"popf\n\t"
		: "=r" (start) : : "rax", "ebx", "ecx", "edx");
	report(n == 3 &&
	       db_addr[0] == start + 6 && dr6[0] == 0xffff4ff0 &&
	       db_addr[1] == start + 6 + 2 && dr6[1] == 0xffff4ff0 &&
	       db_addr[2] == start + 6 + 2 + 1 && dr6[2] == 0xffff4ff0,
	       "single step TDX module emulated RDMSR 0x1a0");

	unregister_die_notifier(&kvm_unit_test_debug_notifier);

	return 0;
}
core_initcall(kvm_unit_test_debug_init);
