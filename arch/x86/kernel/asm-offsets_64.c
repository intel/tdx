// SPDX-License-Identifier: GPL-2.0
#ifndef __LINUX_KBUILD_H
# error "Please do not build this file directly, build asm-offsets.c instead"
#endif

#include <asm/ia32.h>

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_PARAVIRT_SPINLOCKS)
#include <asm/kvm_para.h>
#endif

#ifdef CONFIG_INTEL_TDX_HOST
#include <asm/seam.h>
#endif

int main(void)
{
#ifdef CONFIG_PARAVIRT
#ifdef CONFIG_PARAVIRT_XXL
#ifdef CONFIG_DEBUG_ENTRY
	OFFSET(PV_IRQ_save_fl, paravirt_patch_template, irq.save_fl);
#endif
#endif
	BLANK();
#endif

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_PARAVIRT_SPINLOCKS)
	OFFSET(KVM_STEAL_TIME_preempted, kvm_steal_time, preempted);
	BLANK();
#endif

#ifdef CONFIG_INTEL_TDX_HOST
	OFFSET(SEAMCALL_in_rcx, seamcall_regs_in, rcx);
	OFFSET(SEAMCALL_in_rdx, seamcall_regs_in, rdx);
	OFFSET(SEAMCALL_in_r8,  seamcall_regs_in, r8);
	OFFSET(SEAMCALL_in_r9,  seamcall_regs_in, r9);
	OFFSET(SEAMCALL_out_rcx, seamcall_regs_out, rcx);
	OFFSET(SEAMCALL_out_rdx, seamcall_regs_out, rdx);
	OFFSET(SEAMCALL_out_r8,  seamcall_regs_out, r8);
	OFFSET(SEAMCALL_out_r9,  seamcall_regs_out, r9);
	OFFSET(SEAMCALL_out_r10, seamcall_regs_out, r10);
	OFFSET(SEAMCALL_out_r11, seamcall_regs_out, r11);
	BLANK();
#endif

#define ENTRY(entry) OFFSET(pt_regs_ ## entry, pt_regs, entry)
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(sp);
	ENTRY(bp);
	ENTRY(si);
	ENTRY(di);
	ENTRY(r8);
	ENTRY(r9);
	ENTRY(r10);
	ENTRY(r11);
	ENTRY(r12);
	ENTRY(r13);
	ENTRY(r14);
	ENTRY(r15);
	ENTRY(flags);
	BLANK();
#undef ENTRY

#define ENTRY(entry) OFFSET(saved_context_ ## entry, saved_context, entry)
	ENTRY(cr0);
	ENTRY(cr2);
	ENTRY(cr3);
	ENTRY(cr4);
	ENTRY(gdt_desc);
	BLANK();
#undef ENTRY

	BLANK();

#ifdef CONFIG_STACKPROTECTOR
	DEFINE(stack_canary_offset, offsetof(struct fixed_percpu_data, stack_canary));
	BLANK();
#endif
	return 0;
}
