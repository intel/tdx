/* SPDX-License-Identifier: GPL-2.0 */
/* helper functions to invoke SEAM ACM. */

#ifndef _X86_TDX_SEAM_H
#define _X86_TDX_SEAM_H

#include <linux/earlycpio.h>

#include <asm/tlbflush.h>

struct vmcs_hdr {
	u32 revision_id:31;
	u32 shadow_vmcs:1;
};

struct vmcs {
	struct vmcs_hdr hdr;
	u32 abort;
	char data[];
};

struct vmx_basic_info {
	int size;
	u32 rev_id;
	u32 cap;
};

bool __init seam_get_firmware(struct cpio_data *blob, const char *name);

int __init seam_init_vmx_early(void);
void __init seam_init_vmxon_vmcs(struct vmcs *vmcs);

int seam_vmxon_on_each_cpu(void);
int seam_vmxoff_on_each_cpu(void);

/*
 * cpu_vmxon() - Enable VMX on the current CPU
 *
 * Set CR4.VMXE and enable VMX
 */
static inline int cpu_vmxon(u64 vmxon_pointer)
{
	u64 msr;

	cr4_set_bits(X86_CR4_VMXE);

	asm_volatile_goto("1: vmxon %[vmxon_pointer]\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  : : [vmxon_pointer] "m"(vmxon_pointer)
			  : : fault);
	return 0;

fault:
	WARN_ONCE(1, "VMXON faulted, MSR_IA32_FEAT_CTL (0x3a) = 0x%llx\n",
		  rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ? 0xdeadbeef : msr);
	cr4_clear_bits(X86_CR4_VMXE);

	return -EFAULT;
}

/**
 * cpu_vmxoff() - Disable VMX on the current CPU
 *
 * Disable VMX and clear CR4.VMXE (even if VMXOFF faults)
 *
 * Note, VMXOFF causes a #UD if the CPU is !post-VMXON, but it's impossible to
 * atomically track post-VMXON state, e.g. this may be called in NMI context.
 * Eat all faults as all other faults on VMXOFF faults are mode related, i.e.
 * faults are guaranteed to be due to the !post-VMXON check unless the CPU is
 * magically in RM, VM86, compat mode, or at CPL>0.
 */
static inline int cpu_vmxoff(void)
{
	asm_volatile_goto("1: vmxoff\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  ::: "cc", "memory" : fault);

	cr4_clear_bits(X86_CR4_VMXE);
	return 0;

fault:
	cr4_clear_bits(X86_CR4_VMXE);
	return -EIO;
}

#endif /* _X86_TDX_SEAM_H */
