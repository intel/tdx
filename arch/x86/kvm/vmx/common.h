// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_X86_VMX_COMMON_H
#define __KVM_X86_VMX_COMMON_H

#include <linux/kvm_host.h>

#include <asm/traps.h>
#include <asm/vmx.h>

#include "mmu.h"
#include "vmcs.h"
#include "vmx.h"
#include "x86.h"

void vmx_handle_interrupt_nmi_irqoff(struct kvm_vcpu *vcpu, u32 intr_info);

static inline void vmx_handle_external_interrupt_irqoff(struct kvm_vcpu *vcpu,
							u32 intr_info)
{
	if (KVM_BUG(!is_external_intr(intr_info), vcpu->kvm,
	    "KVM: unexpected VM-Exit interrupt info: 0x%x", intr_info))
		return;

	vmx_handle_interrupt_nmi_irqoff(vcpu, intr_info);
}

static inline void vmx_handle_exception_nmi_irqoff(struct kvm_vcpu *vcpu,
						  u32 intr_info)
{
	/* Handle machine checks before interrupts are enabled */
	if (is_machine_check(intr_info))
		kvm_machine_check();
	/* We need to handle NMIs before interrupts are enabled */
	else if (is_nmi(intr_info))
		vmx_handle_interrupt_nmi_irqoff(vcpu, intr_info);
}

static inline int __vmx_handle_ept_violation(struct kvm_vcpu *vcpu, gpa_t gpa,
					     unsigned long exit_qualification)
{
	u64 error_code;

	/* Is it a read fault? */
	error_code = (exit_qualification & EPT_VIOLATION_ACC_READ)
		     ? PFERR_USER_MASK : 0;
	/* Is it a write fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_WRITE)
		      ? PFERR_WRITE_MASK : 0;
	/* Is it a fetch fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_INSTR)
		      ? PFERR_FETCH_MASK : 0;
	/* ept page table entry is present? */
	error_code |= (exit_qualification &
		       (EPT_VIOLATION_READABLE | EPT_VIOLATION_WRITABLE |
			EPT_VIOLATION_EXECUTABLE))
		      ? PFERR_PRESENT_MASK : 0;

	error_code |= (exit_qualification & 0x100) != 0 ?
	       PFERR_GUEST_FINAL_MASK : PFERR_GUEST_PAGE_MASK;

	return kvm_mmu_page_fault(vcpu, gpa, error_code, NULL, 0);
}

#endif /* __KVM_X86_VMX_COMMON_H */
