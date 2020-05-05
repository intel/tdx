/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_X86_VMX_COMMON_H
#define __KVM_X86_VMX_COMMON_H

#include <linux/kvm_host.h>

#include <asm/traps.h>

#include "vmcs.h"
#include "x86.h"

extern unsigned long vmx_host_idt_base;
void vmx_do_interrupt_nmi_irqoff(unsigned long entry);

static inline void vmx_handle_interrupt_nmi_irqoff(struct kvm_vcpu *vcpu,
				     unsigned long entry)
{
	kvm_before_interrupt(vcpu);
	vmx_do_interrupt_nmi_irqoff(entry);
	kvm_after_interrupt(vcpu);
}

static inline void vmx_handle_exception_nmi_irqoff(struct kvm_vcpu *vcpu,
						   u32 intr_info)
{
	const unsigned long nmi_entry = (unsigned long)asm_exc_nmi_noist;

	/* if exit due to PF check for async PF */
	if (is_page_fault(intr_info))
		vcpu->arch.apf.host_apf_flags = kvm_read_and_reset_apf_flags();
	/* Handle machine checks before interrupts are enabled */
	else if (is_machine_check(intr_info))
		kvm_machine_check();
	/* We need to handle NMIs before interrupts are enabled */
	else if (is_nmi(intr_info))
		vmx_handle_interrupt_nmi_irqoff(vcpu, nmi_entry);
}

static inline void vmx_handle_external_interrupt_irqoff(struct kvm_vcpu *vcpu,
							u32 intr_info)
{
	unsigned int vector = intr_info & INTR_INFO_VECTOR_MASK;
	gate_desc *desc = (gate_desc *)vmx_host_idt_base + vector;

	if (KVM_BUG(!is_external_intr(intr_info), vcpu->kvm,
	    "KVM: unexpected VM-Exit interrupt info: 0x%x", intr_info))
		return;

	vmx_handle_interrupt_nmi_irqoff(vcpu, gate_offset(desc));
}

#endif /* __KVM_X86_VMX_COMMON_H */
