// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_X86_VMX_COMMON_H
#define __KVM_X86_VMX_COMMON_H

#include <linux/kvm_host.h>

#include <asm/traps.h>

#include "vmcs.h"
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

#endif /* __KVM_X86_VMX_COMMON_H */
