/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_VMX_POSTED_INTR_H
#define __KVM_X86_VMX_POSTED_INTR_H

#include <linux/find.h>
#include <asm/posted_intr.h>

struct vcpu_pi {
	struct kvm_vcpu	vcpu;

	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	/* Used if this vCPU is waiting for PI notification wakeup. */
	struct list_head pi_wakeup_list;
	/* Until here common layout between vcpu_vmx and vcpu_tdx. */
};

void vmx_vcpu_pi_load(struct kvm_vcpu *vcpu, int cpu);
void vmx_vcpu_pi_put(struct kvm_vcpu *vcpu);
void pi_wakeup_handler(void);
void __init pi_init_cpu(int cpu);
bool pi_has_pending_interrupt(struct kvm_vcpu *vcpu);
int vmx_pi_update_irte(struct kvm *kvm, unsigned int host_irq,
		       uint32_t guest_irq, bool set);
void vmx_pi_start_assignment(struct kvm *kvm);

static inline int pi_find_highest_vector(struct pi_desc *pi_desc)
{
	int vec;

	vec = find_last_bit((unsigned long *)pi_desc->pir, 256);
	return vec < 256 ? vec : -1;
}

#endif /* __KVM_X86_VMX_POSTED_INTR_H */
