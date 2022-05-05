/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_X86_VMX_COMMON_H
#define __KVM_X86_VMX_COMMON_H

#include <linux/kvm_host.h>

#include <asm/traps.h>
#include <asm/fred.h>

#include "posted_intr.h"
#include "mmu.h"
#include "vmcs.h"
#include "x86.h"

extern unsigned long vmx_host_idt_base;
void vmx_do_interrupt_irqoff(unsigned long entry);
void vmx_do_nmi_irqoff(void);

static inline void vmx_handle_nm_fault_irqoff(struct kvm_vcpu *vcpu)
{
	/*
	 * Save xfd_err to guest_fpu before interrupt is enabled, so the
	 * MSR value is not clobbered by the host activity before the guest
	 * has chance to consume it.
	 *
	 * Do not blindly read xfd_err here, since this exception might
	 * be caused by L1 interception on a platform which doesn't
	 * support xfd at all.
	 *
	 * Do it conditionally upon guest_fpu::xfd. xfd_err matters
	 * only when xfd contains a non-zero value.
	 *
	 * Queuing exception is done in vmx_handle_exit. See comment there.
	 */
	if (vcpu->arch.guest_fpu.fpstate->xfd)
		rdmsrl(MSR_IA32_XFD_ERR, vcpu->arch.guest_fpu.xfd_err);
}

static inline void vmx_handle_exception_irqoff(struct kvm_vcpu *vcpu,
					       u32 intr_info)
{
	/* if exit due to PF check for async PF */
	if (is_page_fault(intr_info))
		vcpu->arch.apf.host_apf_flags = kvm_read_and_reset_apf_flags();
	/* if exit due to NM, handle before interrupts are enabled */
	else if (is_nm_fault(intr_info))
		vmx_handle_nm_fault_irqoff(vcpu);
	/* Handle machine checks before interrupts are enabled */
	else if (is_machine_check(intr_info))
		kvm_machine_check();
}

static inline void vmx_handle_external_interrupt_irqoff(struct kvm_vcpu *vcpu,
							u32 intr_info)
{
	unsigned int vector = intr_info & INTR_INFO_VECTOR_MASK;

	if (KVM_BUG(!is_external_intr(intr_info), vcpu->kvm,
	    "unexpected VM-Exit interrupt info: 0x%x", intr_info))
		return;

	kvm_before_interrupt(vcpu, KVM_HANDLING_IRQ);
	if (cpu_feature_enabled(X86_FEATURE_FRED))
		fred_entry_from_kvm(EVENT_TYPE_EXTINT, vector);
	else
		vmx_do_interrupt_irqoff(gate_offset((gate_desc *)vmx_host_idt_base + vector));
	kvm_after_interrupt(vcpu);

	vcpu->arch.at_instruction_boundary = true;
}

static inline bool kvm_is_private_gpa(struct kvm *kvm, gpa_t gpa)
{
	/* For TDX the direct mask is the shared mask. */
	return !kvm_is_addr_direct(kvm, gpa);
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
	error_code |= (exit_qualification & EPT_VIOLATION_RWX_MASK)
		      ? PFERR_PRESENT_MASK : 0;

	error_code |= (exit_qualification & EPT_VIOLATION_GVA_TRANSLATED) != 0 ?
	       PFERR_GUEST_FINAL_MASK : PFERR_GUEST_PAGE_MASK;

	/*
	 * Don't rely on GFN's attribute tracking xarray to prevent EPT violation
	 * loops.
	 */
	if (kvm_is_private_gpa(vcpu->kvm, gpa))
		error_code |= PFERR_PRIVATE_ACCESS;

	return kvm_mmu_page_fault(vcpu, gpa, error_code, NULL, 0);
}

static inline void kvm_vcpu_trigger_posted_interrupt(struct kvm_vcpu *vcpu,
						     int pi_vec)
{
#ifdef CONFIG_SMP
	if (vcpu->mode == IN_GUEST_MODE) {
		/*
		 * The vector of the virtual has already been set in the PIR.
		 * Send a notification event to deliver the virtual interrupt
		 * unless the vCPU is the currently running vCPU, i.e. the
		 * event is being sent from a fastpath VM-Exit handler, in
		 * which case the PIR will be synced to the vIRR before
		 * re-entering the guest.
		 *
		 * When the target is not the running vCPU, the following
		 * possibilities emerge:
		 *
		 * Case 1: vCPU stays in non-root mode. Sending a notification
		 * event posts the interrupt to the vCPU.
		 *
		 * Case 2: vCPU exits to root mode and is still runnable. The
		 * PIR will be synced to the vIRR before re-entering the guest.
		 * Sending a notification event is ok as the host IRQ handler
		 * will ignore the spurious event.
		 *
		 * Case 3: vCPU exits to root mode and is blocked. vcpu_block()
		 * has already synced PIR to vIRR and never blocks the vCPU if
		 * the vIRR is not empty. Therefore, a blocked vCPU here does
		 * not wait for any requested interrupts in PIR, and sending a
		 * notification event also results in a benign, spurious event.
		 */

		if (vcpu != kvm_get_running_vcpu())
			__apic_send_IPI_mask(get_cpu_mask(vcpu->cpu), pi_vec);
		return;
	}
#endif
	/*
	 * The vCPU isn't in the guest; wake the vCPU in case it is blocking,
	 * otherwise do nothing as KVM will grab the highest priority pending
	 * IRQ via ->sync_pir_to_irr() in vcpu_enter_guest().
	 */
	kvm_vcpu_wake_up(vcpu);
}

/*
 * Send interrupt to vcpu via posted interrupt way.
 * 1. If target vcpu is running(non-root mode), send posted interrupt
 * notification to vcpu and hardware will sync PIR to vIRR atomically.
 * 2. If target vcpu isn't running(root mode), kick it to pick up the
 * interrupt from PIR in next vmentry.
 */
static inline void __vmx_deliver_posted_interrupt(struct kvm_vcpu *vcpu,
						  struct pi_desc *pi_desc, int vector)
{
	if (pi_test_and_set_pir(vector, pi_desc))
		return;

	/* If a previous notification has sent the IPI, nothing to do.  */
	if (pi_test_and_set_on(pi_desc))
		return;

	/*
	 * The implied barrier in pi_test_and_set_on() pairs with the smp_mb_*()
	 * after setting vcpu->mode in vcpu_enter_guest(), thus the vCPU is
	 * guaranteed to see PID.ON=1 and sync the PIR to IRR if triggering a
	 * posted interrupt "fails" because vcpu->mode != IN_GUEST_MODE.
	 */
	kvm_vcpu_trigger_posted_interrupt(vcpu, POSTED_INTR_VECTOR);
}

#endif /* __KVM_X86_VMX_COMMON_H */
