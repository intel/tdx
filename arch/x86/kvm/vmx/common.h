/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_X86_VMX_COMMON_H
#define __KVM_X86_VMX_COMMON_H

#include <linux/kvm_host.h>

#include <asm/kvm.h>
#include <asm/traps.h>
#include <asm/vmx.h>

#include "mmu.h"
#include "vmcs.h"
#include "vmx.h"
#include "x86.h"
#include "tdx.h"

#ifdef CONFIG_INTEL_TDX_HOST
#define VT_BUILD_VMCS_HELPERS(type, bits, tdbits)			   \
static __always_inline type vmread##bits(struct kvm_vcpu *vcpu,		   \
					 unsigned long field)		   \
{									   \
	if (unlikely(is_td_vcpu(vcpu))) {				   \
		if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))		   \
			return 0;					   \
		return td_vmcs_read##tdbits(to_tdx(vcpu), field);	   \
	}								   \
	return vmcs_read##bits(field);					   \
}									   \
static __always_inline void vmwrite##bits(struct kvm_vcpu *vcpu,	   \
					  unsigned long field, type value) \
{									   \
	if (unlikely(is_td_vcpu(vcpu))) {				   \
		if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))		   \
			return;						   \
		return td_vmcs_write##tdbits(to_tdx(vcpu), field, value);  \
	}								   \
	vmcs_write##bits(field, value);					   \
}

static __always_inline u64 vmread_gprs(struct kvm_vcpu *vcpu,
				       u64 field)
{
	if (!is_td_vcpu(vcpu))
		return vcpu->arch.regs[field];

	if (KVM_BUG_ON(!is_debug_td(vcpu), vcpu->kvm))
		return 0UL;

	return td_gpr_read64(to_tdx(vcpu), field);
}

static inline unsigned long vm_get_exit_qual(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdexit_exit_qual(vcpu);
	return vmx_get_exit_qual(vcpu);
}

static inline void vm_exec_controls_clearbit(struct kvm_vcpu *vcpu,
					     u32 bit)
{
	if (is_td_vcpu(vcpu))
		td_vmcs_clearbit32(to_tdx(vcpu),
				   CPU_BASED_VM_EXEC_CONTROL,
				   bit);
	else
		exec_controls_clearbit(to_vmx(vcpu), bit);
}
#else
#define VT_BUILD_VMCS_HELPERS(type, bits, tdbits)			   \
static __always_inline type vmread##bits(struct kvm_vcpu *vcpu,		   \
					 unsigned long field)		   \
{									   \
	return vmcs_read##bits(field);					   \
}									   \
static __always_inline void vmwrite##bits(struct kvm_vcpu *vcpu,	   \
					  unsigned long field, type value) \
{									   \
	vmcs_write##bits(field, value);					   \
}

static __always_inline u64 vmread_gprs(struct kvm_vcpu *vcpu,
				       u64 field)
{
	return vcpu->arch.regs[field];
}

static inline unsigned long vm_get_exit_qual(struct kvm_vcpu *vcpu)
{
	return vmx_get_exit_qual(vcpu);
}

static inline void vm_exec_controls_clearbit(struct kvm_vcpu *vcpu,
					     u32 bit)
{
	exec_controls_clearbit(to_vmx(vcpu), bit);
}
#endif /* CONFIG_INTEL_TDX_HOST */
VT_BUILD_VMCS_HELPERS(u16, 16, 16);
VT_BUILD_VMCS_HELPERS(u32, 32, 32);
VT_BUILD_VMCS_HELPERS(u64, 64, 64);
VT_BUILD_VMCS_HELPERS(unsigned long, l, 64);

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

static inline int __vmx_handle_ept_violation(struct kvm_vcpu *vcpu, gpa_t gpa,
					     unsigned long exit_qualification,
					     int err_page_level)
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

	error_code |= (exit_qualification & EPT_VIOLATION_GVA_TRANSLATED) != 0 ?
	       PFERR_GUEST_FINAL_MASK : PFERR_GUEST_PAGE_MASK;

	if (err_page_level > 0)
		error_code |= (err_page_level << PFERR_LEVEL_START_BIT) & PFERR_LEVEL_MASK;

	return kvm_mmu_page_fault(vcpu, gpa, error_code, NULL, 0);
}

static inline u32 __vmx_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	u32 interruptibility;
	int ret = 0;

	interruptibility = vmread32(vcpu, GUEST_INTERRUPTIBILITY_INFO);
	if (interruptibility & GUEST_INTR_STATE_STI)
		ret |= KVM_X86_SHADOW_INT_STI;
	if (interruptibility & GUEST_INTR_STATE_MOV_SS)
		ret |= KVM_X86_SHADOW_INT_MOV_SS;

	return ret;
}

static inline u32 vmx_encode_ar_bytes(struct kvm_segment *var)
{
	u32 ar;

	if (var->unusable || !var->present)
		ar = 1 << 16;
	else {
		ar = var->type & 15;
		ar |= (var->s & 1) << 4;
		ar |= (var->dpl & 3) << 5;
		ar |= (var->present & 1) << 7;
		ar |= (var->avl & 1) << 12;
		ar |= (var->l & 1) << 13;
		ar |= (var->db & 1) << 14;
		ar |= (var->g & 1) << 15;
	}

	return ar;
}

static inline void vmx_decode_ar_bytes(u32 ar, struct kvm_segment *var)
{
	var->unusable = (ar >> 16) & 1;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	/*
	 * Some userspaces do not preserve unusable property. Since usable
	 * segment has to be present according to VMX spec we can use present
	 * property to amend userspace bug by making unusable segment always
	 * nonpresent. vmx_encode_ar_bytes() already marks nonpresent
	 * segment as unusable.
	 */
	var->present = !var->unusable;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
}

static inline unsigned long vmx_mask_out_guest_rip(struct kvm_vcpu *vcpu,
						   unsigned long orig_rip,
						   unsigned long new_rip)
{
	/*
	 * We need to mask out the high 32 bits of RIP if not in 64-bit
	 * mode, but just finding out that we are in 64-bit mode is
	 * quite expensive.  Only do it if there was a carry.
	 */
	if (unlikely(((new_rip ^ orig_rip) >> 31) == 3) &&
	    !is_64_bit_mode(vcpu))
		return (u32)new_rip;
	return new_rip;
}

/* For share the handler between legacy guest and TD guest */
int vmx_handle_dr(struct kvm_vcpu *vcpu);

#endif /* __KVM_X86_VMX_COMMON_H */
