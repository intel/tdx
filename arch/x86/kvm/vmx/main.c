// SPDX-License-Identifier: GPL-2.0
#include <linux/moduleparam.h>

#include "x86_ops.h"
#include "vmx.h"
#include "nested.h"
#include "mmu.h"
#include "pmu.h"
#include "tdx.h"

static bool vt_is_vm_type_supported(unsigned long type)
{
	return type == KVM_X86_DEFAULT_VM || tdx_is_vm_type_supported(type);
}

static int vt_hardware_enable(void)
{
	int ret;

	ret = vmx_hardware_enable();
	if (ret)
		return ret;

	tdx_hardware_enable();
	return 0;
}

static void vt_hardware_disable(void)
{
	/* Note, TDX *and* VMX need to be disabled if TDX is enabled. */
	tdx_hardware_disable();
	vmx_hardware_disable();
}

static __init int vt_hardware_setup(void)
{
	int ret;

	ret = vmx_hardware_setup();
	if (ret)
		return ret;

	tdx_hardware_setup(&vt_x86_ops);

	if (enable_ept) {
		const u64 init_value = enable_tdx ? VMX_EPT_SUPPRESS_VE_BIT : 0ull;
		kvm_mmu_set_ept_masks(enable_ept_ad_bits,
				      cpu_has_vmx_ept_execute_only(), init_value);
		kvm_mmu_set_spte_init_value(init_value);
	}

	return 0;
}

static void vt_hardware_unsetup(void)
{
	tdx_hardware_unsetup();
	vmx_hardware_unsetup();
}

static int vt_vm_init(struct kvm *kvm)
{
	int ret;

	if (is_td(kvm)) {
		ret = tdx_module_setup();
		if (ret)
			return ret;
		return tdx_vm_init(kvm);
	}

	return vmx_vm_init(kvm);
}

static void vt_mmu_prezap(struct kvm *kvm)
{
	if (is_td(kvm))
		return tdx_mmu_prezap(kvm);
}

static void vt_vm_free(struct kvm *kvm)
{
	if (is_td(kvm))
		return tdx_vm_free(kvm);
}

static int vt_vcpu_create(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_create(vcpu);

	return vmx_vcpu_create(vcpu);
}

static void vt_vcpu_free(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_free(vcpu);

	return vmx_vcpu_free(vcpu);
}

static void vt_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_reset(vcpu, init_event);

	return vmx_vcpu_reset(vcpu, init_event);
}

static void vt_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	/*
	 * All host state is saved/restored across SEAMCALL/SEAMRET, and the
	 * guest state of a TD is obviously off limits.  Deferring MSRs and DRs
	 * is pointless because the TDX module needs to load *something* so as
	 * not to expose guest state.
	 */
	if (is_td_vcpu(vcpu)) {
		tdx_prepare_switch_to_guest(vcpu);
		return;
	}

	vmx_prepare_switch_to_guest(vcpu);
}

static void vt_vcpu_put(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_put(vcpu);

	return vmx_vcpu_put(vcpu);
}

static fastpath_t vt_vcpu_run(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_run(vcpu);

	return vmx_vcpu_run(vcpu);
}

static void vt_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_load(vcpu, cpu);

	return vmx_vcpu_load(vcpu, cpu);
}

static int vt_handle_exit(struct kvm_vcpu *vcpu,
			     enum exit_fastpath_completion fastpath)
{
	if (is_td_vcpu(vcpu))
		return tdx_handle_exit(vcpu, fastpath);

	return vmx_handle_exit(vcpu, fastpath);
}

static void vt_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_handle_exit_irqoff(vcpu);

	vmx_handle_exit_irqoff(vcpu);
}

static int vt_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	if (unlikely(is_td_vcpu(vcpu)))
		return tdx_set_msr(vcpu, msr_info);

	return vmx_set_msr(vcpu, msr_info);
}

/*
 * The kvm parameter can be NULL (module initialization, or invocation before
 * VM creation). Be sure to check the kvm parameter before using it.
 */
static bool vt_has_emulated_msr(struct kvm *kvm, u32 index)
{
	if (kvm && is_td(kvm))
		return tdx_is_emulated_msr(index, true);

	return vmx_has_emulated_msr(kvm, index);
}

static int vt_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	if (unlikely(is_td_vcpu(vcpu)))
		return tdx_get_msr(vcpu, msr_info);

	return vmx_get_msr(vcpu, msr_info);
}

static int vt_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	if (is_td_vcpu(vcpu))
		return tdx_smi_allowed(vcpu, for_injection);

	return vmx_smi_allowed(vcpu, for_injection);
}

static int vt_enter_smm(struct kvm_vcpu *vcpu, char *smstate)
{
	if (unlikely(is_td_vcpu(vcpu)))
		return tdx_enter_smm(vcpu, smstate);

	return vmx_enter_smm(vcpu, smstate);
}

static int vt_leave_smm(struct kvm_vcpu *vcpu, const char *smstate)
{
	if (unlikely(is_td_vcpu(vcpu)))
		return tdx_leave_smm(vcpu, smstate);

	return vmx_leave_smm(vcpu, smstate);
}

static void vt_enable_smi_window(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_enable_smi_window(vcpu);
		return;
	}

	/* RSM will cause a vmexit anyway.  */
	vmx_enable_smi_window(vcpu);
}

static bool vt_can_emulate_instruction(struct kvm_vcpu *vcpu, int emul_type,
				       void *insn, int insn_len)
{
	if (is_td_vcpu(vcpu))
		return false;

	return vmx_can_emulate_instruction(vcpu, emul_type, insn, insn_len);
}

static int vt_check_intercept(struct kvm_vcpu *vcpu,
				 struct x86_instruction_info *info,
				 enum x86_intercept_stage stage,
				 struct x86_exception *exception)
{
	/*
	 * This call back is triggered by the x86 instruction emulator. TDX
	 * doesn't allow guest memory inspection.
	 */
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return X86EMUL_UNHANDLEABLE;

	return vmx_check_intercept(vcpu, info, stage, exception);
}

static bool vt_apic_init_signal_blocked(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return true;

	return vmx_apic_init_signal_blocked(vcpu);
}

static void vt_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_set_virtual_apic_mode(vcpu);

	return vmx_set_virtual_apic_mode(vcpu);
}

static void vt_apicv_post_state_restore(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_apicv_post_state_restore(vcpu);

	return vmx_apicv_post_state_restore(vcpu);
}

static void vt_hwapic_irr_update(struct kvm_vcpu *vcpu, int max_irr)
{
	if (is_td_vcpu(vcpu))
		return;

	return vmx_hwapic_irr_update(vcpu, max_irr);
}

static void vt_hwapic_isr_update(struct kvm_vcpu *vcpu, int max_isr)
{
	if (is_td_vcpu(vcpu))
		return;

	return vmx_hwapic_isr_update(vcpu, max_isr);
}

static bool vt_guest_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	/* TDX doesn't support L2 at the moment. */
	if (WARN_ON_ONCE(is_td_vcpu(vcpu)))
		return false;

	return vmx_guest_apic_has_interrupt(vcpu);
}

static int vt_sync_pir_to_irr(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return -1;

	return vmx_sync_pir_to_irr(vcpu);
}

static void vt_deliver_interrupt(struct kvm_lapic *apic, int delivery_mode,
			   int trig_mode, int vector)
{
	if (is_td_vcpu(apic->vcpu)) {
		tdx_deliver_interrupt(apic, delivery_mode, trig_mode,
					     vector);
		return;
	}

	vmx_deliver_interrupt(apic, delivery_mode, trig_mode, vector);
}

static bool vt_apicv_has_pending_interrupt(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return pi_has_pending_interrupt(vcpu);

	return false;
}

static void vt_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector)
{
	if (is_td_vcpu(vcpu))
		return;

	kvm_vcpu_deliver_sipi_vector(vcpu, vector);
}

static void vt_vcpu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	return vmx_vcpu_after_set_cpuid(vcpu);
}

static void vt_update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_update_exception_bitmap(vcpu);
}

static u64 vt_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_segment_base(vcpu, seg);

	return vmx_get_segment_base(vcpu, seg);
}

static void vt_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var,
			      int seg)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_segment(vcpu, var, seg);

	vmx_get_segment(vcpu, var, seg);
}

static void vt_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var,
			      int seg)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_segment(vcpu, var, seg);
}

static int vt_get_cpl(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_cpl(vcpu);

	return vmx_get_cpl(vcpu);
}

static void vt_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_get_cs_db_l_bits(vcpu, db, l);
}

static void vt_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_cr0(vcpu, cr0);
}

static void vt_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_cr4(vcpu, cr4);
}

static int vt_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	if (is_td_vcpu(vcpu))
		return 0;

	return vmx_set_efer(vcpu, efer);
}

static void vt_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (is_td_vcpu(vcpu)) {
		memset(dt, 0, sizeof(*dt));
		return;
	}

	vmx_get_idt(vcpu, dt);
}

static void vt_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_idt(vcpu, dt);
}

static void vt_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (is_td_vcpu(vcpu)) {
		memset(dt, 0, sizeof(*dt));
		return;
	}

	vmx_get_gdt(vcpu, dt);
}

static void vt_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_gdt(vcpu, dt);
}

static void vt_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_dr7(vcpu, val);
}

static void vt_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
	/*
	 * MOV-DR exiting is always cleared for TD guest, even in debug mode.
	 * Thus KVM_DEBUGREG_WONT_EXIT can never be set and it should never
	 * reach here for TD vcpu.
	 */
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return;

	vmx_sync_dirty_debug_regs(vcpu);
}

static void vt_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	if (is_td_vcpu(vcpu)) {
		tdx_cache_reg(vcpu, reg);
		return;
	}

	vmx_cache_reg(vcpu, reg);
}

static unsigned long vt_get_rflags(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_rflags(vcpu);

	return vmx_get_rflags(vcpu);
}

static void vt_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_rflags(vcpu, rflags);
}

static bool vt_get_if_flag(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return false;

	return vmx_get_if_flag(vcpu);
}

static void vt_flush_tlb_all(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_flush_tlb(vcpu);

	vmx_flush_tlb_all(vcpu);
}

static void vt_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_flush_tlb(vcpu);

	vmx_flush_tlb_current(vcpu);
}

static void vt_flush_tlb_gva(struct kvm_vcpu *vcpu, gva_t addr)
{
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return;

	vmx_flush_tlb_gva(vcpu, addr);
}

static void vt_flush_tlb_guest(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_flush_tlb_guest(vcpu);
}

static void vt_inject_nmi(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_inject_nmi(vcpu);

	vmx_inject_nmi(vcpu);
}

static int vt_nmi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	/*
	 * The TDX module manages NMI windows and NMI reinjection, and hides NMI
	 * blocking, all KVM can do is throw an NMI over the wall.
	 */
	if (is_td_vcpu(vcpu))
		return true;

	return vmx_nmi_allowed(vcpu, for_injection);
}

static bool vt_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	/*
	 * Assume NMIs are always unmasked.  KVM could query PEND_NMI and treat
	 * NMIs as masked if a previous NMI is still pending, but SEAMCALLs are
	 * expensive and the end result is unchanged as the only relevant usage
	 * of get_nmi_mask() is to limit the number of pending NMIs, i.e. it
	 * only changes whether KVM or the TDX module drops an NMI.
	 */
	if (is_td_vcpu(vcpu))
		return false;

	return vmx_get_nmi_mask(vcpu);
}

static void vt_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_nmi_mask(vcpu, masked);
}

static void vt_enable_nmi_window(struct kvm_vcpu *vcpu)
{
	/* Refer the comment in vt_get_nmi_mask(). */
	if (is_td_vcpu(vcpu))
		return;

	vmx_enable_nmi_window(vcpu);
}

static void vt_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa,
			int pgd_level)
{
	if (is_td_vcpu(vcpu))
		return tdx_load_mmu_pgd(vcpu, root_hpa, pgd_level);

	vmx_load_mmu_pgd(vcpu, root_hpa, pgd_level);
}

static void vt_sched_in(struct kvm_vcpu *vcpu, int cpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_sched_in(vcpu, cpu);
}

static void vt_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	if (is_td_vcpu(vcpu))
		return;
	vmx_set_interrupt_shadow(vcpu, mask);
}

static u32 vt_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return 0;

	return vmx_get_interrupt_shadow(vcpu);
}

static void vt_patch_hypercall(struct kvm_vcpu *vcpu,
				  unsigned char *hypercall)
{
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return;

	vmx_patch_hypercall(vcpu, hypercall);
}

static void vt_inject_irq(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_inject_irq(vcpu);
}

static void vt_queue_exception(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_queue_exception(vcpu);
}

static void vt_cancel_injection(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_cancel_injection(vcpu);
}

static int vt_interrupt_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	if (is_td_vcpu(vcpu))
		return true;

	return vmx_interrupt_allowed(vcpu, for_injection);
}

static void vt_enable_irq_window(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_enable_irq_window(vcpu);
}

static void vt_request_immediate_exit(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return __kvm_request_immediate_exit(vcpu);

	vmx_request_immediate_exit(vcpu);
}

static void vt_update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_update_cr8_intercept(vcpu, tpr, irr);
}

static void vt_set_apic_access_page_addr(struct kvm_vcpu *vcpu)
{
	if (WARN_ON_ONCE(is_td_vcpu(vcpu)))
		return;

	vmx_set_apic_access_page_addr(vcpu);
}

static void vt_refresh_apicv_exec_ctrl(struct kvm_vcpu *vcpu)
{
	if (WARN_ON_ONCE(is_td_vcpu(vcpu)))
		return;

	vmx_refresh_apicv_exec_ctrl(vcpu);
}

static void vt_load_eoi_exitmap(struct kvm_vcpu *vcpu, u64 *eoi_exit_bitmap)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_load_eoi_exitmap(vcpu, eoi_exit_bitmap);
}

static int vt_set_tss_addr(struct kvm *kvm, unsigned int addr)
{
	if (is_td(kvm))
		return 0;

	return vmx_set_tss_addr(kvm, addr);
}

static int vt_set_identity_map_addr(struct kvm *kvm, u64 ident_addr)
{
	if (is_td(kvm))
		return 0;

	return vmx_set_identity_map_addr(kvm, ident_addr);
}

static u64 vt_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	if (is_td_vcpu(vcpu)) {
		if (is_mmio)
			return MTRR_TYPE_UNCACHABLE << VMX_EPT_MT_EPTE_SHIFT;
		return  MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT;
	}

	return vmx_get_mt_mask(vcpu, gfn, is_mmio);
}

static u64 vt_get_l2_tsc_offset(struct kvm_vcpu *vcpu)
{
	/* TDX doesn't support L2 guest at the moment. */
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return 0;

	return vmx_get_l2_tsc_offset(vcpu);
}

static u64 vt_get_l2_tsc_multiplier(struct kvm_vcpu *vcpu)
{
	/* TDX doesn't support L2 guest at the moment. */
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return 0;

	return vmx_get_l2_tsc_multiplier(vcpu);
}

static void vt_write_tsc_offset(struct kvm_vcpu *vcpu, u64 offset)
{
	/* In TDX, tsc offset can't be changed. */
	if (is_td_vcpu(vcpu))
		return;

	vmx_write_tsc_offset(vcpu, offset);
}

static void vt_write_tsc_multiplier(struct kvm_vcpu *vcpu, u64 multiplier)
{
	/* In TDX, tsc multiplier can't be changed. */
	if (is_td_vcpu(vcpu))
		return;

	vmx_write_tsc_multiplier(vcpu, multiplier);
}

static void vt_update_cpu_dirty_logging(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_update_cpu_dirty_logging(vcpu);
}

#ifdef CONFIG_X86_64
static int vt_set_hv_timer(struct kvm_vcpu *vcpu, u64 guest_deadline_tsc,
			      bool *expired)
{
	/* VMX-preemption timer isn't available for TDX. */
	if (is_td_vcpu(vcpu))
		return -EINVAL;

	return vmx_set_hv_timer(vcpu, guest_deadline_tsc, expired);
}

static void vt_cancel_hv_timer(struct kvm_vcpu *vcpu)
{
	/* VMX-preemption timer can't be set.  Set vt_set_hv_timer(). */
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return;

	vmx_cancel_hv_timer(vcpu);
}
#endif

static void vt_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason,
			u64 *info1, u64 *info2, u32 *intr_info, u32 *error_code)
{
	if (is_td_vcpu(vcpu)) {
		tdx_get_exit_info(vcpu, reason, info1, info2, intr_info,
				error_code);
		return;
	}

	vmx_get_exit_info(vcpu, reason, info1, info2, intr_info, error_code);
}

static int vt_mem_enc_op(struct kvm *kvm, void __user *argp)
{
	if (!is_td(kvm))
		return -ENOTTY;

	return tdx_vm_ioctl(kvm, argp);
}

static int vt_mem_enc_op_vcpu(struct kvm_vcpu *vcpu, void __user *argp)
{
	if (!is_td_vcpu(vcpu))
		return -EINVAL;

	return tdx_vcpu_ioctl(vcpu, argp);
}

struct kvm_x86_ops vt_x86_ops __initdata = {
	.name = "kvm_intel",

	.hardware_unsetup = vt_hardware_unsetup,

	.hardware_enable = vt_hardware_enable,
	.hardware_disable = vt_hardware_disable,
	.cpu_has_accelerated_tpr = report_flexpriority,
	.has_emulated_msr = vt_has_emulated_msr,

	.is_vm_type_supported = vt_is_vm_type_supported,
	.vm_size = sizeof(struct kvm_vmx),
	.vm_init = vt_vm_init,
	.mmu_prezap = vt_mmu_prezap,
	.vm_free = vt_vm_free,

	.vcpu_create = vt_vcpu_create,
	.vcpu_free = vt_vcpu_free,
	.vcpu_reset = vt_vcpu_reset,

	.prepare_guest_switch = vt_prepare_switch_to_guest,
	.vcpu_load = vt_vcpu_load,
	.vcpu_put = vt_vcpu_put,

	.update_exception_bitmap = vt_update_exception_bitmap,
	.get_msr_feature = vmx_get_msr_feature,
	.get_msr = vt_get_msr,
	.set_msr = vt_set_msr,
	.get_segment_base = vt_get_segment_base,
	.get_segment = vt_get_segment,
	.set_segment = vt_set_segment,
	.get_cpl = vt_get_cpl,
	.get_cs_db_l_bits = vt_get_cs_db_l_bits,
	.set_cr0 = vt_set_cr0,
	.is_valid_cr4 = vmx_is_valid_cr4,
	.set_cr4 = vt_set_cr4,
	.set_efer = vt_set_efer,
	.get_idt = vt_get_idt,
	.set_idt = vt_set_idt,
	.get_gdt = vt_get_gdt,
	.set_gdt = vt_set_gdt,
	.set_dr7 = vt_set_dr7,
	.sync_dirty_debug_regs = vt_sync_dirty_debug_regs,
	.cache_reg = vt_cache_reg,
	.get_rflags = vt_get_rflags,
	.set_rflags = vt_set_rflags,
	.get_if_flag = vt_get_if_flag,

	.tlb_flush_all = vt_flush_tlb_all,
	.tlb_flush_current = vt_flush_tlb_current,
	.tlb_flush_gva = vt_flush_tlb_gva,
	.tlb_flush_guest = vt_flush_tlb_guest,

	.vcpu_pre_run = vmx_vcpu_pre_run,
	.run = vt_vcpu_run,
	.handle_exit = vt_handle_exit,
	.skip_emulated_instruction = vmx_skip_emulated_instruction,
	.update_emulated_instruction = vmx_update_emulated_instruction,
	.set_interrupt_shadow = vt_set_interrupt_shadow,
	.get_interrupt_shadow = vt_get_interrupt_shadow,
	.patch_hypercall = vt_patch_hypercall,
	.set_irq = vt_inject_irq,
	.set_nmi = vt_inject_nmi,
	.queue_exception = vt_queue_exception,
	.cancel_injection = vt_cancel_injection,
	.interrupt_allowed = vt_interrupt_allowed,
	.nmi_allowed = vt_nmi_allowed,
	.get_nmi_mask = vt_get_nmi_mask,
	.set_nmi_mask = vt_set_nmi_mask,
	.enable_nmi_window = vt_enable_nmi_window,
	.enable_irq_window = vt_enable_irq_window,
	.update_cr8_intercept = vt_update_cr8_intercept,
	.set_virtual_apic_mode = vt_set_virtual_apic_mode,
	.set_apic_access_page_addr = vt_set_apic_access_page_addr,
	.refresh_apicv_exec_ctrl = vt_refresh_apicv_exec_ctrl,
	.load_eoi_exitmap = vt_load_eoi_exitmap,
	.apicv_post_state_restore = vt_apicv_post_state_restore,
	.check_apicv_inhibit_reasons = vmx_check_apicv_inhibit_reasons,
	.hwapic_irr_update = vt_hwapic_irr_update,
	.hwapic_isr_update = vt_hwapic_isr_update,
	.guest_apic_has_interrupt = vt_guest_apic_has_interrupt,
	.sync_pir_to_irr = vt_sync_pir_to_irr,
	.deliver_interrupt = vt_deliver_interrupt,
	.dy_apicv_has_pending_interrupt = pi_has_pending_interrupt,
	.apicv_has_pending_interrupt = vt_apicv_has_pending_interrupt,

	.set_tss_addr = vt_set_tss_addr,
	.set_identity_map_addr = vt_set_identity_map_addr,
	.get_mt_mask = vt_get_mt_mask,

	.get_exit_info = vt_get_exit_info,

	.vcpu_after_set_cpuid = vt_vcpu_after_set_cpuid,

	.has_wbinvd_exit = cpu_has_vmx_wbinvd_exit,

	.get_l2_tsc_offset = vt_get_l2_tsc_offset,
	.get_l2_tsc_multiplier = vt_get_l2_tsc_multiplier,
	.write_tsc_offset = vt_write_tsc_offset,
	.write_tsc_multiplier = vt_write_tsc_multiplier,

	.load_mmu_pgd = vt_load_mmu_pgd,

	.check_intercept = vt_check_intercept,
	.handle_exit_irqoff = vt_handle_exit_irqoff,

	.request_immediate_exit = vt_request_immediate_exit,

	.sched_in = vt_sched_in,

	.cpu_dirty_log_size = PML_ENTITY_NUM,
	.update_cpu_dirty_logging = vt_update_cpu_dirty_logging,

	.pmu_ops = &intel_pmu_ops,
	.nested_ops = &vmx_nested_ops,

	.update_pi_irte = pi_update_irte,
	.start_assignment = vmx_pi_start_assignment,

#ifdef CONFIG_X86_64
	.set_hv_timer = vt_set_hv_timer,
	.cancel_hv_timer = vt_cancel_hv_timer,
#endif

	.setup_mce = vmx_setup_mce,

	.smi_allowed = vt_smi_allowed,
	.enter_smm = vt_enter_smm,
	.leave_smm = vt_leave_smm,
	.enable_smi_window = vt_enable_smi_window,

	.can_emulate_instruction = vt_can_emulate_instruction,
	.apic_init_signal_blocked = vt_apic_init_signal_blocked,
	.migrate_timers = vmx_migrate_timers,

	.msr_filter_changed = vmx_msr_filter_changed,
	.complete_emulated_msr = kvm_complete_insn_gp,

	.vcpu_deliver_sipi_vector = vt_vcpu_deliver_sipi_vector,

	.mem_enc_op = vt_mem_enc_op,
	.mem_enc_op_vcpu = vt_mem_enc_op_vcpu,
};

struct kvm_x86_init_ops vt_init_ops __initdata = {
	.cpu_has_kvm_support = vmx_cpu_has_kvm_support,
	.disabled_by_bios = vmx_disabled_by_bios,
	.check_processor_compatibility = vmx_check_processor_compat,
	.hardware_setup = vt_hardware_setup,
	.handle_intel_pt_intr = NULL,

	.runtime_ops = &vt_x86_ops,
};

static int __init vt_init(void)
{
	unsigned int vcpu_size = 0, vcpu_align = 0;
	int r;

	/* tdx_pre_kvm_init must be called before vmx_pre_kvm_init(). */
	tdx_pre_kvm_init(&vcpu_size, &vcpu_align, &vt_x86_ops.vm_size);

	vmx_pre_kvm_init(&vcpu_size, &vcpu_align);

	r = kvm_init(&vt_init_ops, vcpu_size, vcpu_align, THIS_MODULE);
	if (r)
		goto err_vmx_post_exit;

	r = vmx_init();
	if (r)
		goto err_kvm_exit;

	return 0;

err_kvm_exit:
	kvm_exit();
err_vmx_post_exit:
	vmx_post_kvm_exit();
	return r;
}
module_init(vt_init);

static void vt_exit(void)
{
	vmx_exit();
	kvm_exit();
	vmx_post_kvm_exit();
}
module_exit(vt_exit);
