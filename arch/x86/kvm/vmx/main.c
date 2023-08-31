// SPDX-License-Identifier: GPL-2.0
#include <linux/moduleparam.h>

#include "x86_ops.h"
#include "vmx.h"
#include "nested.h"
#include "common.h"
#include "mmu.h"
#include "pmu.h"
#include "tdx.h"
#include "tdx_arch.h"

static bool enable_tdx __ro_after_init;
module_param_named(tdx, enable_tdx, bool, 0444);

bool vt_is_vm_type_supported(unsigned long type)
{
	return __kvm_is_vm_type_supported(type) ||
		(enable_tdx && tdx_is_vm_type_supported(type));
}

int vt_max_vcpus(struct kvm *kvm)
{
	if (!kvm)
		return KVM_MAX_VCPUS;

	if (is_td(kvm))
		return min3(kvm->max_vcpus, KVM_MAX_VCPUS, TDX_MAX_VCPUS);

	return kvm->max_vcpus;
}

static int vt_flush_remote_tlbs(struct kvm *kvm);
static int vt_flush_remote_tlbs_range(struct kvm *kvm, gfn_t gfn, gfn_t nr_pages);

int vt_hardware_enable(void)
{
	return vmx_hardware_enable();
}

void vt_hardware_disable(void)
{
	/* Note, TDX *and* VMX need to be disabled if TDX is enabled. */
	if (enable_tdx)
		tdx_hardware_disable();
	vmx_hardware_disable();
}

__init int vt_hardware_setup(void)
{
	int ret;

	ret = vmx_hardware_setup();
	if (ret)
		return ret;

	/*
	 * As kvm_mmu_set_ept_masks() updates enable_mmio_caching, call it
	 * before checking enable_mmio_caching.
	 */
	if (enable_ept)
		kvm_mmu_set_ept_masks(enable_ept_ad_bits,
				      cpu_has_vmx_ept_execute_only());

	/* TDX requires MMIO caching. */
	if (enable_tdx && !enable_mmio_caching) {
		enable_tdx = false;
		pr_warn_ratelimited("TDX requires mmio caching.  Please enable mmio caching for TDX.\n");
	}

	/*
	 * TDX KVM overrides flush_remote_tlbs method and assumes
	 * flush_remote_tlbs_range = NULL that falls back to
	 * flush_remote_tlbs.  Disable TDX if there are conflicts.
	 */
	if (vt_x86_ops.flush_remote_tlbs ||
	    vt_x86_ops.flush_remote_tlbs_range) {
		enable_tdx = false;
		pr_warn_ratelimited("TDX requires baremetal. Not Supported on VMM guest.\n");
	}

	enable_tdx = enable_tdx && !tdx_hardware_setup(&vt_x86_ops);

	if (enable_tdx) {
		vt_x86_ops.flush_remote_tlbs = vt_flush_remote_tlbs;
		vt_x86_ops.flush_remote_tlbs_range = vt_flush_remote_tlbs_range;
	} else
		vt_x86_ops.protected_apic_has_interrupt = NULL;

	return 0;
}

int vt_vm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	if (is_td(kvm))
		return tdx_vm_enable_cap(kvm, cap);

	return -EINVAL;
}

void vt_hardware_unsetup(void)
{
	if (enable_tdx)
		tdx_hardware_unsetup();
	vmx_hardware_unsetup();
}

int vt_vm_init(struct kvm *kvm)
{
	if (is_td(kvm))
		return tdx_vm_init(kvm);

	return vmx_vm_init(kvm);
}

void vt_flush_shadow_all_private(struct kvm *kvm)
{
	if (is_td(kvm))
		tdx_mmu_release_hkid(kvm);
}

void vt_vm_destroy(struct kvm *kvm)
{
	if (is_td(kvm))
		return;

	vmx_vm_destroy(kvm);
}

void vt_vm_free(struct kvm *kvm)
{
	if (is_td(kvm))
		tdx_vm_free(kvm);
}

int vt_vcpu_precreate(struct kvm *kvm)
{
	if (is_td(kvm))
		return 0;

	return vmx_vcpu_precreate(kvm);
}

int vt_vcpu_create(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_create(vcpu);

	return vmx_vcpu_create(vcpu);
}

void vt_vcpu_free(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_vcpu_free(vcpu);
		return;
	}

	vmx_vcpu_free(vcpu);
}

void vt_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	if (is_td_vcpu(vcpu)) {
		tdx_vcpu_reset(vcpu, init_event);
		return;
	}

	vmx_vcpu_reset(vcpu, init_event);
}

void vt_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
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

void vt_vcpu_put(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_vcpu_put(vcpu);
		return;
	}

	vmx_vcpu_put(vcpu);
}

int vt_vcpu_pre_run(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		/* Unconditionally continue to vcpu_run(). */
		return 1;

	return vmx_vcpu_pre_run(vcpu);
}

fastpath_t vt_vcpu_run(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_run(vcpu);

	return vmx_vcpu_run(vcpu);
}

void vt_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_vcpu_load(vcpu, cpu);
		return;
	}

	vmx_vcpu_load(vcpu, cpu);
}

bool vt_protected_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(!is_td_vcpu(vcpu), vcpu->kvm);

	return tdx_protected_apic_has_interrupt(vcpu);
}

int vt_handle_exit(struct kvm_vcpu *vcpu, enum exit_fastpath_completion fastpath)
{
	if (is_td_vcpu(vcpu))
		return tdx_handle_exit(vcpu, fastpath);

	return vmx_handle_exit(vcpu, fastpath);
}

void vt_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_handle_exit_irqoff(vcpu);
		return;
	}

	vmx_handle_exit_irqoff(vcpu);
}

int vt_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	if (unlikely(is_td_vcpu(vcpu)))
		return tdx_set_msr(vcpu, msr_info);

	return vmx_set_msr(vcpu, msr_info);
}

/*
 * The kvm parameter can be NULL (module initialization, or invocation before
 * VM creation). Be sure to check the kvm parameter before using it.
 */
bool vt_has_emulated_msr(struct kvm *kvm, u32 index)
{
	if (kvm && is_td(kvm))
		return tdx_has_emulated_msr(index, true);

	return vmx_has_emulated_msr(kvm, index);
}

int vt_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	if (unlikely(is_td_vcpu(vcpu)))
		return tdx_get_msr(vcpu, msr_info);

	return vmx_get_msr(vcpu, msr_info);
}

void vt_msr_filter_changed(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_msr_filter_changed(vcpu);
}

#ifdef CONFIG_KVM_SMM
int vt_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	if (is_td_vcpu(vcpu))
		return tdx_smi_allowed(vcpu, for_injection);

	return vmx_smi_allowed(vcpu, for_injection);
}

int vt_enter_smm(struct kvm_vcpu *vcpu, union kvm_smram *smram)
{
	if (unlikely(is_td_vcpu(vcpu)))
		return tdx_enter_smm(vcpu, smram);

	return vmx_enter_smm(vcpu, smram);
}

int vt_leave_smm(struct kvm_vcpu *vcpu, const union kvm_smram *smram)
{
	if (unlikely(is_td_vcpu(vcpu)))
		return tdx_leave_smm(vcpu, smram);

	return vmx_leave_smm(vcpu, smram);
}

void vt_enable_smi_window(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_enable_smi_window(vcpu);
		return;
	}

	/* RSM will cause a vmexit anyway.  */
	vmx_enable_smi_window(vcpu);
}
#endif

bool vt_can_emulate_instruction(struct kvm_vcpu *vcpu, int emul_type,
				       void *insn, int insn_len)
{
	if (is_td_vcpu(vcpu))
		return false;

	return vmx_can_emulate_instruction(vcpu, emul_type, insn, insn_len);
}

int vt_check_intercept(struct kvm_vcpu *vcpu,
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

bool vt_apic_init_signal_blocked(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return true;

	return vmx_apic_init_signal_blocked(vcpu);
}

void vt_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_set_virtual_apic_mode(vcpu);

	return vmx_set_virtual_apic_mode(vcpu);
}

void vt_apicv_post_state_restore(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi = vcpu_to_pi_desc(vcpu);

	pi_clear_on(pi);
	memset(pi->pir, 0, sizeof(pi->pir));
}

void vt_hwapic_irr_update(struct kvm_vcpu *vcpu, int max_irr)
{
	if (is_td_vcpu(vcpu))
		return;

	return vmx_hwapic_irr_update(vcpu, max_irr);
}

void vt_hwapic_isr_update(int max_isr)
{
	if (is_td_vcpu(kvm_get_running_vcpu()))
		return;

	return vmx_hwapic_isr_update(max_isr);
}

bool vt_guest_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	/* TDX doesn't support L2 at the moment. */
	if (WARN_ON_ONCE(is_td_vcpu(vcpu)))
		return false;

	return vmx_guest_apic_has_interrupt(vcpu);
}

int vt_sync_pir_to_irr(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return -1;

	return vmx_sync_pir_to_irr(vcpu);
}

void vt_deliver_interrupt(struct kvm_lapic *apic, int delivery_mode,
			   int trig_mode, int vector)
{
	if (is_td_vcpu(apic->vcpu)) {
		tdx_deliver_interrupt(apic, delivery_mode, trig_mode,
					     vector);
		return;
	}

	vmx_deliver_interrupt(apic, delivery_mode, trig_mode, vector);
}

void vt_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector)
{
	if (is_td_vcpu(vcpu))
		return;

	kvm_vcpu_deliver_sipi_vector(vcpu, vector);
}

void vt_vcpu_deliver_init(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		/* TDX doesn't support INIT.  Ignore INIT event */
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
		return;
	}

	kvm_vcpu_deliver_init(vcpu);
}

int vt_vcpu_check_cpuid(struct kvm_vcpu *vcpu,
			struct kvm_cpuid_entry2 *e2, int nent)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_check_cpuid(vcpu, e2, nent);

	return 0;
}

void vt_vcpu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_vcpu_after_set_cpuid(vcpu);
}

void vt_update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_update_exception_bitmap(vcpu);
		return;
	}

	vmx_update_exception_bitmap(vcpu);
}

u64 vt_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_segment_base(vcpu, seg);

	return vmx_get_segment_base(vcpu, seg);
}

void vt_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	if (is_td_vcpu(vcpu)) {
		tdx_get_segment(vcpu, var, seg);
		return;
	}

	vmx_get_segment(vcpu, var, seg);
}

void vt_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_segment(vcpu, var, seg);
}

int vt_get_cpl(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_cpl(vcpu);

	return vmx_get_cpl(vcpu);
}

void vt_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	if (is_td_vcpu(vcpu)) {
		tdx_get_cs_db_l_bits(vcpu, db, l);
		return;
	}

	vmx_get_cs_db_l_bits(vcpu, db, l);
}

bool vt_is_valid_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	if (is_td_vcpu(vcpu))
		return true;

	return vmx_is_valid_cr0(vcpu, cr0);
}

void vt_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_cr0(vcpu, cr0);
}

bool vt_is_valid_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	if (is_td_vcpu(vcpu))
		return true;

	return vmx_is_valid_cr4(vcpu, cr4);
}

void vt_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_cr4(vcpu, cr4);
}

int vt_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	if (is_td_vcpu(vcpu))
		return 0;

	return vmx_set_efer(vcpu, efer);
}

void vt_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (is_td_vcpu(vcpu)) {
		tdx_get_idt(vcpu, dt);
		return;
	}

	vmx_get_idt(vcpu, dt);
}

void vt_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (is_td_vcpu(vcpu)) {
		tdx_set_idt(vcpu, dt);
		return;
	}

	vmx_set_idt(vcpu, dt);
}

void vt_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_gdt(vcpu, dt);

	vmx_get_gdt(vcpu, dt);
}

void vt_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	if (is_td_vcpu(vcpu))
		return tdx_set_gdt(vcpu, dt);

	vmx_set_gdt(vcpu, dt);
}

void vt_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	if (is_td_vcpu(vcpu)) {
		tdx_set_dr7(vcpu, val);
		return;
	}

	vmx_set_dr7(vcpu, val);
}

void vt_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_sync_dirty_debug_regs(vcpu);
		return;
	}

	vmx_sync_dirty_debug_regs(vcpu);
}

void vt_load_guest_debug_regs(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_load_guest_debug_regs(vcpu);
		return;
	}

	load_guest_debug_regs(vcpu);
}

void vt_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	if (is_td_vcpu(vcpu)) {
		tdx_cache_reg(vcpu, reg);
		return;
	}

	vmx_cache_reg(vcpu, reg);
}

unsigned long vt_get_rflags(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_rflags(vcpu);

	return vmx_get_rflags(vcpu);
}

void vt_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	if (is_td_vcpu(vcpu)) {
		tdx_set_rflags(vcpu, rflags);
		return;
	}

	vmx_set_rflags(vcpu, rflags);
}

bool vt_get_if_flag(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_if_flag(vcpu);

	return vmx_get_if_flag(vcpu);
}

unsigned long vt_get_cr2(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_cr2(vcpu);

	return kvm_get_cr2(vcpu);
}

unsigned long vt_get_xcr(struct kvm_vcpu *vcpu, int index)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_xcr(vcpu, index);

	return kvm_get_xcr(vcpu, index);
}

void vt_flush_tlb_all(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_flush_tlb(vcpu);
		return;
	}

	vmx_flush_tlb_all(vcpu);
}

void vt_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_flush_tlb_current(vcpu);
		return;
	}

	vmx_flush_tlb_current(vcpu);
}

static int vt_flush_remote_tlbs(struct kvm *kvm)
{
	if (is_td(kvm))
		return tdx_sept_flush_remote_tlbs(kvm);

	/*
	 * fallback to KVM_REQ_TLB_FLUSH.
	 * See kvm_arch_flush_remote_tlb() and kvm_flush_remote_tlbs().
	 */
	return -EOPNOTSUPP;
}

static int vt_flush_remote_tlbs_range(struct kvm *kvm, gfn_t gfn, gfn_t nr_pages)
{
	if (is_td(kvm))
		return tdx_sept_flush_remote_tlbs_range(kvm, gfn, nr_pages);

	/* fallback to flush_remote_tlbs method */
	return -EOPNOTSUPP;
}

void vt_flush_tlb_gva(struct kvm_vcpu *vcpu, gva_t addr)
{
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return;

	vmx_flush_tlb_gva(vcpu, addr);
}

void vt_flush_tlb_guest(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_flush_tlb_guest(vcpu);
}

void vt_inject_nmi(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_inject_nmi(vcpu);
		return;
	}

	vmx_inject_nmi(vcpu);
}

int vt_nmi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	/*
	 * The TDX module manages NMI windows and NMI reinjection, and hides NMI
	 * blocking, all KVM can do is throw an NMI over the wall.
	 */
	if (is_td_vcpu(vcpu))
		return true;

	return vmx_nmi_allowed(vcpu, for_injection);
}

bool vt_get_nmi_mask(struct kvm_vcpu *vcpu)
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

void vt_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_nmi_mask(vcpu, masked);
}

void vt_enable_nmi_window(struct kvm_vcpu *vcpu)
{
	/* Refer the comment in vt_get_nmi_mask(). */
	if (is_td_vcpu(vcpu))
		return;

	vmx_enable_nmi_window(vcpu);
}

void vt_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int pgd_level)
{
	if (is_td_vcpu(vcpu)) {
		tdx_load_mmu_pgd(vcpu, root_hpa, pgd_level);
		return;
	}

	vmx_load_mmu_pgd(vcpu, root_hpa, pgd_level);
}

void vt_sched_in(struct kvm_vcpu *vcpu, int cpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_sched_in(vcpu, cpu);
}

void vt_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	if (is_td_vcpu(vcpu)) {
		tdx_set_interrupt_shadow(vcpu, mask);
		return;
	}

	vmx_set_interrupt_shadow(vcpu, mask);
}

u32 vt_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu) && !is_debug_td(vcpu))
		return 0;

	return __vmx_get_interrupt_shadow(vcpu);
}

void vt_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/*
	 * Because guest memory is protected, guest can't be patched. TD kernel
	 * is modified to use TDG.VP.VMCAL for hypercall.
	 */
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return;

	vmx_patch_hypercall(vcpu, hypercall);
}

void vt_inject_irq(struct kvm_vcpu *vcpu, bool reinjected)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_inject_irq(vcpu, reinjected);
}

void vt_inject_exception(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu) && is_debug_td(vcpu)) {
		tdx_inject_exception(vcpu);
		return;
	}
	if (is_td_vcpu(vcpu))
		return;

	vmx_inject_exception(vcpu);
}

void vt_cancel_injection(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_cancel_injection(vcpu);
}

int vt_interrupt_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	if (is_td_vcpu(vcpu))
		return true;

	return vmx_interrupt_allowed(vcpu, for_injection);
}

void vt_enable_irq_window(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_enable_irq_window(vcpu);
}

void vt_request_immediate_exit(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		__kvm_request_immediate_exit(vcpu);
		return;
	}

	vmx_request_immediate_exit(vcpu);
}

void vt_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason,
			u64 *info1, u64 *info2, u32 *intr_info, u32 *error_code)
{
	if (is_td_vcpu(vcpu)) {
		tdx_get_exit_info(vcpu, reason, info1, info2, intr_info,
				  error_code);
		return;
	}

	vmx_get_exit_info(vcpu, reason, info1, info2, intr_info, error_code);
}


void vt_update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_update_cr8_intercept(vcpu, tpr, irr);
}

void vt_set_apic_access_page_addr(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_set_apic_access_page_addr(vcpu);
}

void vt_refresh_apicv_exec_ctrl(struct kvm_vcpu *vcpu)
{
	if (WARN_ON_ONCE(is_td_vcpu(vcpu)))
		return;

	vmx_refresh_apicv_exec_ctrl(vcpu);
}

void vt_load_eoi_exitmap(struct kvm_vcpu *vcpu, u64 *eoi_exit_bitmap)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_load_eoi_exitmap(vcpu, eoi_exit_bitmap);
}

int vt_set_tss_addr(struct kvm *kvm, unsigned int addr)
{
	if (is_td(kvm))
		return 0;

	return vmx_set_tss_addr(kvm, addr);
}

int vt_set_identity_map_addr(struct kvm *kvm, u64 ident_addr)
{
	if (is_td(kvm))
		return 0;

	return vmx_set_identity_map_addr(kvm, ident_addr);
}

u8 vt_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_mt_mask(vcpu, gfn, is_mmio);

	return vmx_get_mt_mask(vcpu, gfn, is_mmio);
}

u64 vt_get_l2_tsc_offset(struct kvm_vcpu *vcpu)
{
	/* TDX doesn't support L2 guest at the moment. */
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return 0;

	return vmx_get_l2_tsc_offset(vcpu);
}

u64 vt_get_l2_tsc_multiplier(struct kvm_vcpu *vcpu)
{
	/* TDX doesn't support L2 guest at the moment. */
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return 0;

	return vmx_get_l2_tsc_multiplier(vcpu);
}

void vt_write_tsc_offset(struct kvm_vcpu *vcpu)
{
	/* In TDX, tsc offset can't be changed. */
	if (is_td_vcpu(vcpu))
		return;

	vmx_write_tsc_offset(vcpu);
}

void vt_write_tsc_multiplier(struct kvm_vcpu *vcpu)
{
	/* In TDX, tsc multiplier can't be changed. */
	if (is_td_vcpu(vcpu))
		return;

	vmx_write_tsc_multiplier(vcpu);
}

void vt_update_cpu_dirty_logging(struct kvm_vcpu *vcpu)
{
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return;

	vmx_update_cpu_dirty_logging(vcpu);
}

#ifdef CONFIG_X86_64
int vt_set_hv_timer(struct kvm_vcpu *vcpu, u64 guest_deadline_tsc,
			      bool *expired)
{
	/* VMX-preemption timer isn't available for TDX. */
	if (is_td_vcpu(vcpu))
		return -EINVAL;

	return vmx_set_hv_timer(vcpu, guest_deadline_tsc, expired);
}

void vt_cancel_hv_timer(struct kvm_vcpu *vcpu)
{
	/* VMX-preemption timer can't be set.  See vt_set_hv_timer(). */
	if (KVM_BUG_ON(is_td_vcpu(vcpu), vcpu->kvm))
		return;

	vmx_cancel_hv_timer(vcpu);
}
#endif

void vt_setup_mce(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_setup_mce(vcpu);
}

#ifdef CONFIG_KVM_PRIVATE_MEM
void vt_gmem_invalidate(struct kvm *kvm, kvm_pfn_t start, kvm_pfn_t end)
{
	if (is_td(kvm))
		tdx_gmem_invalidate(kvm, start, end);
}
#endif

int vt_mem_enc_ioctl(struct kvm *kvm, void __user *argp)
{
	if (!is_td(kvm))
		return -ENOTTY;

	return tdx_vm_ioctl(kvm, argp);
}

int vt_vcpu_mem_enc_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	if (!is_td_vcpu(vcpu))
		return -EINVAL;

	return tdx_vcpu_ioctl(vcpu, argp);
}

int vt_move_enc_context_from(struct kvm *kvm, unsigned int source_fd)
{
	if (!is_td(kvm))
		return -ENOTTY;

	return tdx_vm_move_enc_context_from(kvm, source_fd);
}

int vt_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_skip_emulated_instruction(vcpu);

	return vmx_skip_emulated_instruction(vcpu);
}

struct kvm_x86_init_ops vt_init_ops __initdata = {
	.hardware_setup = vt_hardware_setup,
	.handle_intel_pt_intr = NULL,

	.runtime_ops = &vt_x86_ops,
	.pmu_ops = &intel_pmu_ops,
};

static int __init vt_init(void)
{
	unsigned int vcpu_size, vcpu_align;
	int r;

	if (!kvm_is_vmx_supported())
		return -EOPNOTSUPP;

	/*
	 * Note, hv_init_evmcs() touches only VMX knobs, i.e. there's nothing
	 * to unwind if a later step fails.
	 */
	hv_init_evmcs();

	/*
	 * kvm_x86_ops is updated with vt_x86_ops.  vt_x86_ops.vm_size must
	 * be set before kvm_x86_vendor_init().
	 */
	vcpu_size = sizeof(struct vcpu_vmx);
	vcpu_align = __alignof__(struct vcpu_vmx);
	if (enable_tdx) {
		vt_x86_ops.vm_size = max_t(unsigned int, vt_x86_ops.vm_size,
					   sizeof(struct kvm_tdx));
		vcpu_size = max_t(unsigned int, vcpu_size,
				  sizeof(struct vcpu_tdx));
		vcpu_align = max_t(unsigned int, vcpu_align,
				   __alignof__(struct vcpu_tdx));
	}

	r = vmx_init();
	if (r)
		goto err_vmx_init;

	r = kvm_x86_vendor_init(&vt_init_ops);
	if (r)
		goto err_vmx_init;

	/*
	 * Common KVM initialization _must_ come last, after this, /dev/kvm is
	 * exposed to userspace!
	 */
	r = kvm_init(vcpu_size, vcpu_align, THIS_MODULE);
	if (r)
		goto err_kvm_init;

	return 0;

err_kvm_init:
	kvm_x86_vendor_exit();
err_vmx_init:
	vmx_exit();
	return r;
}
module_init(vt_init);

static void vt_exit(void)
{
	kvm_exit();
	kvm_x86_vendor_exit();
	vmx_exit();
}
module_exit(vt_exit);
