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

static bool vt_apicv_has_pending_interrupt(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return pi_has_pending_interrupt(vcpu);

	return false;
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
	.has_emulated_msr = vmx_has_emulated_msr,

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

	.update_exception_bitmap = vmx_update_exception_bitmap,
	.get_msr_feature = vmx_get_msr_feature,
	.get_msr = vmx_get_msr,
	.set_msr = vmx_set_msr,
	.get_segment_base = vmx_get_segment_base,
	.get_segment = vmx_get_segment,
	.set_segment = vmx_set_segment,
	.get_cpl = vmx_get_cpl,
	.get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	.set_cr0 = vmx_set_cr0,
	.is_valid_cr4 = vmx_is_valid_cr4,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer,
	.get_idt = vmx_get_idt,
	.set_idt = vmx_set_idt,
	.get_gdt = vmx_get_gdt,
	.set_gdt = vmx_set_gdt,
	.set_dr7 = vmx_set_dr7,
	.sync_dirty_debug_regs = vmx_sync_dirty_debug_regs,
	.cache_reg = vmx_cache_reg,
	.get_rflags = vmx_get_rflags,
	.set_rflags = vmx_set_rflags,
	.get_if_flag = vmx_get_if_flag,

	.tlb_flush_all = vt_flush_tlb_all,
	.tlb_flush_current = vt_flush_tlb_current,
	.tlb_flush_gva = vt_flush_tlb_gva,
	.tlb_flush_guest = vt_flush_tlb_guest,

	.vcpu_pre_run = vmx_vcpu_pre_run,
	.run = vt_vcpu_run,
	.handle_exit = vmx_handle_exit,
	.skip_emulated_instruction = vmx_skip_emulated_instruction,
	.update_emulated_instruction = vmx_update_emulated_instruction,
	.set_interrupt_shadow = vmx_set_interrupt_shadow,
	.get_interrupt_shadow = vmx_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.set_irq = vmx_inject_irq,
	.set_nmi = vmx_inject_nmi,
	.queue_exception = vmx_queue_exception,
	.cancel_injection = vmx_cancel_injection,
	.interrupt_allowed = vmx_interrupt_allowed,
	.nmi_allowed = vmx_nmi_allowed,
	.get_nmi_mask = vmx_get_nmi_mask,
	.set_nmi_mask = vmx_set_nmi_mask,
	.enable_nmi_window = vmx_enable_nmi_window,
	.enable_irq_window = vmx_enable_irq_window,
	.update_cr8_intercept = vmx_update_cr8_intercept,
	.set_virtual_apic_mode = vmx_set_virtual_apic_mode,
	.set_apic_access_page_addr = vmx_set_apic_access_page_addr,
	.refresh_apicv_exec_ctrl = vmx_refresh_apicv_exec_ctrl,
	.load_eoi_exitmap = vmx_load_eoi_exitmap,
	.apicv_post_state_restore = vmx_apicv_post_state_restore,
	.check_apicv_inhibit_reasons = vmx_check_apicv_inhibit_reasons,
	.hwapic_irr_update = vmx_hwapic_irr_update,
	.hwapic_isr_update = vmx_hwapic_isr_update,
	.guest_apic_has_interrupt = vmx_guest_apic_has_interrupt,
	.sync_pir_to_irr = vmx_sync_pir_to_irr,
	.deliver_interrupt = vmx_deliver_interrupt,
	.dy_apicv_has_pending_interrupt = pi_has_pending_interrupt,
	.apicv_has_pending_interrupt = vt_apicv_has_pending_interrupt,

	.set_tss_addr = vmx_set_tss_addr,
	.set_identity_map_addr = vmx_set_identity_map_addr,
	.get_mt_mask = vmx_get_mt_mask,

	.get_exit_info = vmx_get_exit_info,

	.vcpu_after_set_cpuid = vmx_vcpu_after_set_cpuid,

	.has_wbinvd_exit = cpu_has_vmx_wbinvd_exit,

	.get_l2_tsc_offset = vmx_get_l2_tsc_offset,
	.get_l2_tsc_multiplier = vmx_get_l2_tsc_multiplier,
	.write_tsc_offset = vmx_write_tsc_offset,
	.write_tsc_multiplier = vmx_write_tsc_multiplier,

	.load_mmu_pgd = vt_load_mmu_pgd,

	.check_intercept = vmx_check_intercept,
	.handle_exit_irqoff = vmx_handle_exit_irqoff,

	.request_immediate_exit = vmx_request_immediate_exit,

	.sched_in = vt_sched_in,

	.cpu_dirty_log_size = PML_ENTITY_NUM,
	.update_cpu_dirty_logging = vmx_update_cpu_dirty_logging,

	.pmu_ops = &intel_pmu_ops,
	.nested_ops = &vmx_nested_ops,

	.update_pi_irte = pi_update_irte,
	.start_assignment = vmx_pi_start_assignment,

#ifdef CONFIG_X86_64
	.set_hv_timer = vmx_set_hv_timer,
	.cancel_hv_timer = vmx_cancel_hv_timer,
#endif

	.setup_mce = vmx_setup_mce,

	.smi_allowed = vmx_smi_allowed,
	.enter_smm = vmx_enter_smm,
	.leave_smm = vmx_leave_smm,
	.enable_smi_window = vmx_enable_smi_window,

	.can_emulate_instruction = vmx_can_emulate_instruction,
	.apic_init_signal_blocked = vmx_apic_init_signal_blocked,
	.migrate_timers = vmx_migrate_timers,

	.msr_filter_changed = vmx_msr_filter_changed,
	.complete_emulated_msr = kvm_complete_insn_gp,

	.vcpu_deliver_sipi_vector = kvm_vcpu_deliver_sipi_vector,

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
