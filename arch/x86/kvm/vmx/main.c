// SPDX-License-Identifier: GPL-2.0
#include <linux/moduleparam.h>

#include "x86_ops.h"
#include "vmx.h"
#include "nested.h"
#include "pmu.h"
#include "tdx.h"
#include "tdx_arch.h"

static bool enable_tdx __ro_after_init;
module_param_named(tdx, enable_tdx, bool, 0444);

static bool vt_is_vm_type_supported(unsigned long type)
{
	return __kvm_is_vm_type_supported(type) ||
		(enable_tdx && tdx_is_vm_type_supported(type));
}

static int vt_max_vcpus(struct kvm *kvm)
{
	if (!kvm)
		return KVM_MAX_VCPUS;

	if (is_td(kvm))
		return min(kvm->max_vcpus, TDX_MAX_VCPUS);

	return kvm->max_vcpus;
}

static __init int vt_hardware_setup(void)
{
	int ret;

	ret = vmx_hardware_setup();
	if (ret)
		return ret;

	enable_tdx = enable_tdx && !tdx_hardware_setup(&vt_x86_ops);
	if (enable_tdx)
		vt_x86_ops.vm_size = max_t(unsigned int, vt_x86_ops.vm_size,
					   sizeof(struct kvm_tdx));

	return 0;
}

static void vt_hardware_unsetup(void)
{
	if (enable_tdx)
		tdx_hardware_unsetup();
	vmx_hardware_unsetup();
}

static int vt_vm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	if (is_td(kvm))
		return tdx_vm_enable_cap(kvm, cap);

	return -EINVAL;
}

static int vt_vm_init(struct kvm *kvm)
{
	if (is_td(kvm))
		return tdx_vm_init(kvm);

	return vmx_vm_init(kvm);
}

static void vt_flush_shadow_all_private(struct kvm *kvm)
{
	if (is_td(kvm))
		tdx_mmu_release_hkid(kvm);
}

static void vt_vm_destroy(struct kvm *kvm)
{
	if (is_td(kvm))
		return;

	vmx_vm_destroy(kvm);
}

static void vt_vm_free(struct kvm *kvm)
{
	if (is_td(kvm))
		tdx_vm_free(kvm);
}

static int vt_mem_enc_ioctl(struct kvm *kvm, void __user *argp)
{
	if (!is_td(kvm))
		return -ENOTTY;

	return tdx_vm_ioctl(kvm, argp);
}

#define VMX_REQUIRED_APICV_INHIBITS				\
	(BIT(APICV_INHIBIT_REASON_DISABLE)|			\
	 BIT(APICV_INHIBIT_REASON_ABSENT) |			\
	 BIT(APICV_INHIBIT_REASON_HYPERV) |			\
	 BIT(APICV_INHIBIT_REASON_BLOCKIRQ) |			\
	 BIT(APICV_INHIBIT_REASON_PHYSICAL_ID_ALIASED) |	\
	 BIT(APICV_INHIBIT_REASON_APIC_ID_MODIFIED) |		\
	 BIT(APICV_INHIBIT_REASON_APIC_BASE_MODIFIED))

struct kvm_x86_ops vt_x86_ops __initdata = {
	.name = KBUILD_MODNAME,

	.check_processor_compatibility = vmx_check_processor_compat,

	.hardware_unsetup = vt_hardware_unsetup,
	.offline_cpu = tdx_offline_cpu,

	/* TDX cpu enablement is done by tdx_hardware_setup(). */
	.hardware_enable = vmx_hardware_enable,
	.hardware_disable = vmx_hardware_disable,
	.has_emulated_msr = vmx_has_emulated_msr,

	.is_vm_type_supported = vt_is_vm_type_supported,
	.max_vcpus = vt_max_vcpus,
	.vm_size = sizeof(struct kvm_vmx),
	.vm_enable_cap = vt_vm_enable_cap,
	.vm_init = vt_vm_init,
	.flush_shadow_all_private = vt_flush_shadow_all_private,
	.vm_destroy = vt_vm_destroy,
	.vm_free = vt_vm_free,

	.vcpu_precreate = vmx_vcpu_precreate,
	.vcpu_create = vmx_vcpu_create,
	.vcpu_free = vmx_vcpu_free,
	.vcpu_reset = vmx_vcpu_reset,

	.prepare_switch_to_guest = vmx_prepare_switch_to_guest,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,

	.update_exception_bitmap = vmx_update_exception_bitmap,
	.get_msr_feature = vmx_get_msr_feature,
	.get_msr = vmx_get_msr,
	.set_msr = vmx_set_msr,
	.get_segment_base = vmx_get_segment_base,
	.get_segment = vmx_get_segment,
	.set_segment = vmx_set_segment,
	.get_cpl = vmx_get_cpl,
	.get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	.is_valid_cr0 = vmx_is_valid_cr0,
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

	.flush_tlb_all = vmx_flush_tlb_all,
	.flush_tlb_current = vmx_flush_tlb_current,
	.flush_tlb_gva = vmx_flush_tlb_gva,
	.flush_tlb_guest = vmx_flush_tlb_guest,

	.vcpu_pre_run = vmx_vcpu_pre_run,
	.vcpu_run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,
	.skip_emulated_instruction = vmx_skip_emulated_instruction,
	.update_emulated_instruction = vmx_update_emulated_instruction,
	.set_interrupt_shadow = vmx_set_interrupt_shadow,
	.get_interrupt_shadow = vmx_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.inject_irq = vmx_inject_irq,
	.inject_nmi = vmx_inject_nmi,
	.inject_exception = vmx_inject_exception,
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
	.apicv_pre_state_restore = vmx_apicv_pre_state_restore,
	.required_apicv_inhibits = VMX_REQUIRED_APICV_INHIBITS,
	.hwapic_irr_update = vmx_hwapic_irr_update,
	.hwapic_isr_update = vmx_hwapic_isr_update,
	.guest_apic_has_interrupt = vmx_guest_apic_has_interrupt,
	.sync_pir_to_irr = vmx_sync_pir_to_irr,
	.deliver_interrupt = vmx_deliver_interrupt,
	.dy_apicv_has_pending_interrupt = pi_has_pending_interrupt,

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

	.load_mmu_pgd = vmx_load_mmu_pgd,

	.check_intercept = vmx_check_intercept,
	.handle_exit_irqoff = vmx_handle_exit_irqoff,

	.request_immediate_exit = vmx_request_immediate_exit,

	.sched_in = vmx_sched_in,

	.cpu_dirty_log_size = PML_ENTITY_NUM,
	.update_cpu_dirty_logging = vmx_update_cpu_dirty_logging,

	.nested_ops = &vmx_nested_ops,

	.pi_update_irte = vmx_pi_update_irte,
	.pi_start_assignment = vmx_pi_start_assignment,

#ifdef CONFIG_X86_64
	.set_hv_timer = vmx_set_hv_timer,
	.cancel_hv_timer = vmx_cancel_hv_timer,
#endif

	.setup_mce = vmx_setup_mce,

#ifdef CONFIG_KVM_SMM
	.smi_allowed = vmx_smi_allowed,
	.enter_smm = vmx_enter_smm,
	.leave_smm = vmx_leave_smm,
	.enable_smi_window = vmx_enable_smi_window,
#endif

	.check_emulate_instruction = vmx_check_emulate_instruction,
	.apic_init_signal_blocked = vmx_apic_init_signal_blocked,
	.migrate_timers = vmx_migrate_timers,

	.msr_filter_changed = vmx_msr_filter_changed,
	.complete_emulated_msr = kvm_complete_insn_gp,

	.vcpu_deliver_sipi_vector = kvm_vcpu_deliver_sipi_vector,

	.get_untagged_addr = vmx_get_untagged_addr,

	.mem_enc_ioctl = vt_mem_enc_ioctl,
};

struct kvm_x86_init_ops vt_init_ops __initdata = {
	.hardware_setup = vt_hardware_setup,
	.handle_intel_pt_intr = NULL,

	.runtime_ops = &vt_x86_ops,
	.pmu_ops = &intel_pmu_ops,
};

static int __init vt_init(void)
{
	unsigned int vcpu_size, vcpu_align;
	int cpu, r;

	if (!kvm_is_vmx_supported())
		return -EOPNOTSUPP;

	/*
	 * Note, hv_init_evmcs() touches only VMX knobs, i.e. there's nothing
	 * to unwind if a later step fails.
	 */
	hv_init_evmcs();

	/* vmx_hardware_disable() accesses loaded_vmcss_on_cpu. */
	for_each_possible_cpu(cpu)
		INIT_LIST_HEAD(&per_cpu(loaded_vmcss_on_cpu, cpu));

	r = kvm_x86_vendor_init(&vt_init_ops);
	if (r)
		return r;

	r = vmx_init();
	if (r)
		goto err_vmx_init;

	/*
	 * Common KVM initialization _must_ come last, after this, /dev/kvm is
	 * exposed to userspace!
	 */
	/*
	 * kvm_x86_ops is updated with vt_x86_ops.  vt_x86_ops.vm_size must
	 * be set before kvm_x86_vendor_init().
	 */
	vcpu_size = sizeof(struct vcpu_vmx);
	vcpu_align = __alignof__(struct vcpu_vmx);
	if (enable_tdx) {
		vcpu_size = max_t(unsigned int, vcpu_size,
				  sizeof(struct vcpu_tdx));
		vcpu_align = max_t(unsigned int, vcpu_align,
				   __alignof__(struct vcpu_tdx));
	}
	r = kvm_init(vcpu_size, vcpu_align, THIS_MODULE);
	if (r)
		goto err_kvm_init;

	return 0;

err_kvm_init:
	vmx_exit();
err_vmx_init:
	kvm_x86_vendor_exit();
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
