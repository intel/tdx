// SPDX-License-Identifier: GPL-2.0
#include <linux/moduleparam.h>

#include "x86_ops.h"
#include "vmx.h"
#include "mmu.h"
#include "nested.h"
#include "pmu.h"
#include "posted_intr.h"
#include "tdx.h"
#include "tdx_arch.h"

#if IS_ENABLED(CONFIG_INTEL_TDX_HOST)
static int vt_flush_remote_tlbs(struct kvm *kvm);
static int vt_flush_remote_tlbs_range(struct kvm *kvm, gfn_t start_gfn, gfn_t nr_pages);
#endif

static void vt_hardware_disable(void)
{
	/* Note, TDX *and* VMX need to be disabled if TDX is enabled. */
	if (enable_tdx)
		tdx_hardware_disable();
	vmx_hardware_disable();
}

static __init int vt_hardware_setup(void)
{
	int ret;

	ret = vmx_hardware_setup();
	if (ret)
		return ret;

#if IS_ENABLED(CONFIG_INTEL_TDX_HOST)
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
#endif

	/*
	 * Undate vt_x86_ops::vm_size here so it is ready before
	 * kvm_ops_update() is called in kvm_x86_vendor_init().
	 *
	 * Note, the actual bringing up of TDX must be done after
	 * kvm_ops_update() because enabling TDX requires enabling
	 * hardware virtualization first, i.e., all online CPUs must
	 * be in post-VMXON state.  This means the @vm_size here
	 * may be updated to TDX's size but TDX may fail to enable
	 * at later time.
	 *
	 * The VMX/VT code could update kvm_x86_ops::vm_size again
	 * after bringing up TDX, but this would require exporting
	 * either kvm_x86_ops or kvm_ops_update() from the base KVM
	 * module, which looks overkill.  Anyway, the worst case here
	 * is KVM may allocate couple of more bytes than needed for
	 * each VM.
	 */
	if (enable_tdx) {
		vt_x86_ops.vm_size = max_t(unsigned int, vt_x86_ops.vm_size,
				sizeof(struct kvm_tdx));
		/*
		 * Note, TDX may fail to initialize in a later time in
		 * vt_init(), in which case it is not necessary to setup
		 * those callbacks.  But making them valid here even
		 * when TDX fails to init later is fine because those
		 * callbacks won't be called if the VM isn't TDX guest.
		 */
		vt_x86_ops.link_external_spt = tdx_sept_link_private_spt;
		vt_x86_ops.set_external_spte = tdx_sept_set_private_spte;
		vt_x86_ops.free_external_spt = tdx_sept_free_private_spt;
		vt_x86_ops.remove_external_spte = tdx_sept_remove_private_spte;
	}
	else
		vt_x86_ops.protected_apic_has_interrupt = NULL;

#if IS_ENABLED(CONFIG_INTEL_TDX_HOST)
	if (enable_tdx) {
		vt_x86_ops.flush_remote_tlbs = vt_flush_remote_tlbs;
		vt_x86_ops.flush_remote_tlbs_range = vt_flush_remote_tlbs_range;
	}
#endif

	return 0;
}

static int vt_vm_init(struct kvm *kvm)
{
	if (is_td(kvm))
		return tdx_vm_init(kvm);

	return vmx_vm_init(kvm);
}

static void vt_vm_destroy(struct kvm *kvm)
{
	if (is_td(kvm))
		return tdx_mmu_release_hkid(kvm);

	vmx_vm_destroy(kvm);
}

static void vt_vm_free(struct kvm *kvm)
{
	if (is_td(kvm))
		tdx_vm_free(kvm);
}

static int vt_vcpu_precreate(struct kvm *kvm)
{
	if (is_td(kvm))
		return 0;

	return vmx_vcpu_precreate(kvm);
}

static int vt_vcpu_create(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_create(vcpu);

	return vmx_vcpu_create(vcpu);
}

static void vt_vcpu_free(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_vcpu_free(vcpu);
		return;
	}

	vmx_vcpu_free(vcpu);
}

static void vt_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	if (is_td_vcpu(vcpu)) {
		tdx_vcpu_reset(vcpu, init_event);
		return;
	}

	vmx_vcpu_reset(vcpu, init_event);
}

static void vt_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_prepare_switch_to_guest(vcpu);
		return;
	}

	vmx_prepare_switch_to_guest(vcpu);
}

static void vt_vcpu_put(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_vcpu_put(vcpu);
		return;
	}

	vmx_vcpu_put(vcpu);
}

static int vt_vcpu_pre_run(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		/* Unconditionally continue to vcpu_run(). */
		return 1;

	return vmx_vcpu_pre_run(vcpu);
}

static fastpath_t vt_vcpu_run(struct kvm_vcpu *vcpu, bool force_immediate_exit)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_run(vcpu, force_immediate_exit);

	return vmx_vcpu_run(vcpu, force_immediate_exit);
}

static void vt_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_vcpu_load(vcpu, cpu);
		return;
	}

	vmx_vcpu_load(vcpu, cpu);
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
	if (is_td_vcpu(vcpu)) {
		tdx_handle_exit_irqoff(vcpu);
		return;
	}

	vmx_handle_exit_irqoff(vcpu);
}

static void vt_apicv_pre_state_restore(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi = vcpu_to_pi_desc(vcpu);

	pi_clear_on(pi);
	memset(pi->pir, 0, sizeof(pi->pir));
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

static void vt_flush_tlb_all(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_flush_tlb(vcpu);
		return;
	}

	vmx_flush_tlb_all(vcpu);
}

static void vt_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu)) {
		tdx_flush_tlb_current(vcpu);
		return;
	}

	vmx_flush_tlb_current(vcpu);
}

#if IS_ENABLED(CONFIG_INTEL_TDX_HOST)
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

static int vt_flush_remote_tlbs_range(struct kvm *kvm, gfn_t start_gfn, gfn_t nr_pages)
{
	return -EOPNOTSUPP;
}
#endif

static void vt_flush_tlb_gva(struct kvm_vcpu *vcpu, gva_t addr)
{
	if (is_td_vcpu(vcpu))
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
	if (is_td_vcpu(vcpu)) {
		tdx_inject_nmi(vcpu);
		return;
	}

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
	if (is_td_vcpu(vcpu)) {
		tdx_load_mmu_pgd(vcpu, root_hpa, pgd_level);
		return;
	}

	vmx_load_mmu_pgd(vcpu, root_hpa, pgd_level);
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

static void vt_inject_irq(struct kvm_vcpu *vcpu, bool reinjected)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_inject_irq(vcpu, reinjected);
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
		return tdx_interrupt_allowed(vcpu);

	return vmx_interrupt_allowed(vcpu, for_injection);
}

static void vt_enable_irq_window(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return;

	vmx_enable_irq_window(vcpu);
}

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

static u8 vt_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	if (is_td_vcpu(vcpu))
		return tdx_get_mt_mask(vcpu, gfn, is_mmio);

	return vmx_get_mt_mask(vcpu, gfn, is_mmio);
}

static int vt_mem_enc_ioctl(struct kvm *kvm, void __user *argp)
{
	if (!is_td(kvm))
		return -ENOTTY;

	return tdx_vm_ioctl(kvm, argp);
}

static int vt_vcpu_mem_enc_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	if (!is_td_vcpu(vcpu))
		return -EINVAL;

	return tdx_vcpu_ioctl(vcpu, argp);
}

static int vt_gmem_private_max_mapping_level(struct kvm *kvm, kvm_pfn_t pfn)
{
	if (is_td(kvm))
		return tdx_gmem_private_max_mapping_level(kvm, pfn);

	return 0;
}

#define VMX_REQUIRED_APICV_INHIBITS				\
	(BIT(APICV_INHIBIT_REASON_DISABLED) |			\
	 BIT(APICV_INHIBIT_REASON_ABSENT) |			\
	 BIT(APICV_INHIBIT_REASON_HYPERV) |			\
	 BIT(APICV_INHIBIT_REASON_BLOCKIRQ) |			\
	 BIT(APICV_INHIBIT_REASON_PHYSICAL_ID_ALIASED) |	\
	 BIT(APICV_INHIBIT_REASON_APIC_ID_MODIFIED) |		\
	 BIT(APICV_INHIBIT_REASON_APIC_BASE_MODIFIED))

struct kvm_x86_ops vt_x86_ops __initdata = {
	.name = KBUILD_MODNAME,

	.check_processor_compatibility = vmx_check_processor_compat,

	.hardware_unsetup = vmx_hardware_unsetup,

	.hardware_enable = vmx_hardware_enable,
	.hardware_disable = vt_hardware_disable,
	.emergency_disable = vmx_emergency_disable,

	.has_emulated_msr = vmx_has_emulated_msr,

	.vm_size = sizeof(struct kvm_vmx),

	.vm_init = vt_vm_init,
	.vm_destroy = vt_vm_destroy,
	.vm_free = vt_vm_free,

	.vcpu_precreate = vt_vcpu_precreate,
	.vcpu_create = vt_vcpu_create,
	.vcpu_free = vt_vcpu_free,
	.vcpu_reset = vt_vcpu_reset,

	.prepare_switch_to_guest = vt_prepare_switch_to_guest,
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

	.flush_tlb_all = vt_flush_tlb_all,
	.flush_tlb_current = vt_flush_tlb_current,
	.flush_tlb_gva = vt_flush_tlb_gva,
	.flush_tlb_guest = vt_flush_tlb_guest,

	.vcpu_pre_run = vt_vcpu_pre_run,
	.vcpu_run = vt_vcpu_run,
	.handle_exit = vt_handle_exit,
	.skip_emulated_instruction = vmx_skip_emulated_instruction,
	.update_emulated_instruction = vmx_update_emulated_instruction,
	.set_interrupt_shadow = vt_set_interrupt_shadow,
	.get_interrupt_shadow = vt_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.inject_irq = vt_inject_irq,
	.inject_nmi = vt_inject_nmi,
	.inject_exception = vmx_inject_exception,
	.cancel_injection = vt_cancel_injection,
	.interrupt_allowed = vt_interrupt_allowed,
	.nmi_allowed = vt_nmi_allowed,
	.get_nmi_mask = vt_get_nmi_mask,
	.set_nmi_mask = vt_set_nmi_mask,
	.enable_nmi_window = vt_enable_nmi_window,
	.enable_irq_window = vt_enable_irq_window,
	.update_cr8_intercept = vmx_update_cr8_intercept,
	.set_virtual_apic_mode = vmx_set_virtual_apic_mode,
	.set_apic_access_page_addr = vmx_set_apic_access_page_addr,
	.refresh_apicv_exec_ctrl = vmx_refresh_apicv_exec_ctrl,
	.load_eoi_exitmap = vmx_load_eoi_exitmap,
	.apicv_pre_state_restore = vt_apicv_pre_state_restore,
	.required_apicv_inhibits = VMX_REQUIRED_APICV_INHIBITS,
	.hwapic_irr_update = vmx_hwapic_irr_update,
	.hwapic_isr_update = vmx_hwapic_isr_update,
	.sync_pir_to_irr = vt_sync_pir_to_irr,
	.deliver_interrupt = vt_deliver_interrupt,
	.dy_apicv_has_pending_interrupt = pi_has_pending_interrupt,
	.protected_apic_has_interrupt = tdx_protected_apic_has_interrupt,

	.set_tss_addr = vmx_set_tss_addr,
	.set_identity_map_addr = vmx_set_identity_map_addr,
	.get_mt_mask = vt_get_mt_mask,

	.get_exit_info = vt_get_exit_info,

	.vcpu_after_set_cpuid = vmx_vcpu_after_set_cpuid,

	.has_wbinvd_exit = cpu_has_vmx_wbinvd_exit,

	.get_l2_tsc_offset = vmx_get_l2_tsc_offset,
	.get_l2_tsc_multiplier = vmx_get_l2_tsc_multiplier,
	.write_tsc_offset = vmx_write_tsc_offset,
	.write_tsc_multiplier = vmx_write_tsc_multiplier,

	.load_mmu_pgd = vt_load_mmu_pgd,

	.check_intercept = vmx_check_intercept,
	.handle_exit_irqoff = vt_handle_exit_irqoff,

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
	.vcpu_mem_enc_ioctl = vt_vcpu_mem_enc_ioctl,

	.private_max_mapping_level = vt_gmem_private_max_mapping_level
};

struct kvm_x86_init_ops vt_init_ops __initdata = {
	.hardware_setup = vt_hardware_setup,
	.handle_intel_pt_intr = NULL,

	.runtime_ops = &vt_x86_ops,
	.pmu_ops = &intel_pmu_ops,
};

static void vt_exit(void)
{
	kvm_exit();
	tdx_cleanup();
	vmx_exit();
}
module_exit(vt_exit);

static int __init vt_init(void)
{
	unsigned vcpu_size, vcpu_align;
	int r;

	r = vmx_init();
	if (r)
		return r;

	/* tdx_init() has been taken */
	tdx_bringup();

	/*
	 * TDX and VMX have different vCPU structures.  Calculate the
	 * maximum size/align so that kvm_init() can use the larger
	 * values to create the kmem_vcpu_cache.
	 */
	vcpu_size = sizeof(struct vcpu_vmx);
	vcpu_align = __alignof__(struct vcpu_vmx);
	if (enable_tdx) {
		vcpu_size = max_t(unsigned, vcpu_size,
				sizeof(struct vcpu_tdx));
		vcpu_align = max_t(unsigned, vcpu_align,
				__alignof__(struct vcpu_tdx));
	}

	/*
	 * Common KVM initialization _must_ come last, after this, /dev/kvm is
	 * exposed to userspace!
	 */
	r = kvm_init(vcpu_size, vcpu_align, THIS_MODULE);
	if (r)
		goto err_kvm_init;

	return 0;

err_kvm_init:
	tdx_cleanup();
	vmx_exit();
	return r;
}
module_init(vt_init);
