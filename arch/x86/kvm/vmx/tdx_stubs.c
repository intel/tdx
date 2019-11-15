// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

#include "x86_ops.h"

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size) {}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops) { return -EOPNOTSUPP; }
void tdx_hardware_enable(void) {}
void tdx_hardware_disable(void) {}

void tdx_vm_teardown(struct kvm *kvm) {}
int tdx_vcpu_create(struct kvm_vcpu *vcpu) { return -EOPNOTSUPP; }
void tdx_vcpu_free(struct kvm_vcpu *vcpu) {}
void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event) {}
void tdx_inject_nmi(struct kvm_vcpu *vcpu) {}
fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu) { return EXIT_FASTPATH_NONE; }
void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu) {}
void tdx_vcpu_put(struct kvm_vcpu *vcpu) {}
void tdx_set_virtual_apic_mode(struct kvm_vcpu *vcpu) {}

void tdx_prepare_switch_to_guest(struct kvm_vcpu *vcpu) {}
void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu) {}
int tdx_handle_exit(struct kvm_vcpu *vcpu,
		enum exit_fastpath_completion fastpath) { return 0; }
int tdx_get_cpl(struct kvm_vcpu *vcpu) { return 0; }
unsigned long tdx_get_rflags(struct kvm_vcpu *vcpu) { return 0; }
bool tdx_is_emulated_msr(u32 index, bool write) { return false; }
int tdx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr) { return 1; }
int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr) { return 1; }
u64 tdx_get_segment_base(struct kvm_vcpu *vcpu, int seg) { return 0; }
void tdx_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg) {}

void tdx_apicv_post_state_restore(struct kvm_vcpu *vcpu) {}
int tdx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector) { return 0; }
void tdx_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason,
		u64 *info1, u64 *info2, u32 *intr_info, u32 *error_code) {}
int tdx_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection) { return false; }
int tdx_enter_smm(struct kvm_vcpu *vcpu, char *smstate) { return 0; }
int tdx_leave_smm(struct kvm_vcpu *vcpu, const char *smstate) { return 0; }
void tdx_enable_smi_window(struct kvm_vcpu *vcpu) {}

int tdx_dev_ioctl(void __user *argp) { return -EOPNOTSUPP; }
int tdx_vm_ioctl(struct kvm *kvm, void __user *argp) { return -EOPNOTSUPP; }
int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp) { return -EOPNOTSUPP; }

void tdx_flush_tlb(struct kvm_vcpu *vcpu) {}
void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int root_level) {}
