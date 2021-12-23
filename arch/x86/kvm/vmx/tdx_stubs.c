// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

#include "x86_ops.h"

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size) {}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops) { return -EOPNOTSUPP; }
void tdx_hardware_enable(void) {}
void tdx_hardware_disable(void) {}

int tdx_vcpu_create(struct kvm_vcpu *vcpu) { return -EOPNOTSUPP; }
void tdx_vcpu_free(struct kvm_vcpu *vcpu) {}
void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event) {}
fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu) { return EXIT_FASTPATH_NONE; }
void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu) {}
void tdx_vcpu_put(struct kvm_vcpu *vcpu) {}
void tdx_prepare_switch_to_guest(struct kvm_vcpu *vcpu) {}

void tdx_apicv_post_state_restore(struct kvm_vcpu *vcpu) {}
int tdx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector) { return 0; }

int tdx_dev_ioctl(void __user *argp) { return -EOPNOTSUPP; }
int tdx_vm_ioctl(struct kvm *kvm, void __user *argp) { return -EOPNOTSUPP; }
int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp) { return -EOPNOTSUPP; }

void tdx_flush_tlb(struct kvm_vcpu *vcpu) {}
void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int root_level) {}
