// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

#include "x86_ops.h"

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size) {}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops) { return -EOPNOTSUPP; }

int tdx_vcpu_create(struct kvm_vcpu *vcpu) { return -EOPNOTSUPP; }
void tdx_vcpu_free(struct kvm_vcpu *vcpu) {}
void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event) {}

int tdx_dev_ioctl(void __user *argp) { return -EOPNOTSUPP; }
int tdx_vm_ioctl(struct kvm *kvm, void __user *argp) { return -EOPNOTSUPP; }
int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp) { return -EOPNOTSUPP; }

void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int root_level) {}
