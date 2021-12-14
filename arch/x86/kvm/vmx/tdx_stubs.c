// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

#include "x86_ops.h"

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size) {}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops) { return -EOPNOTSUPP; }

int tdx_dev_ioctl(void __user *argp) { return -EOPNOTSUPP; }
