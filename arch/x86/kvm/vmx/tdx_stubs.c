// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

#include "x86_ops.h"

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops) { return -EOPNOTSUPP; }
