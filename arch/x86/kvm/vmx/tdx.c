// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/kvm_host.h>

#include "tdx_errno.h"
#include "tdx_ops.h"
#include "x86_ops.h"
#include "tdx.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
			unsigned int *vcpu_align, unsigned int *vm_size)
{
	*vcpu_size = sizeof(struct vcpu_tdx);
	*vcpu_align = __alignof__(struct vcpu_tdx);

	if (sizeof(struct kvm_tdx) > *vm_size)
		*vm_size = sizeof(struct kvm_tdx);
}
