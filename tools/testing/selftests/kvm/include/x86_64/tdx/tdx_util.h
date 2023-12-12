/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTESTS_TDX_KVM_UTIL_H
#define SELFTESTS_TDX_KVM_UTIL_H

#include <stdint.h>

#include "kvm_util.h"

struct kvm_vcpu *td_vcpu_add(struct kvm_vm *vm, uint32_t vcpu_id, void *guest_code);

struct kvm_vm *td_create(void);
void td_initialize(struct kvm_vm *vm, enum vm_mem_backing_src_type src_type,
		   uint64_t attributes);
void td_finalize(struct kvm_vm *vm);

#endif // SELFTESTS_TDX_KVM_UTIL_H
