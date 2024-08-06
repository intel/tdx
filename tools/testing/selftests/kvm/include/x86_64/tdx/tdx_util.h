/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTESTS_TDX_KVM_UTIL_H
#define SELFTESTS_TDX_KVM_UTIL_H

#include <stdint.h>

#include "kvm_util.h"

extern uint64_t tdx_s_bit;
void tdx_filter_cpuid(struct kvm_vm *vm, struct kvm_cpuid2 *cpuid_data);
void __tdx_mask_cpuid_features(struct kvm_cpuid_entry2 *entry);

struct kvm_vcpu *td_vcpu_add(struct kvm_vm *vm, uint32_t vcpu_id, void *guest_code);

struct kvm_vm *td_create(void);
void td_initialize(struct kvm_vm *vm, enum vm_mem_backing_src_type src_type,
		   uint64_t attributes);
void td_finalize(struct kvm_vm *vm);
void td_vcpu_run(struct kvm_vcpu *vcpu);
void handle_memory_conversion(struct kvm_vm *vm, uint64_t gpa, uint64_t size,
			bool shared_to_private);

#endif // SELFTESTS_TDX_KVM_UTIL_H
