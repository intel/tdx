// SPDX-License-Identifier: GPL-2.0
/*
 * ucall support. A ucall is a "hypercall to userspace".
 *
 * Copyright (C) 2018, Red Hat, Inc.
 */
#include "kvm_util.h"

/*
 * ucall_exit_mmio_addr holds per-VM values (global data is duplicated by each
 * VM), it must not be accessed from host code.
 */
static vm_vaddr_t *ucall_exit_mmio_addr;

void ucall_arch_init(struct kvm_vm *vm, vm_paddr_t mmio_gpa)
{
	virt_pg_map(vm, mmio_gpa, mmio_gpa);

	vm->ucall_mmio_addr = mmio_gpa;

	write_guest_global(vm, ucall_exit_mmio_addr, (vm_vaddr_t *)mmio_gpa);
}

void ucall_arch_do_ucall(vm_vaddr_t uc)
{
	WRITE_ONCE(*ucall_exit_mmio_addr, uc);
}

void *ucall_arch_get_ucall(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;

	if (run->exit_reason == KVM_EXIT_MMIO &&
	    run->mmio.phys_addr == vcpu->vm->ucall_mmio_addr) {
		TEST_ASSERT(run->mmio.is_write && run->mmio.len == sizeof(uint64_t),
			    "Unexpected ucall exit mmio address access");
		return (void *)(*((uint64_t *)run->mmio.data));
	}

	return NULL;
}
