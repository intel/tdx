// SPDX-License-Identifier: GPL-2.0-only
#include "kvm_util.h"
#include "linux/types.h"
#include "linux/bitmap.h"
#include "linux/atomic.h"

struct ucall_header {
	DECLARE_BITMAP(in_use, KVM_MAX_VCPUS);
	struct ucall ucalls[KVM_MAX_VCPUS];
};

/*
 * ucall_pool holds per-VM values (global data is duplicated by each VM), it
 * must not be accessed from host code.
 */
static struct ucall_header *ucall_pool;

void ucall_init(struct kvm_vm *vm, vm_paddr_t mmio_gpa)
{
	struct ucall_header *hdr;
	struct ucall *uc;
	vm_vaddr_t vaddr;
	int i;

	vaddr = vm_vaddr_alloc(vm, sizeof(*hdr), KVM_UTIL_MIN_VADDR);
	hdr = (struct ucall_header *)addr_gva2hva(vm, vaddr);
	memset(hdr, 0, sizeof(*hdr));

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		uc = &hdr->ucalls[i];
		uc->hva = uc;
	}

	write_guest_global(vm, ucall_pool, (struct ucall_header *)vaddr);

	ucall_arch_init(vm, mmio_gpa);
}

static struct ucall *ucall_alloc(void)
{
	struct ucall *uc;
	int i;

	GUEST_ASSERT(ucall_pool);

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		if (!test_and_set_bit(i, ucall_pool->in_use)) {
			uc = &ucall_pool->ucalls[i];
			memset(uc->args, 0, sizeof(uc->args));
			return uc;
		}
	}

	GUEST_ASSERT(0);
	return NULL;
}

static void ucall_free(struct ucall *uc)
{
	/* Beware, here be pointer arithmetic.  */
	clear_bit(uc - ucall_pool->ucalls, ucall_pool->in_use);
}

void ucall(uint64_t cmd, int nargs, ...)
{
	struct ucall *uc;
	va_list va;
	int i;

	uc = ucall_alloc();

	WRITE_ONCE(uc->cmd, cmd);

	nargs = min(nargs, UCALL_MAX_ARGS);

	va_start(va, nargs);
	for (i = 0; i < nargs; ++i)
		WRITE_ONCE(uc->args[i], va_arg(va, uint64_t));
	va_end(va);

	ucall_arch_do_ucall((vm_vaddr_t)uc->hva);

	ucall_free(uc);
}

uint64_t get_ucall(struct kvm_vcpu *vcpu, struct ucall *uc)
{
	struct ucall ucall;
	void *addr;

	if (!uc)
		uc = &ucall;

	addr = ucall_arch_get_ucall(vcpu);
	if (addr) {
		memcpy(uc, addr, sizeof(*uc));
		vcpu_run_complete_io(vcpu);
	} else {
		memset(uc, 0, sizeof(*uc));
	}

	return uc->cmd;
}
