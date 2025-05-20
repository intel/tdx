// SPDX-License-Identifier: GPL-2.0-only
#include "linux/types.h"
#include "linux/bitmap.h"
#include "linux/atomic.h"

#include "kvm_util.h"
#include "ucall_common.h"


#define GUEST_UCALL_FAILED -1

struct ucall_header {
	DECLARE_BITMAP(in_use, KVM_MAX_VCPUS);
	struct ucall ucalls[KVM_MAX_VCPUS];
};

int ucall_nr_pages_required(uint64_t page_size)
{
	return align_up(sizeof(struct ucall_header), page_size) / page_size;
}

/*
 * ucall_pool holds per-VM values (global data is duplicated by each VM), it
 * should generally not be accessed from host code other than via ucall_free(),
 * to cleanup after using GUEST_DONE()
 */
static struct ucall_header *ucall_pool;

void ucall_init(struct kvm_vm *vm, vm_paddr_t mmio_gpa)
{
	struct ucall *uc;
	vm_vaddr_t vaddr;
	int i;

	vaddr = vm_vaddr_alloc_shared(vm, sizeof(*ucall_pool),
				      KVM_UTIL_MIN_VADDR, MEM_REGION_UCALL);

	ucall_pool = (struct ucall_header *)addr_gva2hva(vm, vaddr);
	memset(ucall_pool, 0, sizeof(*ucall_pool));

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		uc = &ucall_pool->ucalls[i];
		uc->hva = uc;
	}

	write_guest_global(vm, ucall_pool, (struct ucall_header *)vaddr);

	ucall_arch_init(vm, mmio_gpa);
}

static struct ucall *ucall_alloc(void)
{
	struct ucall *uc;
	int i;

	if (!ucall_pool)
		goto ucall_failed;

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		if (!test_and_set_bit(i, ucall_pool->in_use)) {
			uc = &ucall_pool->ucalls[i];
			memset(uc->args, 0, sizeof(uc->args));
			return uc;
		}
	}

ucall_failed:
	/*
	 * If the vCPU cannot grab a ucall structure, make a bare ucall with a
	 * magic value to signal to get_ucall() that things went sideways.
	 * GUEST_ASSERT() depends on ucall_alloc() and so cannot be used here.
	 */
	ucall_arch_do_ucall(GUEST_UCALL_FAILED);
	return NULL;
}

void ucall_free(struct ucall *uc)
{
	/* Beware, here be pointer arithmetic.  */
	clear_bit(uc - ucall_pool->ucalls, ucall_pool->in_use);
}

void ucall_assert(uint64_t cmd, const char *exp, const char *file,
		  unsigned int line, const char *fmt, ...)
{
	struct ucall *uc;
	va_list va;

	uc = ucall_alloc();
	uc->cmd = cmd;

	WRITE_ONCE(uc->args[GUEST_ERROR_STRING], (uint64_t)(exp));
	WRITE_ONCE(uc->args[GUEST_FILE], (uint64_t)(file));
	WRITE_ONCE(uc->args[GUEST_LINE], line);

	va_start(va, fmt);
	guest_vsnprintf(uc->buffer, UCALL_BUFFER_LEN, fmt, va);
	va_end(va);

	ucall_arch_do_ucall((vm_vaddr_t)uc->hva);

	ucall_free(uc);
}

void ucall_fmt(uint64_t cmd, const char *fmt, ...)
{
	struct ucall *uc;
	va_list va;

	uc = ucall_alloc();
	uc->cmd = cmd;

	va_start(va, fmt);
	guest_vsnprintf(uc->buffer, UCALL_BUFFER_LEN, fmt, va);
	va_end(va);

	ucall_arch_do_ucall((vm_vaddr_t)uc->hva);

	ucall_free(uc);
}

static uint64_t do_ucall(struct ucall *uc_out, uint64_t cmd, int nargs,
			 va_list va)
{
	struct ucall *uc;
	uint64_t out;
	int i;

	uc = ucall_alloc();

	WRITE_ONCE(uc->cmd, cmd);

	nargs = min(nargs, UCALL_MAX_ARGS);

	for (i = 0; i < nargs; ++i)
		WRITE_ONCE(uc->args[i], va_arg(va, uint64_t));

	ucall_arch_do_ucall((vm_vaddr_t)uc->hva);

	out = UCALL_NONE;
	if (uc_out) {
		memcpy(uc_out, uc, sizeof(*uc));
		out = uc_out->cmd;
	}

	ucall_free(uc);

	return out;
}

void ucall(uint64_t cmd, int nargs, ...)
{
	va_list va;

	va_start(va, nargs);
	do_ucall(NULL, cmd, nargs, va);
	va_end(va);
}

uint64_t ucall_read(struct ucall *uc_out, uint64_t cmd, int nargs, ...)
{
	uint64_t out;
	va_list va;

	va_start(va, nargs);
	out = do_ucall(uc_out, cmd, nargs, va);
	va_end(va);

	return out;
}

struct ucall *do_get_ucall(struct kvm_vcpu *vcpu)
{
	struct ucall *uc;

	uc = ucall_arch_get_ucall(vcpu);
	if (!uc)
		return NULL;

	TEST_ASSERT(uc != (struct ucall *)GUEST_UCALL_FAILED,
		    "Guest failed to allocate ucall struct");

	vcpu_run_complete_io(vcpu);

	return uc;
}

uint64_t get_ucall(struct kvm_vcpu *vcpu, struct ucall *uc)
{
	struct ucall *uc_received;

	uc_received = do_get_ucall(vcpu);
	if (!uc_received)
		return UCALL_NONE;

	if (!uc)
		return uc_received->cmd;

	memcpy(uc, uc_received, sizeof(*uc));
	return uc->cmd;
}

uint64_t get_writable_ucall(struct kvm_vcpu *vcpu, struct ucall **uc)
{
	struct ucall *uc_received;

	uc_received = do_get_ucall(vcpu);
	*uc = uc_received;

	if (!uc_received)
		return UCALL_NONE;

	return uc_received->cmd;
}
