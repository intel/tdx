// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022, Google LLC.
 */
#include <asm/vmx.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>
#include <linux/memfd.h>
#include <linux/sizes.h>

#include <test_util.h>
#include <kvm_util.h>
#include <processor.h>

#include "ucall_common.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"

#define BASE_DATA_SLOT		10
#define BASE_DATA_GPA		((uint64_t)(1ull << 32))
#define PER_CPU_DATA_SIZE	((uint64_t)(SZ_2M + PAGE_SIZE))

/* Select any bit that can be used as a flag */
#define TD_GVA_SHARED_BIT BIT_ULL(36)

/* Horrific macro so that the line info is captured accurately :-( */
#define memcmp_g(gva, pattern,  size)								\
do {												\
	uint8_t *mem = (uint8_t *)gva;								\
	size_t i;										\
												\
	for (i = 0; i < size; i++)								\
		__GUEST_ASSERT(mem[i] == pattern,						\
			       "Guest expected 0x%x at offset %lu (gva 0x%lx), got 0x%x",	\
			       pattern, i, gva + i, mem[i]);					\
} while (0)

static void memcmp_h(uint8_t *mem, uint64_t gva, uint8_t pattern, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		TEST_ASSERT(mem[i] == pattern,
			    "Host expected 0x%x at gva 0x%lx, got 0x%x",
			    pattern, gva + i, mem[i]);
}

/*
 * Run memory conversion tests with explicit conversion:
 * Execute KVM hypercall to map/unmap gpa range which will cause userspace exit
 * to back/unback private memory. Subsequent accesses by guest to the gpa range
 * will not cause exit to userspace.
 *
 * Test memory conversion scenarios with following steps:
 * 1) Access private memory using private access and verify that memory contents
 *   are not visible to userspace.
 * 2) Convert memory to shared using explicit conversions and ensure that
 *   userspace is able to access the shared regions.
 * 3) Convert memory back to private using explicit conversions and ensure that
 *   userspace is again not able to access converted private regions.
 */

#define GUEST_STAGE(o, s) { .offset = o, .size = s }

enum ucall_syncs {
	SYNC_BASE_ADDR = NUM_UCALLS + 1,
	SYNC_SHARED,
	SYNC_PRIVATE,
	UCALL_PUNCH_HOLE,
};

static void guest_sync_shared(uint64_t gpa, uint64_t size,
			      uint8_t current_pattern, uint8_t new_pattern)
{
	GUEST_SYNC5(SYNC_SHARED, gpa, size, current_pattern, new_pattern);
}

static void guest_sync_private(uint64_t gpa, uint64_t size, uint8_t pattern)
{
	GUEST_SYNC4(SYNC_PRIVATE, gpa, size, pattern);
}

static struct test_params {
	enum vm_mem_backing_src_type shared_mem_src_type;
	enum vm_private_mem_backing_src_type private_mem_src_type;
	bool back_shared_memory_with_guest_memfd;
	uint32_t nr_vcpus;
	uint32_t nr_memslots;
	uint8_t vm_type;
} test_params;

/* Arbitrary values; KVM_X86_SW_PROTECTED_VM doesn't care about the attribute flags. */
#define MAP_GPA_SET_ATTRIBUTES	BIT(0)
#define MAP_GPA_SHARED		BIT(1)
#define MAP_GPA_DO_FALLOCATE	BIT(2)

static uint64_t arch_s_bit;

static void guest_map_mem(uint64_t gpa, uint64_t size, bool map_shared,
			  bool do_fallocate)
{
	if (test_params.vm_type == KVM_X86_TDX_VM) {
		uint64_t failed_gpa;
		uint64_t ret;

		if (map_shared)
			gpa |= arch_s_bit;

		ret = tdg_vp_vmcall_map_gpa(gpa, size, &failed_gpa);
		GUEST_ASSERT_EQ(ret, 0);
	} else {
		uint64_t flags = MAP_GPA_SET_ATTRIBUTES;

		if (map_shared)
			flags |= MAP_GPA_SHARED;
		if (do_fallocate)
			flags |= MAP_GPA_DO_FALLOCATE;
		kvm_hypercall_map_gpa_range(gpa, size, flags);
	}
}

static void guest_map_shared(uint64_t gpa, uint64_t size, bool do_fallocate)
{
	guest_map_mem(gpa, size, true, do_fallocate);
}

static void guest_map_private(uint64_t gpa, uint64_t size, bool do_fallocate)
{
	guest_map_mem(gpa, size, false, do_fallocate);
}

struct {
	uint64_t offset;
	uint64_t size;
} static const test_ranges[] = {
	GUEST_STAGE(0, PAGE_SIZE),
	GUEST_STAGE(0, SZ_2M),
	GUEST_STAGE(PAGE_SIZE, PAGE_SIZE),
	GUEST_STAGE(PAGE_SIZE, SZ_2M),
	GUEST_STAGE(SZ_2M, PAGE_SIZE),
};

static uint64_t make_shared(uint64_t addr)
{
	if (test_params.vm_type == KVM_X86_TDX_VM)
		addr |= TD_GVA_SHARED_BIT;

	return addr;
}

static uint64_t make_private(uint64_t addr)
{
	if (test_params.vm_type == KVM_X86_TDX_VM)
		addr &= ~TD_GVA_SHARED_BIT;

	return addr;
}

static void guest_test_explicit_conversion(uint64_t base_addr, bool do_fallocate)
{
	const uint8_t def_p = 0xaa;
	const uint8_t init_p = 0xcc;
	uint64_t base_gva_shared;
	uint64_t base_gpa;
	uint64_t j;
	int i;

	/* Memory should be shared by default. */
	base_gva_shared = make_shared(base_addr);
	base_gpa = base_addr;

	memset((void *)base_gva_shared, def_p, PER_CPU_DATA_SIZE);
	memcmp_g(base_gva_shared, def_p, PER_CPU_DATA_SIZE);
	guest_sync_shared(base_gpa, PER_CPU_DATA_SIZE, def_p, init_p);

	memcmp_g(base_gva_shared, init_p, PER_CPU_DATA_SIZE);

	for (i = 0; i < ARRAY_SIZE(test_ranges); i++) {
		const uint8_t p1 = 0x11;
		const uint8_t p2 = 0x22;
		const uint8_t p3 = 0x33;
		const uint8_t p4 = 0x44;
		uint64_t gva_private;
		uint64_t gva_shared;
		uint64_t size;
		uint64_t addr;
		uint64_t gpa;

		size = test_ranges[i].size;
		addr = base_addr + test_ranges[i].offset;
		gpa = addr;
		gva_shared = make_shared(addr);
		gva_private = make_private(addr);

		/*
		 * Set the test region to pattern one to differentiate it from
		 * the data range as a whole (contains the initial pattern).
		 */
		memset((void *)gva_shared, p1, size);

		/*
		 * Convert to private, set and verify the private data, and
		 * then verify that the rest of the data (map shared) still
		 * holds the initial pattern, and that the host always sees the
		 * shared memory (initial pattern).  Unlike shared memory,
		 * punching a hole in private memory is destructive, i.e.
		 * previous values aren't guaranteed to be preserved.
		 */
		guest_map_private(gpa, size, do_fallocate);

		if (size > PAGE_SIZE) {
			memset((void *)gva_private, p2, PAGE_SIZE);
			goto skip;
		}

		memset((void *)gva_private, p2, size);
		guest_sync_private(gpa, size, p1);

		/*
		 * Verify that the private memory was set to pattern two, and
		 * that shared memory still holds the initial pattern.
		 */
		memcmp_g(gva_private, p2, size);
		if (addr > base_addr)
			memcmp_g(base_gva_shared, init_p, addr - base_addr);
		if (addr + size < base_addr + PER_CPU_DATA_SIZE)
			memcmp_g(gva_shared + size, init_p,
				 (base_addr + PER_CPU_DATA_SIZE) - (addr + size));

		/*
		 * Convert odd-number page frames back to shared to verify KVM
		 * also correctly handles holes in private ranges.
		 */
		for (j = 0; j < size; j += PAGE_SIZE) {
			if ((j >> PAGE_SHIFT) & 1) {
				guest_map_shared(gpa + j, PAGE_SIZE, do_fallocate);
				guest_sync_shared(gpa + j, PAGE_SIZE, p1, p3);

				memcmp_g(gva_shared + j, p3, PAGE_SIZE);
			} else {
				guest_sync_private(gpa + j, PAGE_SIZE, p1);
			}
		}

skip:
		/*
		 * Convert the entire region back to shared, explicitly write
		 * pattern three to fill in the even-number frames before
		 * asking the host to verify (and write pattern four).
		 */
		guest_map_shared(gpa, size, do_fallocate);
		memset((void *)gva_shared, p3, size);
		guest_sync_shared(gpa, size, p3, p4);
		memcmp_g(gva_shared, p4, size);

		/*
		 * Free (via PUNCH_HOLE) *all* private memory so that the next
		 * iteration starts from a clean slate, e.g. with respect to
		 * whether or not there are pages/folios in guest_mem.
		 */
		guest_map_shared(base_gpa, PER_CPU_DATA_SIZE, true);

		/*
		 * Reset the entire block back to the initial pattern. Do this
		 * after fallocate(PUNCH_HOLE) because hole-punching zeroes
		 * memory.
		 */
		memset((void *)base_gva_shared, init_p, PER_CPU_DATA_SIZE);
	}
}

static void guest_punch_hole(uint64_t gpa, uint64_t size)
{
	ucall(UCALL_PUNCH_HOLE, 2, gpa, size);
}

/*
 * Test that PUNCH_HOLE actually frees memory by punching holes without doing a
 * proper conversion.  Freeing (PUNCH_HOLE) should zap SPTEs, and reallocating
 * (subsequent fault) should zero memory.
 */
static void guest_test_punch_hole(uint64_t base_addr, bool precise)
{
	const uint8_t init_p = 0xcc;
	int i;

	/*
	 * Convert the entire range to private, this testcase is all about
	 * punching holes in guest_memfd, i.e. shared mappings aren't needed.
	 */
	guest_map_private(base_addr, PER_CPU_DATA_SIZE, false);

	for (i = 0; i < ARRAY_SIZE(test_ranges); i++) {
		uint64_t gpa = base_addr + test_ranges[i].offset;
		uint64_t size = test_ranges[i].size;

		/*
		 * Free all memory before each iteration, even for the !precise
		 * case where the memory will be faulted back in.  Freeing and
		 * reallocating should obviously work, and freeing all memory
		 * minimizes the probability of cross-testcase influence.
		 */
		guest_punch_hole(base_addr, PER_CPU_DATA_SIZE);

		/* Fault-in and initialize memory, and verify the pattern. */
		if (precise) {
			memset((void *)gpa, init_p, size);
			memcmp_g(gpa, init_p, size);
		} else {
			memset((void *)base_addr, init_p, PER_CPU_DATA_SIZE);
			memcmp_g(base_addr, init_p, PER_CPU_DATA_SIZE);
		}

		/*
		 * Punch a hole at the target range and verify that reads from
		 * the guest succeed and return zeroes.
		 */
		guest_punch_hole(gpa, size);
		memcmp_g(gpa, 0, size);
	}
}

static void guest_code(void)
{
	uint64_t base_addr;
	struct ucall uc;
	uint64_t cmd;

	cmd = ucall_read(&uc, UCALL_SYNC, 0);
	GUEST_ASSERT_EQ(cmd, SYNC_BASE_ADDR);
	base_addr = uc.args[0];

	/*
	 * Run the conversion test twice, with and without doing fallocate() on
	 * the guest_memfd backing when converting between shared and private.
	 *
	 * For TDX VMs, fallocate() is not performed by userspace VMM,
	 * do_fallocate is ignored.
	 */
	guest_test_explicit_conversion(base_addr, false);
	if (test_params.vm_type != KVM_X86_TDX_VM)
		guest_test_explicit_conversion(base_addr, true);

	/*
	 * Run the PUNCH_HOLE test twice too, once with the entire guest_memfd
	 * faulted in, once with only the target range faulted in.
	 */
	guest_test_punch_hole(base_addr, false);
	guest_test_punch_hole(base_addr, true);
	GUEST_DONE();
}

static void handle_exit_hypercall(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	struct kvm_vm *vm = vcpu->vm;
	uint64_t size;
	uint64_t gpa;
	bool set_attributes;
	bool map_shared;
	bool do_fallocate;

	gpa = run->hypercall.args[0];
	size = run->hypercall.args[1] * PAGE_SIZE;

	if (test_params.vm_type == KVM_X86_TDX_VM) {
		set_attributes = true;
		map_shared = !(vcpu->run->hypercall.args[2] &
			       KVM_MAP_GPA_RANGE_ENCRYPTED);
		do_fallocate = false;
	} else {
		set_attributes = run->hypercall.args[2] & MAP_GPA_SET_ATTRIBUTES;
		map_shared = run->hypercall.args[2] & MAP_GPA_SHARED;
		do_fallocate = run->hypercall.args[2] & MAP_GPA_DO_FALLOCATE;
	}

	TEST_ASSERT(run->hypercall.nr == KVM_HC_MAP_GPA_RANGE,
		    "Wanted MAP_GPA_RANGE (%u), got '%llu'",
		    KVM_HC_MAP_GPA_RANGE, run->hypercall.nr);

	if (do_fallocate)
		vm_guest_mem_fallocate(vm, gpa, size, map_shared);

	if (set_attributes) {
		if (test_params.back_shared_memory_with_guest_memfd) {
			loff_t offset;
			int guest_memfd;

			guest_memfd = addr_gpa2guest_memfd(vm, gpa, &offset);

			if (map_shared)
				guest_memfd_convert_shared(guest_memfd, offset, size);
			else
				guest_memfd_convert_private(guest_memfd, offset, size);
		} else {
			uint64_t attrs;

			attrs = map_shared ? 0 : KVM_MEMORY_ATTRIBUTE_PRIVATE;
			vm_set_memory_attributes(vm, gpa, size, attrs);
		}
	}
	run->hypercall.ret = 0;
}

static void assert_not_faultable(uint8_t *address)
{
	pid_t child_pid;

	child_pid = fork();
	TEST_ASSERT(child_pid != -1, "fork failed");

	if (child_pid == 0) {
		*address = 'A';
		TEST_FAIL("Child should have exited with a signal");
	} else {
		int status;

		waitpid(child_pid, &status, 0);

		TEST_ASSERT(WIFSIGNALED(status),
			    "Child should have exited with a signal");
		TEST_ASSERT_EQ(WTERMSIG(status), SIGBUS);
	}
}

static void add_memslot(struct kvm_vm *vm, uint64_t gpa, uint32_t slot,
			uint64_t size, int guest_memfd,
			uint64_t guest_memfd_offset, uint64_t guest_memfd_flags)
{
	struct userspace_mem_region *region;

	region = vm_mem_region_alloc(vm);

	guest_memfd = vm_mem_region_install_guest_memfd(region, guest_memfd,
							guest_memfd_flags);

	vm_mem_region_mmap(region, size, MAP_SHARED, guest_memfd, guest_memfd_offset);
	vm_mem_region_install_memory(region, size, getpagesize());

	region->region.slot = slot;
	region->region.flags = KVM_MEM_GUEST_MEMFD;
	region->region.guest_phys_addr = gpa;
	region->region.guest_memfd_offset = guest_memfd_offset;

	vm_mem_region_add(vm, region);
}

static bool run_vcpus;

static void setup_guest_base_addr(struct kvm_vcpu *vcpu, uint64_t base_addr)
{
	struct ucall *uc;

	vcpu_run(vcpu);

	get_writable_ucall(vcpu, &uc);
	uc->cmd = SYNC_BASE_ADDR;
	uc->args[0] = base_addr;
}

struct thread_args {
	struct kvm_vcpu *vcpu;
	uint64_t base_addr;
};

static void *__test_mem_conversions(void *params)
{
	struct thread_args *args = params;
	struct kvm_vcpu *vcpu = args->vcpu;
	struct kvm_run *run = vcpu->run;
	struct kvm_vm *vm = vcpu->vm;
	struct ucall uc;

	setup_guest_base_addr(vcpu, args->base_addr);

	while (!READ_ONCE(run_vcpus))
		;

	for ( ;; ) {
		uint32_t expected_ucall_exit_reason;

		vcpu_run(vcpu);

		if (run->exit_reason == KVM_EXIT_HYPERCALL) {
			handle_exit_hypercall(vcpu);
			continue;
		}

		expected_ucall_exit_reason =
			test_params.vm_type == KVM_X86_TDX_VM ? KVM_EXIT_MMIO :
								KVM_EXIT_IO;
		TEST_ASSERT(run->exit_reason == expected_ucall_exit_reason,
			    "Wanted %s, got exit reason: %u (%s)",
			    exit_reason_str(expected_ucall_exit_reason),
			    run->exit_reason,
			    exit_reason_str(run->exit_reason));

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		case UCALL_PRINTF:
			REPORT_GUEST_PRINTF(uc);
			break;
		case UCALL_PUNCH_HOLE: {
			uint64_t gpa  = uc.args[0];
			size_t size = uc.args[1];

			vm_guest_mem_fallocate(vm, gpa, size, true);
			break;
		}
		case UCALL_SYNC: {
			uint64_t gpa  = uc.args[1];
			size_t size = uc.args[2];
			size_t i;

			TEST_ASSERT(uc.args[0] == SYNC_SHARED ||
				    uc.args[0] == SYNC_PRIVATE,
				    "Unknown sync command '%ld'", uc.args[0]);

			for (i = 0; i < size; i += vm->page_size) {
				size_t nr_bytes = min_t(size_t, vm->page_size, size - i);
				uint8_t *hva = addr_gpa2hva(vm, gpa + i);

				/* Check contents of memory */
				if (test_params.back_shared_memory_with_guest_memfd &&
				    uc.args[0] == SYNC_PRIVATE) {
					assert_not_faultable(hva);
				} else {
					/*
					 * If shared and private memory use
					 * separate backing memory, the host
					 * should always observe shared data.
					 */
					memcmp_h(hva, gpa + i, uc.args[3], nr_bytes);
				}

				/* For shared, write the new pattern to guest memory. */
				if (uc.args[0] == SYNC_SHARED)
					memset(hva, uc.args[4], nr_bytes);
			}
			break;
		}
		case UCALL_DONE:
			return NULL;
		default:
			TEST_FAIL("Unknown ucall 0x%lx.", uc.cmd);
		}
	}
}

static struct kvm_vm *test_vm_setup(size_t per_cpu_size, struct kvm_vcpu *vcpus[KVM_MAX_VCPUS], int *guest_memfd)
{
	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = KVM_X86_SW_PROTECTED_VM,
	};
	struct kvm_vm *vm;
	size_t memfd_size;
	size_t slot_size;
	uint64_t flags;
	int memfd;
	int i;

	memfd_size = per_cpu_size * test_params.nr_vcpus;
	slot_size = memfd_size / test_params.nr_memslots;

	TEST_ASSERT(slot_size * test_params.nr_memslots == memfd_size,
		    "The memfd size (0x%lx) needs to be cleanly divisible by the number of memslots (%u)",
		    memfd_size, test_params.nr_memslots);
	vm = __vm_create_with_vcpus(shape, test_params.nr_vcpus, 0, guest_code, vcpus);

	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL, (1 << KVM_HC_MAP_GPA_RANGE));

	flags = test_params.back_shared_memory_with_guest_memfd ?
			GUEST_MEMFD_FLAG_SUPPORT_SHARED :
			0;
	flags |= vm_private_mem_backing_src_alias(test_params.private_mem_src_type)->flag;
	memfd = vm_create_guest_memfd(vm, memfd_size, flags);

	for (i = 0; i < test_params.nr_memslots; i++) {
		if (test_params.back_shared_memory_with_guest_memfd) {
			add_memslot(vm, BASE_DATA_GPA + slot_size * i,
				    BASE_DATA_SLOT + i, slot_size, memfd,
				    slot_size * i, flags);
		} else {
			vm_mem_add(vm, test_params.shared_mem_src_type,
				   BASE_DATA_GPA + slot_size * i,
				   BASE_DATA_SLOT + i,
				   slot_size / vm->page_size,
				   KVM_MEM_GUEST_MEMFD, memfd, slot_size * i);

		}
	}

	for (i = 0; i < test_params.nr_vcpus; i++) {
		uint64_t gpa = BASE_DATA_GPA + i * per_cpu_size;

		/*
		 * Map only what is needed so that an out-of-bounds access
		 * results #PF => SHUTDOWN instead of data corruption.
		 */
		virt_map(vm, gpa, gpa, PER_CPU_DATA_SIZE / vm->page_size);
	}

	sync_global_to_guest(vm, test_params);

	*guest_memfd = memfd;
	return vm;
}

static void guest_ve_handler(struct ex_regs *regs)
{
	struct ve_info ve;
	uint64_t ret;

	ret = tdg_vp_veinfo_get(&ve);
	GUEST_ASSERT(!ret);

	/* For this test, we will only handle EXIT_REASON_EPT_VIOLATION */
	GUEST_ASSERT_EQ(ve.exit_reason, EXIT_REASON_EPT_VIOLATION);

	ret = td_guest_accept(ve.gpa & PAGE_MASK);
	GUEST_ASSERT(!ret);
}

static struct kvm_vm *test_td_setup(size_t per_cpu_size,
				    struct kvm_vcpu *vcpus[KVM_MAX_VCPUS],
				    int *guest_memfd)
{
	uint64_t guest_memfd_flags;
	size_t per_cpu_nr_pages;
	size_t test_nr_pages;
	struct kvm_vm *vm;
	size_t test_size;
	size_t slot_size;
	int i;

	vm = td_create();

	test_size = per_cpu_size * test_params.nr_vcpus;
	test_nr_pages = test_size >> vm->page_shift;
	td_initialize_with_extra_mem_pages(vm, VM_MEM_SRC_ANONYMOUS, 0, test_nr_pages);

	for (i = 0; i < test_params.nr_vcpus; ++i)
		vcpus[i] = td_vcpu_add(vm, i, guest_code);

	vm_install_exception_handler(vm, VE_VECTOR, guest_ve_handler);

	test_params.back_shared_memory_with_guest_memfd = true;
	guest_memfd_flags = GUEST_MEMFD_FLAG_SUPPORT_SHARED;
	*guest_memfd = vm_create_guest_memfd(vm, test_size, guest_memfd_flags);
	TEST_ASSERT(*guest_memfd > 0, "guest_memfd creation failed");

	slot_size = test_size / test_params.nr_memslots;
	for (i = 0; i < test_params.nr_memslots; i++) {
		add_memslot(vm, BASE_DATA_GPA + slot_size * i,
			    BASE_DATA_SLOT + i, slot_size, *guest_memfd,
			    slot_size * i, guest_memfd_flags);
	}

	write_guest_global(vm, arch_s_bit, vm->arch.s_bit);
	sync_global_to_guest(vm, test_params);

	per_cpu_nr_pages = PER_CPU_DATA_SIZE / vm->page_size;
	for (i = 0; i < test_params.nr_vcpus; i++) {
		uint64_t gpa = BASE_DATA_GPA + i * per_cpu_size;

		/*
		 * By mapping the same GPA as shared and private, the TD does
		 * not have to remap its page tables at runtime to perform
		 * private and shared accesses.
		 */
		virt_map_private(vm, gpa, gpa, per_cpu_nr_pages);
		virt_map_shared(vm, gpa | TD_GVA_SHARED_BIT, gpa, per_cpu_nr_pages);
	}

	td_finalize(vm);

	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL, BIT_ULL(KVM_HC_MAP_GPA_RANGE));

	return vm;
}

static void test_mem_conversions(void)
{
	struct kvm_vcpu *vcpus[KVM_MAX_VCPUS];
	struct thread_args thread_args[KVM_MAX_VCPUS];
	pthread_t threads[KVM_MAX_VCPUS];
	size_t per_cpu_size;
	size_t memfd_size;
	struct kvm_vm *vm;
	size_t alignment;
	int memfd, i, r;

	/*
	 * Allocate enough memory so that each vCPU's chunk of memory can be
	 * naturally aligned with respect to the size of the backing store.
	 */
	alignment = max_t(
		size_t, SZ_2M,
		max_t(size_t,
		      get_backing_src_pagesz(test_params.shared_mem_src_type),
		      get_private_mem_backing_src_pagesz(test_params.private_mem_src_type)));

	per_cpu_size = align_up(PER_CPU_DATA_SIZE, alignment);
	memfd_size = per_cpu_size * test_params.nr_vcpus;

	switch (test_params.vm_type) {
	case KVM_X86_SW_PROTECTED_VM:
		vm = test_vm_setup(per_cpu_size, vcpus, &memfd);
		break;
	case KVM_X86_TDX_VM:
		vm = test_td_setup(per_cpu_size, vcpus, &memfd);
		break;
	default:
		TEST_FAIL("Unknown vm type %d.", test_params.vm_type);
	}

	for (i = 0; i < test_params.nr_vcpus; i++) {
		thread_args[i].vcpu = vcpus[i];
		thread_args[i].base_addr = BASE_DATA_GPA + i * per_cpu_size;

		pthread_create(&threads[i], NULL, __test_mem_conversions,
			       (void *)&thread_args[i]);
	}

	WRITE_ONCE(run_vcpus, true);

	for (i = 0; i < test_params.nr_vcpus; i++)
		pthread_join(threads[i], NULL);

	kvm_vm_free(vm);

	/*
	 * Allocate and free memory from the guest_memfd after closing the VM
	 * fd.  The guest_memfd is gifted a reference to its owning VM, i.e.
	 * should prevent the VM from being fully destroyed until the last
	 * reference to the guest_memfd is also put.
	 */
	r = fallocate(memfd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 0, memfd_size);
	TEST_ASSERT(!r, __KVM_SYSCALL_ERROR("fallocate()", r));

	r = fallocate(memfd, FALLOC_FL_KEEP_SIZE, 0, memfd_size);
	TEST_ASSERT(!r, __KVM_SYSCALL_ERROR("fallocate()", r));

	close(memfd);
}

static uint8_t parse_vm_type(const char *string)
{
	if (strcmp(string, "sw_protected") == 0)
		return KVM_X86_SW_PROTECTED_VM;
	else if (strcmp(string, "tdx") == 0)
		return KVM_X86_TDX_VM;
	else
		TEST_FAIL("Unknown vm type %s.", string);
}

static void usage(const char *cmd)
{
	puts("");
	printf("usage: %s [-h] [-g] [-m nr_memslots] [-s mem_type] [-p private_mem_type] [-n nr_vcpus]\n",
	       cmd);
	puts("");
	backing_src_help("-s");
	puts("");
	private_mem_backing_src_help("-p");
	puts("");
	puts(" -n: specify the number of vcpus (default: 1)");
	puts("");
	puts(" -m: specify the number of memslots (default: 1)");
	puts("");
	puts(" -g: back shared memory with guest_memfd (default: false)");
	puts("");
}

int main(int argc, char *argv[])
{
	int opt;

	test_params = (struct test_params){
		.private_mem_src_type = DEFAULT_VM_PRIVATE_MEM_SRC,
		.shared_mem_src_type = DEFAULT_VM_MEM_SRC,
		.back_shared_memory_with_guest_memfd = false,
		.nr_vcpus = 1,
		.nr_memslots = 1,
		.vm_type = KVM_X86_SW_PROTECTED_VM,
	};

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SW_PROTECTED_VM));

	while ((opt = getopt(argc, argv, "hgm:s:p:n:v:")) != -1) {
		switch (opt) {
		case 's':
			test_params.shared_mem_src_type = parse_backing_src_type(optarg);
			break;
		case 'p':
			test_params.private_mem_src_type = parse_private_mem_backing_src_type(optarg);
			break;
		case 'n':
			test_params.nr_vcpus = atoi_positive("nr_vcpus", optarg);
			break;
		case 'm':
			test_params.nr_memslots = atoi_positive("nr_memslots", optarg);
			break;
		case 'g':
			test_params.back_shared_memory_with_guest_memfd = true;
			break;
		case 'v':
			test_params.vm_type = parse_vm_type(optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(0);
		}
	}

	test_mem_conversions();

	return 0;
}
