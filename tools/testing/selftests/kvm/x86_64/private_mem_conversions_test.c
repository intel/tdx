// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022, Google LLC.
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>
#include <linux/memfd.h>
#include <linux/sizes.h>

#include <test_util.h>
#include <kvm_util.h>
#include <processor.h>

#define BASE_DATA_SLOT		10
#define BASE_DATA_GPA		((uint64_t)(1ull << 32))
#define PER_CPU_DATA_SIZE	((uint64_t)(SZ_2M + PAGE_SIZE))

/* Horrific macro so that the line info is captured accurately :-( */
#define memcmp_g(gpa, pattern,  size)				\
do {								\
	uint8_t *mem = (uint8_t *)gpa;				\
	size_t i;						\
								\
	for (i = 0; i < size; i++)				\
		GUEST_ASSERT_4(mem[i] == pattern,		\
			       gpa, i, mem[i], pattern);	\
} while (0)

static void memcmp_h(uint8_t *mem, uint8_t pattern, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		TEST_ASSERT(mem[i] == pattern,
			    "Expected 0x%x at offset %lu, got 0x%x",
			    pattern, i, mem[i]);
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
	SYNC_SHARED,
	SYNC_PRIVATE,
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

static void guest_code(uint64_t base_gpa)
{
	struct {
		uint64_t offset;
		uint64_t size;
		uint8_t pattern;
	} stages[] = {
		GUEST_STAGE(0, PAGE_SIZE),
		GUEST_STAGE(0, SZ_2M),
		GUEST_STAGE(PAGE_SIZE, PAGE_SIZE),
		GUEST_STAGE(PAGE_SIZE, SZ_2M),
		GUEST_STAGE(SZ_2M, PAGE_SIZE),
	};
	const uint8_t init_p = 0xcc;
	uint64_t j;
	int i;

	/* Memory should be shared by default. */
	memset((void *)base_gpa, ~init_p, PER_CPU_DATA_SIZE);
	guest_sync_shared(base_gpa, PER_CPU_DATA_SIZE, (uint8_t)~init_p, init_p);
	memcmp_g(base_gpa, init_p, PER_CPU_DATA_SIZE);

	for (i = 0; i < ARRAY_SIZE(stages); i++) {
		uint64_t gpa = base_gpa + stages[i].offset;
		uint64_t size = stages[i].size;
		uint8_t p1 = 0x11;
		uint8_t p2 = 0x22;
		uint8_t p3 = 0x33;
		uint8_t p4 = 0x44;

		/*
		 * Set the test region to pattern one to differentiate it from
		 * the data range as a whole (contains the initial pattern).
		 */
		memset((void *)gpa, p1, size);

		/*
		 * Convert to private, set and verify the the private data, and
		 * then verify that the rest of the data (map shared) still
		 * holds the initial pattern, and that the host always sees the
		 * shared memory (initial pattern).  Unlike shared memory,
		 * punching a hole in private memory is destructive, i.e.
		 * previous values aren't guaranteed to be preserved.
		 */
		kvm_hypercall_map_private(gpa, size);
		memset((void *)gpa, p2, size);
		guest_sync_private(gpa, size, p1);

		/*
		 * Verify that the private memory was set to pattern two, and
		 * that shared memory still holds the initial pattern.
		 */
		memcmp_g(gpa, p2, size);
		if (gpa > base_gpa)
			memcmp_g(base_gpa, init_p, gpa - base_gpa);
		if (gpa + size < base_gpa + PER_CPU_DATA_SIZE)
			memcmp_g(gpa + size, init_p,
				 (base_gpa + PER_CPU_DATA_SIZE) - (gpa + size));

		/*
		 * Convert odd-number page frames back to shared to verify KVM
		 * also correctly handles holes in private ranges.
		 */
		for (j = 0; j < size; j += PAGE_SIZE) {
			if ((j >> PAGE_SHIFT) & 1) {
				kvm_hypercall_map_shared(gpa + j, PAGE_SIZE);
				guest_sync_shared(gpa + j, PAGE_SIZE, p1, p3);

				memcmp_g(gpa + j, p3, PAGE_SIZE);
			} else {
				guest_sync_private(gpa + j, PAGE_SIZE, p1);
			}
		}

		/*
		 * Convert the entire region back to shared, explicitly write
		 * pattern three to fill in the even-number frames before
		 * asking the host to verify (and write pattern four).
		 */
		kvm_hypercall_map_shared(gpa, size);
		memset((void *)gpa, p3, size);
		guest_sync_shared(gpa, size, p3, p4);
		memcmp_g(gpa, p4, size);

		/* Reset the shared memory back to the initial pattern. */
		memset((void *)gpa, init_p, size);
	}

	GUEST_DONE();
}

static void handle_exit_hypercall(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	uint64_t gpa = run->hypercall.args[0];
	uint64_t npages = run->hypercall.args[1];
	uint64_t attrs = run->hypercall.args[2];

	TEST_ASSERT(run->hypercall.nr == KVM_HC_MAP_GPA_RANGE,
		    "Wanted MAP_GPA_RANGE (%u), got '%llu'",
		    KVM_HC_MAP_GPA_RANGE, run->hypercall.nr);

	vm_mem_map_shared_or_private(vcpu->vm, gpa, npages * PAGE_SIZE,
				     !(attrs & KVM_MAP_GPA_RANGE_ENCRYPTED));

	run->hypercall.ret = 0;
}

static bool run_vcpus;

static void *__test_mem_conversions(void *__vcpu)
{
	struct kvm_vcpu *vcpu = __vcpu;
	struct kvm_run *run = vcpu->run;
	struct kvm_vm *vm = vcpu->vm;
	struct ucall uc;

	while (!READ_ONCE(run_vcpus))
		;

	for ( ;; ) {
		vcpu_run(vcpu);

		if (run->exit_reason == KVM_EXIT_HYPERCALL) {
			handle_exit_hypercall(vcpu);
			continue;
		}

		TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
			    "Wanted KVM_EXIT_IO, got exit reason: %u (%s)",
			    run->exit_reason, exit_reason_str(run->exit_reason));

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT_4(uc, "%lx %lx %lx %lx");
		case UCALL_SYNC: {
			uint8_t *hva = addr_gpa2hva(vm, uc.args[1]);
			uint64_t size = uc.args[2];

			TEST_ASSERT(uc.args[0] == SYNC_SHARED ||
				    uc.args[0] == SYNC_PRIVATE,
				    "Unknown sync command '%ld'", uc.args[0]);

			/* In all cases, the host should observe the shared data. */
			memcmp_h(hva, uc.args[3], size);

			/* For shared, write the new patter to guest memory. */
			if (uc.args[0] == SYNC_SHARED)
				memset(hva, uc.args[4], size);
			break;
		}
		case UCALL_DONE:
			return NULL;
		default:
			TEST_FAIL("Unknown ucall 0x%lx.", uc.cmd);
		}
	}
}

static void test_mem_conversions(enum vm_mem_backing_src_type src_type, uint32_t nr_vcpus,
				 uint32_t nr_memslots)
{
	/*
	 * Allocate enough memory so that each vCPU's chunk of memory can be
	 * naturally aligned with respect to the size of the backing store.
	 */
	const size_t size = align_up(PER_CPU_DATA_SIZE, get_backing_src_pagesz(src_type));
	const size_t memfd_size = size * nr_vcpus;
	struct kvm_vcpu *vcpus[KVM_MAX_VCPUS];
	pthread_t threads[KVM_MAX_VCPUS];
	struct kvm_vm *vm;
	int memfd, i, r;

	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = KVM_X86_PROTECTED_VM,
	};

	vm = __vm_create_with_vcpus(shape, nr_vcpus, 0, guest_code, vcpus);

	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL, (1 << KVM_HC_MAP_GPA_RANGE));

	memfd = vm_create_guest_memfd(vm, memfd_size, 0);
	for (i = 0; i < nr_memslots; i++)
		vm_mem_add(vm, src_type, BASE_DATA_GPA + size * i,
			   BASE_DATA_SLOT + i, size / vm->page_size,
			   KVM_MEM_PRIVATE, memfd, size * i);

	for (i = 0; i < nr_vcpus; i++) {
		uint64_t gpa =  BASE_DATA_GPA + i * size;

		vcpu_args_set(vcpus[i], 1, gpa);

		virt_map(vm, gpa, gpa, size / vm->page_size);

		pthread_create(&threads[i], NULL, __test_mem_conversions, vcpus[i]);
	}

	WRITE_ONCE(run_vcpus, true);

	for (i = 0; i < nr_vcpus; i++)
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
}

static void usage(const char *cmd)
{
	puts("");
	printf("usage: %s [-h] [-m] [-s mem_type] [-n nr_vcpus]\n", cmd);
	puts("");
	backing_src_help("-s");
	puts("");
	puts(" -n: specify the number of vcpus (default: 1)");
	puts("");
	puts(" -m: use multiple memslots (default: 1)");
	puts("");
}

int main(int argc, char *argv[])
{
	enum vm_mem_backing_src_type src_type = DEFAULT_VM_MEM_SRC;
	bool use_multiple_memslots = false;
	uint32_t nr_vcpus = 1;
	uint32_t nr_memslots;
	int opt;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_EXIT_HYPERCALL));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_PROTECTED_VM));

	while ((opt = getopt(argc, argv, "hms:n:")) != -1) {
		switch (opt) {
		case 's':
			src_type = parse_backing_src_type(optarg);
			break;
		case 'n':
			nr_vcpus = atoi_positive("nr_vcpus", optarg);
			break;
		case 'm':
			use_multiple_memslots = true;
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(0);
		}
	}

	nr_memslots = use_multiple_memslots ? nr_vcpus : 1;

	test_mem_conversions(src_type, nr_vcpus, nr_memslots);

	return 0;
}
