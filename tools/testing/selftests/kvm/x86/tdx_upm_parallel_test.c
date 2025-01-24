// SPDX-License-Identifier: GPL-2.0-only

#include <asm/vmx.h>
#include <linux/kvm.h>
#include <linux/sizes.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <pthread.h>

#include "kvm_util.h"
#include "processor.h"
#include "tdx/tdcall.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"
#include "test_util.h"

#define TDX_UPM_TEST_ASSERT(x)				\
	do {						\
		if (!(x))				\
			tdx_test_fatal(__LINE__);	\
	} while (0)

#define TDX_UPM_TEST_ASSERT_WITH_DATA(x, data)				\
	do {								\
		if (!(x))						\
			tdx_test_fatal_with_data(__LINE__, (data));	\
	} while (0)

#define PATTERN_GUEST_GENERAL	0x5a

/*
 * 0x80000000 is arbitrarily selected. The selected address need not be the same
 * as TDX_UPM_TEST_AREA_GVA_PRIVATE, but it should not overlap with selftest
 * code or boot page.
 */
#define TDX_UPM_TEST_AREA_GPA			(0x80000000)
/* Test area GPA is arbitrarily selected */
#define TDX_UPM_TEST_AREA_GVA_PRIVATE		(0x90000000)
/* Select any bit that can be used as a flag */
#define TDX_UPM_TEST_AREA_GVA_SHARED_BIT	(32)
/*
 * TDX_UPM_TEST_AREA_GVA_SHARED is used to map the same GPA twice into the
 * guest, once as shared and once as private
 */
#define TDX_UPM_TEST_AREA_GVA_SHARED				\
	(TDX_UPM_TEST_AREA_GVA_PRIVATE |			\
		BIT_ULL(TDX_UPM_TEST_AREA_GVA_SHARED_BIT))

/* The test area is 2MB in size */
#define TDX_UPM_TEST_AREA_SIZE		SZ_2M

struct tdx_upm_test_area {
	uint8_t area[TDX_UPM_TEST_AREA_SIZE];
};

static pthread_barrier_t start_barrier;

static void start_barrier_wait(void)
{
	int ret;

	ret = pthread_barrier_wait(&start_barrier);
	TEST_ASSERT(!ret || ret == PTHREAD_BARRIER_SERIAL_THREAD, "barrier_wait");
}

/* Shared variables between guest and host */
static atomic_bool should_stop_test;

static void stop_test(struct kvm_vm *vm)
{
	should_stop_test = true;
	sync_global_to_guest(vm, should_stop_test);
}

/*
 * Because vCPU startup argument can't passed via GP registers.  Use global
 * variables shared between guest, host, and vcpuid as index.
 */
#define TDX_VCPU_MAX	256

struct guest_args {
	uint64_t gva;
	uint64_t size;

	bool shared_gpa;
	bool allow_mmio;
	bool disallow_accept;
};

static struct guest_args guest_args[TDX_VCPU_MAX];

static uint64_t guest_vcpu_id(void)
{
	uint32_t eax, ebx, ecx, edx;

	cpuid(1, &eax, &ebx, &ecx, &edx);
	return ebx >> 24;
}

static void my_memset(void *s, int c, size_t count)
{
	uint8_t *xs = s;

	while (count--) {
		/*
		 * Because we don't want to implement instruction decoder for
		 * simplicity, force 88 /r: MOV r/m8, r8: 2 bytes op code
		 * (or whatever op code with known length).
		 *
		 * *(uint8_t *)s = c;
		 */
		asm volatile ("movb %0, %1"
			      : : "q"((uint8_t)c), "m"(*(volatile uint8_t *)xs)
			      : "memory");

		xs++;
	}
}

static void guest_access(void)
{
	uint64_t idx, size, num_iterations;
	void *gva;

	idx = guest_vcpu_id();

	gva = (void *)guest_args[idx].gva;
	size = guest_args[idx].size;
	num_iterations = 0;

	while (!should_stop_test) {
		my_memset(gva, PATTERN_GUEST_GENERAL, size);

		num_iterations++;
		if (!(num_iterations % 1000))
			tdx_test_report_to_user_space(num_iterations);
	}

	tdx_test_success();
}

static void guest_ve_handler(struct ex_regs *regs)
{
	struct guest_args *args;
	uint64_t idx, ret;
	struct ve_info ve;

	idx = guest_vcpu_id();
	args = &guest_args[idx];

	ret = tdg_vp_veinfo_get(&ve);
	TDX_UPM_TEST_ASSERT(!ret);

	/* For this test, we will only handle EXIT_REASON_EPT_VIOLATION */
	TDX_UPM_TEST_ASSERT_WITH_DATA(ve.exit_reason == EXIT_REASON_EPT_VIOLATION,
				      ve.exit_reason);

	if (args->shared_gpa) {
		if (args->allow_mmio) {
			/* See my_memset(). It's 2 bytes op code.*/
			regs->rip += 2;
		}
		return;
	}

	if (args->disallow_accept)
		return;

#define MEM_PAGE_ACCEPT_LEVEL_4K 0
#define ALREADY_ACCEPTED_ERROR (TDCALL_ERROR_PAGE_ALREADY_ACCEPTED | MEM_PAGE_ACCEPT_LEVEL_4K)
	do {
		ret = tdg_mem_page_accept(ve.gpa, MEM_PAGE_ACCEPT_LEVEL_4K);
	} while ((ret & TDCALL_STATUS_MASK) == TDCALL_OPERAND_BUSY);

	TDX_UPM_TEST_ASSERT_WITH_DATA(!ret || ret == ALREADY_ACCEPTED_ERROR, ret);
}

static void vcpu_loop(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	start_barrier_wait();

	while (!should_stop_test) {
		td_vcpu_run(vcpu);

		if (vcpu->run->exit_reason == KVM_EXIT_SYSTEM_EVENT)
			TEST_FAIL("Guest reported error. vcpu 0x%x error code: %lld (0x%llx)\n",
				  vcpu->id,
				  vcpu->run->system_event.data[0] & ~0x8000000000000000,
				  vcpu->run->system_event.data[1]);

		if (vcpu->run->exit_reason == KVM_EXIT_IO &&
		    vcpu->run->io.port == TDX_TEST_REPORT_PORT &&
		    vcpu->run->io.size == TDX_TEST_REPORT_SIZE &&
		    vcpu->run->io.direction == KVM_EXIT_IO_OUT) {
			pr_debug("guest wrote %x data\n",
				 *(uint32_t *)((void *)vcpu->run + vcpu->run->io.data_offset));
			continue;
		}

		break;
	}
}

struct selftest_args {
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
};

static void *run_vcpu(void *args)
{
	struct kvm_vcpu *vcpu = ((struct selftest_args *)args)->vcpu;
	struct kvm_vm *vm = ((struct selftest_args *)args)->vm;

	vcpu_loop(vm, vcpu);

	return NULL;
}

struct host_args {
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	uint64_t gpa;
	uint64_t size;
	void *host_addr;
	bool to_private;

	uint32_t memslot;
};

static void host_check_iter(const char *fmt, uint32_t *num_iterations)
{
	(*num_iterations)++;
	if ((*num_iterations % 200) == 0)
		pr_debug(fmt, *num_iterations);
}

static void *punch_hole(void *args__)
{
	struct host_args *args = args__;
	struct kvm_vm *vm = args->vm;
	uint32_t num_iterations = 0;

	start_barrier_wait();

	while (!should_stop_test) {
		vm_guest_mem_punch_hole(vm, args->gpa, args->size);
		usleep(10000);

		host_check_iter("Punched hole %d times!", &num_iterations);
	}

	return NULL;
}

static void *change_attributes(void *args__)
{
	struct host_args *args = args__;
	uint32_t num_iterations = 0;
	uint64_t i;

	start_barrier_wait();

	while (!should_stop_test) {
		for (i = 0; i < args->size; i += PAGE_SIZE) {
			handle_memory_conversion(args->vm, args->gpa + i,
						 PAGE_SIZE, args->to_private);
		}
		usleep(10000);

		host_check_iter("change_attr %d times!", &num_iterations);
	}

	return NULL;
}

static void *madvise_dontneed(void *args__)
{
	struct host_args *args = args__;
	uint32_t num_iterations = 0;
	size_t i;
	int ret;

	start_barrier_wait();

	while (!should_stop_test) {
		for (i = 0; i < args->size; i += PAGE_SIZE) {
			ret = madvise(args->host_addr + i, PAGE_SIZE, MADV_DONTNEED);
			TEST_ASSERT(ret == 0,
				    "madvise(MADV_DONTNEED) failed, addr: %p length: 0x%lx",
				    args->host_addr, args->size);
		}
		usleep(10000);

		host_check_iter("madvise(REMOVE) hole %d times!", &num_iterations);
	}

	return NULL;
}

static void *memslot_add_remove(void *args__)
{
	struct host_args *args = args__;
	struct userspace_mem_region *region = memslot2region(args->vm, args->memslot);
	struct kvm_userspace_memory_region2 *r = &region->region;
	uint32_t num_iterations = 0;
	int ret;

	start_barrier_wait();

	while (!should_stop_test) {
		ret = __vm_set_user_memory_region2(args->vm, r->slot, r->flags,
						   r->guest_phys_addr, 0,
						   (void *)r->userspace_addr,
						   r->guest_memfd,
						   r->guest_memfd_offset);

		TEST_ASSERT(ret == 0, "deleting slot failed, slot: %d", r->slot);
		usleep(10000);

		ret = __vm_set_user_memory_region2(args->vm, r->slot, r->flags,
						   r->guest_phys_addr, r->memory_size,
						   (void *)r->userspace_addr,
						   r->guest_memfd,
						   r->guest_memfd_offset);
		TEST_ASSERT(ret == 0, "adding slot failed, slot: %d", r->slot);
		usleep(10000);

		host_check_iter("memslot add-remove %d times!", &num_iterations);
	}

	return NULL;
}

vm_vaddr_t vm_vaddr_alloc_private(struct kvm_vm *vm, size_t sz,
				  vm_vaddr_t vaddr_min, vm_paddr_t paddr_min,
				  enum kvm_mem_region_type type)
{
	return ____vm_vaddr_alloc(vm, sz, vaddr_min, paddr_min, type, true);
}

static struct kvm_vcpu *create_vcpu(struct kvm_vm *vm, uint32_t vcpu_id,
				    bool shared_gpa, bool allow_mmio,
				    bool disallow_accept)
{
	struct guest_args *args = &guest_args[vcpu_id];

	*args = (struct guest_args) {
		.gva = shared_gpa ? TDX_UPM_TEST_AREA_GVA_SHARED :
		TDX_UPM_TEST_AREA_GVA_PRIVATE,
		.size = sizeof(struct tdx_upm_test_area),

		.shared_gpa = shared_gpa,
		.allow_mmio = allow_mmio,
		.disallow_accept = disallow_accept,
	};

	return td_vcpu_add(vm, vcpu_id, guest_access);
}

struct guest_vcpu_config {
	bool shared_gpa;
	bool allow_mmio;
	bool disallow_accept;
};

struct guest_threads {
	int nr_threads;
	struct guest_vcpu_config *configs;

	pthread_t *threads;
	struct kvm_vcpu **vcpus;
	struct selftest_args *args;
};

static void guest_thread_allocate(int nr_guest_vcpus,
				  struct guest_vcpu_config *configs,
				  struct guest_threads *guest_threads)
{
	guest_threads->nr_threads = nr_guest_vcpus;
	guest_threads->configs = configs;

	guest_threads->threads = malloc(nr_guest_vcpus * sizeof(*guest_threads->threads));
	TEST_ASSERT(guest_threads->threads, "Allocate memory for guest threads");

	guest_threads->vcpus = malloc(nr_guest_vcpus * sizeof(*guest_threads->vcpus));
	TEST_ASSERT(guest_threads->vcpus, "Allocate memory for guest vcpus");

	guest_threads->args = malloc(nr_guest_vcpus * sizeof(*guest_threads->args));
	TEST_ASSERT(guest_threads->args, "Allocate memory for guest args");
}

static void guest_thread_free(struct guest_threads *guest_threads)
{
	free(guest_threads->threads);
	free(guest_threads->vcpus);
	free(guest_threads->args);
}

static void guest_thread_create_vcpus(struct kvm_vm *vm,
				      struct guest_threads *guest_threads)
{
	struct guest_vcpu_config *c = guest_threads->configs;
	int i, vcpu_id = 0;

	for (i = 0; i < guest_threads->nr_threads; i++) {
		guest_threads->vcpus[i] = create_vcpu(vm, vcpu_id,
						      c[i].shared_gpa,
						      c[i].allow_mmio,
						      c[i].disallow_accept);
		guest_threads->args[i] = (struct selftest_args) {
			.vm = vm,
			.vcpu = guest_threads->vcpus[i],
		};

		vcpu_id++;
	}
}

static void guest_thread_create(struct kvm_vm *vm,
				struct guest_threads *guest_threads)
{
	int i, ret;

	for (i = 0; i < guest_threads->nr_threads; i++) {
		ret = pthread_create(&guest_threads->threads[i], NULL, run_vcpu,
				     &guest_threads->args[i]);
		TEST_ASSERT(!ret, "pthread_create(guest thread %d)", i);
	}
}

static void guest_thread_join(struct guest_threads *guest_threads)
{
	int i;

	for (i = 0; i < guest_threads->nr_threads; i++)
		pthread_join(guest_threads->threads[i], NULL);
}

enum host_thread_type {
	HOST_PUNCH_HOLE,
	HOST_CHANGE_ATTR_PRIVATE,
	HOST_CHANGE_ATTR_SHARED,
	HOST_MADVISE_DONTNEED,
	HOST_MEMSLOT_ADD_REMOVE,
	HOST_THREAD_TYPE_MAX,
};

typedef void *(*host_entry_t)(void *args__);

const host_entry_t host_entries[HOST_THREAD_TYPE_MAX] = {
	&punch_hole,
	&change_attributes,
	&change_attributes,
	&madvise_dontneed,
	&memslot_add_remove,
};

struct host_nr_threads {
	int nr_threads[HOST_THREAD_TYPE_MAX];
};

struct host_threads {
	int nr_threads;
	pthread_t *threads;

	struct host_args *args;
};

static void host_thread_allocate(const struct host_nr_threads *nr_threads,
				 struct host_threads *host_threads)
{
	int i;

	host_threads->nr_threads = 0;
	for (i = 0; i < HOST_THREAD_TYPE_MAX; i++)
		host_threads->nr_threads += nr_threads->nr_threads[i];

	host_threads->threads = malloc(host_threads->nr_threads * sizeof(*host_threads->threads));
	TEST_ASSERT(host_threads->threads, "Allocate memory for host threads");

	host_threads->args = malloc(host_threads->nr_threads * sizeof(*host_threads->args));
	TEST_ASSERT(host_threads->args, "Allocate memory for host args");
}

static void host_thread_free(struct host_threads *host_threads)
{
	free(host_threads->threads);
	free(host_threads->args);
}

static void host_thread_create(struct kvm_vm *vm, uint32_t slot,
			       struct host_nr_threads *host_nr_threads,
			       struct host_threads *host_threads)
{
	struct userspace_mem_region *region;
	enum host_thread_type ht_type;
	int ret, i, th;

	region = memslot2region(vm, slot);
	TEST_ASSERT(region, "memslot2region(slot=%d)", slot);

	th = 0;
	for (ht_type = 0; ht_type < HOST_THREAD_TYPE_MAX; ht_type++) {
		for (i = 0; i < host_nr_threads->nr_threads[ht_type]; i++) {
			struct host_args *args = &host_threads->args[th];

			*args = (struct host_args) {
				.vm = vm,
			};
			switch (ht_type) {
			case HOST_PUNCH_HOLE:
				args->gpa = TDX_UPM_TEST_AREA_GPA;
				args->size = TDX_UPM_TEST_AREA_SIZE;
				break;
			case HOST_CHANGE_ATTR_PRIVATE:
				args->gpa = TDX_UPM_TEST_AREA_GPA;
				args->size = TDX_UPM_TEST_AREA_SIZE;
				args->to_private = true;
				break;
			case HOST_CHANGE_ATTR_SHARED:
				args->gpa = TDX_UPM_TEST_AREA_GPA;
				args->size = TDX_UPM_TEST_AREA_SIZE;
				args->to_private = false;
				break;
			case HOST_MADVISE_DONTNEED:
				args->host_addr = region->host_mem;
				args->size = TDX_UPM_TEST_AREA_SIZE;
				break;
			case HOST_MEMSLOT_ADD_REMOVE:
				args->memslot = slot;
				break;
			case HOST_THREAD_TYPE_MAX:
			default:
				TEST_FAIL("unknown host thread type %d", ht_type);
				break;
			}

			ret = pthread_create(&host_threads->threads[th], NULL,
					     host_entries[ht_type], (void *)args);
			TEST_ASSERT(!ret, "pthread_create(host thread type %d)", ht_type);

			th++;
		}
	}
}

static void host_thread_join(struct host_threads *host_threads)
{
	int i, ret;

	for (i = 0; i < host_threads->nr_threads; i++) {
		ret = pthread_join(host_threads->threads[i], NULL);
		TEST_ASSERT(!ret, "pthread_join");
	}
}

static void __verify_upm_test(int nr_guest_vcpus, struct guest_vcpu_config *configs,
			      struct host_nr_threads *host_nr_threads,
			      unsigned int duration)
{
	struct tdx_upm_test_area *test_area_gpa_private;
	struct guest_threads guest_threads;
	struct host_threads host_threads;
	vm_vaddr_t test_area_gva_private;
	uint64_t test_area_npages;
	const uint32_t slot = 3;
	int nr_threads, ret;
	struct kvm_vm *vm;

	guest_thread_allocate(nr_guest_vcpus, configs, &guest_threads);
	host_thread_allocate(host_nr_threads, &host_threads);

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vm_install_exception_handler(vm, VE_VECTOR, guest_ve_handler);

	/*
	 * Set up shared memory page for testing by first allocating as private
	 * and then mapping the same GPA again as shared. This way, the TD does
	 * not have to remap its page tables at runtime.
	 */
	test_area_npages = TDX_UPM_TEST_AREA_SIZE / vm->page_size;
	vm_userspace_mem_region_add(vm,
				    VM_MEM_SRC_ANONYMOUS, TDX_UPM_TEST_AREA_GPA,
				    slot, test_area_npages, KVM_MEM_GUEST_MEMFD);
	vm->memslots[MEM_REGION_TEST_DATA] = slot;

	test_area_gva_private = vm_vaddr_alloc_private(vm, TDX_UPM_TEST_AREA_SIZE,
						       TDX_UPM_TEST_AREA_GVA_PRIVATE,
						       TDX_UPM_TEST_AREA_GPA,
						       MEM_REGION_TEST_DATA);
	TEST_ASSERT_EQ(test_area_gva_private, TDX_UPM_TEST_AREA_GVA_PRIVATE);

	test_area_gpa_private = (struct tdx_upm_test_area *)
		addr_gva2gpa(vm, test_area_gva_private);
	virt_map_shared(vm, TDX_UPM_TEST_AREA_GVA_SHARED,
			(uint64_t)test_area_gpa_private,
			test_area_npages);
	TEST_ASSERT_EQ(addr_gva2gpa(vm, TDX_UPM_TEST_AREA_GVA_SHARED),
		       (vm_paddr_t)test_area_gpa_private);

	guest_thread_create_vcpus(vm, &guest_threads);
	sync_global_to_guest(vm, guest_args);

	td_finalize(vm);

	nr_threads = guest_threads.nr_threads + host_threads.nr_threads + 1;
	ret = pthread_barrier_init(&start_barrier, NULL, nr_threads);
	guest_thread_create(vm, &guest_threads);
	host_thread_create(vm, slot, host_nr_threads, &host_threads);

	if (!duration)
		duration = ~duration;

	printf("Start testing for %u sec.\n", duration);

	start_barrier_wait();
	sleep(duration);
	stop_test(vm);

	guest_thread_join(&guest_threads);
	host_thread_join(&host_threads);

	guest_thread_free(&guest_threads);
	host_thread_free(&host_threads);

	kvm_vm_free(vm);
	ret = pthread_barrier_destroy(&start_barrier);
	TEST_ASSERT(!ret, "barrier_destroy");

	printf("\t ... PASSED\n");
}

static void verify_upm_test(unsigned int duration)
{
	struct guest_vcpu_config configs[] = {
		{
			.shared_gpa = false,
			.allow_mmio = false,
			.disallow_accept = false,
		},
		{
			.shared_gpa = false,
			.allow_mmio = false,
			.disallow_accept = false,
		},
		{
			.shared_gpa = false,
			.allow_mmio = false,
			.disallow_accept = true,
		},
		{
			.shared_gpa = false,
			.allow_mmio = false,
			.disallow_accept = true,
		},
		{
			.shared_gpa = true,
			.allow_mmio = false,
		},
		{
			.shared_gpa = true,
			.allow_mmio = false,
		},
		{
			.shared_gpa = true,
			.allow_mmio = true,
		},
		{
			.shared_gpa = true,
			.allow_mmio = true,
		},
	};

	struct host_nr_threads host_nr_threads[] = {
		{
			.nr_threads = {
				[HOST_PUNCH_HOLE] = 1,
				[HOST_MADVISE_DONTNEED] = 1,
			},
		},
		{
			.nr_threads = {
				[HOST_CHANGE_ATTR_PRIVATE] = 1,
				[HOST_CHANGE_ATTR_SHARED] = 1,
			},
		},
		{
			.nr_threads = {
				[HOST_MEMSLOT_ADD_REMOVE] = 1,
			},
		},
		{
			.nr_threads = {
				[HOST_PUNCH_HOLE] = 2,
				[HOST_CHANGE_ATTR_PRIVATE] = 2,
				[HOST_CHANGE_ATTR_SHARED] = 2,
				[HOST_MADVISE_DONTNEED] = 2,
				[HOST_MEMSLOT_ADD_REMOVE] = 1,
			},
		},
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(host_nr_threads); i++)
		__verify_upm_test(ARRAY_SIZE(configs), configs,
				  &host_nr_threads[i],
				  duration);
}

#define TEST_DURATION_DEFAULT	10

static void usage(const char *prog)
{
	printf("usage: %s [-h] [-d duration_in_sec]\n"
	       "-d: specify test to run in second (default %d sec)\n"
	       "-h: print this help\n", prog, TEST_DURATION_DEFAULT);
}

int main(int argc, char **argv)
{
	unsigned int duration = TEST_DURATION_DEFAULT, opt;

	/* Disable stdout buffering */
	setbuf(stdout, NULL);

	if (!is_tdx_enabled()) {
		printf("TDX is not supported by the KVM\n"
		       "Skipping the TDX tests.\n");
		return 0;
	}

	while ((opt = getopt(argc, argv, "d:h")) != -1) {
		switch (opt) {
		case 'd':
			duration = atoi_non_negative("test duration in sec", optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}

	verify_upm_test(duration);
}
