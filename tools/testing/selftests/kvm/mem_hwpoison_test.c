// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022, Google LLC.
 * Copyright (C) 2023, Intel Corp.
 */
#define _GNU_SOURCE /* for program_invocation_short_name */

#include <pthread.h>
#include <signal.h>
#include <setjmp.h>

#include <linux/fadvise.h>
#include <linux/sizes.h>

#include <processor.h>

#define DATA_SLOT	10
#define DATA_GPA	((uint64_t)(1ull << 32))
#define DATA_SIZE	((uint64_t)(SZ_2M))

enum ucall_syncs {
	/* Give kvm a chance to inject mce */
	GUEST_NOP,
	GUEST_HWPOISON,
};

static void guest_sync_nop(void)
{
	ucall(UCALL_SYNC, 1, GUEST_NOP);
}

static void guest_sync_hwpoison(uint64_t gpa)
{
	ucall(UCALL_SYNC, 2, GUEST_HWPOISON, gpa);
}

static void memcmp_g(const char *file, unsigned int line, uint64_t gpa,
		     uint8_t pattern, uint64_t size)
{
	uint8_t *mem = (uint8_t *)gpa;
	size_t i;

	for (i = 0; i < size; i++) {
		if (mem[i] == pattern)
			continue;

		ucall_assert(UCALL_ABORT, "mem[i] == pattern",
			     file, line,
			     "Expected 0x%x at offset %lu (gpa 0x%lx), got 0x%x",
			     pattern, i, gpa + i, mem[i]);
	}
}
#define MEMCMP_G(gpa, pattern, size)				\
	memcmp_g(__FILE__, __LINE__, (gpa), (pattern), (size))

static const uint64_t test_offsets[] = {
	0,
	PAGE_SIZE,
};

static void guest_code(uint64_t gpa, bool huge_page, bool do_wait)
{
	const uint8_t init_p = 0xcc;
	uint64_t r;
	int i;

	for (i = 0; i < ARRAY_SIZE(test_offsets); i++) {
		uint64_t offset = test_offsets[i];
		uint64_t base = gpa + offset;

		/*
		 * Set the test region to non-zero to differentiate it from the
		 * page newly assigned.
		 */
		memset((void *)gpa, init_p, SZ_2M);
		if (do_wait)
			/* Hold mce injector. */
			WRITE_ONCE(*(uint8_t *)gpa, 0);

		/* Ask VMM to poison the page. */
		guest_sync_hwpoison(base);

		if (do_wait) {
			/* Allow mce injector to continue. */
			WRITE_ONCE(*(uint8_t *)gpa, init_p);

			/* Wait for poisoned page zeroed. */
			while (READ_ONCE(*(uint8_t *)base) == init_p)
				;
		}

		/* When injecting mce, give KVM a chance to inject it. */
		guest_sync_nop();

		/* Consume poisoned data. */
		r = READ_ONCE(*(uint64_t *)base);
		/* VMM discarded the poisoned page and assign a new page. */
		GUEST_ASSERT_EQ(r, 0);

		/* Check if the page is zeroed or it keeps its contents. */
		if (huge_page) {
			MEMCMP_G(gpa, 0, SZ_2M);
		} else {
			if (offset > 0)
				MEMCMP_G(gpa, init_p, offset);
			MEMCMP_G(base, 0, PAGE_SIZE);
			if (offset + PAGE_SIZE < SZ_2M)
				MEMCMP_G(gpa + offset + PAGE_SIZE, init_p,
					 SZ_2M - (offset + PAGE_SIZE));
		}
	}

	GUEST_DONE();
}

#define MCE_INJECT_DIR		"/sys/kernel/debug/mce-inject/"
#define MCE_STATUS		MCE_INJECT_DIR"status"
#define MCE_MISC		MCE_INJECT_DIR"misc"
#define MCE_BANK		MCE_INJECT_DIR"bank"
#define MCE_FLAGS		MCE_INJECT_DIR"flags"
#define MCE_MCGSTATUS		MCE_INJECT_DIR"mcgstatus"
#define MCE_NOTRIGGER		MCE_INJECT_DIR"notrigger"

static void write_buf(const char *path, const char *buf, size_t size)
{
	ssize_t r;
	int fd;

	fd = open(path, O_WRONLY);
	TEST_ASSERT(fd >= 0, "failed to open %s\n", path);

	r = write(fd, buf, size);
	TEST_ASSERT(r == size, "failed to write(%s:%s:%zd) = %zd\n",
		    path, buf, size, r);

	close(fd);
}

static void mce_write(const char *path, uint64_t val)
{
	char buf[64];
	int len;

	len = sprintf(buf, "%"PRIu64"\n", val);
	write_buf(path, buf, len);
}

static void mce_flags(void)
{
	char *buf = "sw\n";

	write_buf(MCE_FLAGS, buf, strlen(buf));
}

/* From asm/mce.h */
/* MCG_STATUS register defines */
#define MCG_STATUS_EIPV		BIT_ULL(1)   /* ip points to correct instruction */
#define MCG_STATUS_MCIP		BIT_ULL(2)   /* machine check in progress */
#define MCG_STATUS_LMCES	BIT_ULL(3)   /* LMCE signaled */

/* MCi_STATUS register defines */
#define MCI_STATUS_VAL		BIT_ULL(63)  /* valid error */
#define MCI_STATUS_UC		BIT_ULL(61)  /* uncorrected error */
#define MCI_STATUS_EN		BIT_ULL(60)  /* error enabled */
#define MCI_STATUS_MISCV	BIT_ULL(59)  /* misc error reg. valid */
#define MCI_STATUS_ADDRV	BIT_ULL(58)  /* addr reg. valid */
#define MCI_STATUS_AR		BIT_ULL(55)  /* Action required */
#define MCI_STATUS_S		BIT_ULL(56)  /* Signaled machine check */

#define MCACOD_DATA		0x0134		/* Data Load */

/* MCi_MISC register defines */
#define MCI_MISC_ADDR_MODE_SHIFT	6
#define  MCI_MISC_ADDR_PHYS		2

#define KVM_MCE_INJECT	"/sys/kernel/debug/kvm/%d-%d/vcpu%d/mce-inject"

/* Worst case buffer size needed for holding an integer. */
#define ITOA_MAX_LEN 12

static void vcpu_inject_mce(struct kvm_vcpu *vcpu)
{
	char path[sizeof(KVM_MCE_INJECT) + ITOA_MAX_LEN * 3 + 1];
	char data[] = "0";
	ssize_t r;
	int fd;

	snprintf(path, sizeof(path), KVM_MCE_INJECT,
		 getpid(), vcpu->vm->fd, vcpu->id);

	fd = open(path, O_WRONLY);
	TEST_ASSERT(fd >= 0, "failed to open %s\n", path);

	data[0] = '0';
	r = write(fd, data, sizeof(data));
	TEST_ASSERT(r == -1 && errno == EINVAL,
		    "succeeded to write(%s:%s:%zd) = %zd\n",
		    path, data, sizeof(data), r);

	data[0] = '1';
	r = write(fd, data, sizeof(data));
	TEST_ASSERT(r == sizeof(data),
		    "failed to write(%s:%s:%zd) = %zd\n",
		    path, data, sizeof(data), r);

	close(fd);
}

static void inject_mce(struct kvm_vcpu *vcpu, int memfd, uint64_t gpa)
{
	/* See vm_mem_add() in test_mem_failure() */
	uint64_t offset = gpa - DATA_GPA;
	int ret;

	/* mce-inject in debugfs triggers mce injection. */
	mce_write(MCE_NOTRIGGER, 1);

	/* FIXME: These values are vendor specific. */
	mce_write(MCE_MCGSTATUS,
		  MCG_STATUS_EIPV | MCG_STATUS_MCIP | MCG_STATUS_LMCES);
	mce_write(MCE_MISC,
		  (MCI_MISC_ADDR_PHYS << MCI_MISC_ADDR_MODE_SHIFT) | 3);
	/*
	 * MCI_STATUS_UC: Uncorrected error:
	 * MCI_STATUS_EN | MCI_STATUS_AR | MCI_STATUS_S:
	 *   SRAR: Software Recoverable Action Required
	 */
	mce_write(MCE_STATUS,
		  MCACOD_DATA |
		  MCI_STATUS_EN | MCI_STATUS_UC | MCI_STATUS_S | MCI_STATUS_AR |
		  MCI_STATUS_VAL | MCI_STATUS_MISCV | MCI_STATUS_ADDRV);
	mce_flags();
	mce_write(MCE_BANK, 0);

	/* Set physical address to MCE_ADDR. */
	ret = posix_fadvise(memfd, offset, sizeof(u64), FADV_MCE_INJECT);
	/* posix_fadvise() doesn't set errno, but returns erorr no. */
	if (ret)
		errno = ret;
	__TEST_REQUIRE(ret != EPERM,
		       "Injecting mcet requires CAP_SYS_ADMIN ret %d", ret);
	TEST_ASSERT(!ret || ret == EBUSY,
		    "posix_fadvise(FADV_MCE_INJECT) should success ret %d", ret);

	/* Schedule to fire MCE on the next vcpu run. */
	vcpu_inject_mce(vcpu);
}

static sigjmp_buf sigbuf;
static volatile void *fault_addr;

static void sigbus_handler(int sig, siginfo_t *info, void *data)
{
	int lsb = info->si_addr_lsb;

	TEST_ASSERT(info->si_signo == SIGBUS,
		    "Unknown signal number expected %d received %d\n",
		    SIGBUS, info->si_signo);
	TEST_ASSERT(info->si_code == BUS_MCEERR_AR,
		    "Unknown signal code received expected %d code %d\n",
		    BUS_MCEERR_AR, info->si_code);
	TEST_ASSERT((info->si_addr_lsb == PAGE_SHIFT ||
		     info->si_addr_lsb == HUGEPAGE_SHIFT(2)),
		    "Unknown signal addr_lsb expected lsb %d or %d received %d\n",
		    PAGE_SHIFT, HUGEPAGE_SHIFT(2), info->si_addr_lsb);
	TEST_ASSERT(((intptr_t)info->si_addr >> lsb) == ((intptr_t)fault_addr >> lsb),
		    "Unknown signal addr expected %p received %p lsb %d\n",
		    fault_addr, info->si_addr, lsb);

	fault_addr = NULL;
	siglongjmp(sigbuf, 1);
}

static void sigbus_handler_set(bool set)
{
	struct sigaction sa;
	int r;

	if (set)
		sa = (struct sigaction) {
			.sa_sigaction = sigbus_handler,
			.sa_flags = SA_SIGINFO,
		};
	else
		sa = (struct sigaction) {
			.sa_handler = SIG_DFL,
		};

	r = sigaction(SIGBUS, &sa, NULL);
	TEST_ASSERT(!r, "sigaction should success");
}

static void discard_nop(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	struct ucall uc;
	uint64_t cmd;

	vcpu_run(vcpu);
	TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
		    "Wanted KVM_EXIT_IO, got exit reason: %u (%s)",
		    run->exit_reason, exit_reason_str(run->exit_reason));
	cmd = get_ucall(vcpu, &uc);
	TEST_ASSERT(cmd == UCALL_SYNC, "UCALL_SYNC is expected %lu", cmd);
	TEST_ASSERT(uc.args[0] == GUEST_NOP, "GUEST_NOP is expected %lu",
		    uc.args[0]);
}

static void test_madvise(struct kvm_vcpu *vcpu, int memfd, bool huge_page,
			 uint64_t gpa)
{
	uint8_t *hva = addr_gpa2hva(vcpu->vm, gpa);
	int r;

	discard_nop(vcpu);
	r = madvise(hva, sizeof(u64), MADV_HWPOISON);
	__TEST_REQUIRE(!(r == -1 && errno == EPERM),
		       "madvise(MADV_HWPOISON) requires CAP_SYS_ADMIN");
	TEST_ASSERT(!r, "madvise(MADV_HWPOISON) should succeed");

	if (!sigsetjmp(sigbuf, 1)) {
		sigbus_handler_set(true);

		/* Trigger SIGBUS */
		fault_addr = hva;
		vcpu_run(vcpu);
		TEST_FAIL("SIGBUS isn't triggered");
	}

	/*
	 * Discard poisoned page and add a new page so that guest vcpu
	 * can continue.
	 */
	if (huge_page) {
		void *v;

		/*
		 * madvise(MADV_FREE) doesn't work for huge page.
		 * Resort to munmap() and mmap().
		 */
		gpa = align_down(gpa, SZ_2M);
		hva = addr_gpa2hva(vcpu->vm, gpa);

		r = munmap(hva, SZ_2M);
		TEST_ASSERT(!r, "munmap() should succeed");

		/* Map it again with new page for guest to continue. */
		v = mmap(hva, SZ_2M, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
			 memfd, gpa - DATA_GPA);
		TEST_ASSERT(v != MAP_FAILED,
			    __KVM_SYSCALL_ERROR("mmap()",
						(int)(unsigned long)MAP_FAILED));
		TEST_ASSERT(v == hva, "mmap(MAP_FIXED) v %p hva %p",
			    v, hva);
	} else {
		fault_addr = hva;
		r = madvise(hva, PAGE_SIZE, MADV_FREE);
		TEST_ASSERT(!r, "madvise(MADV_FREE) should success");
	}

	sigbus_handler_set(false);
}

static void punch_hole(struct kvm_vcpu *vcpu, int memfd, uint64_t gpa, uint64_t len)
{
	int r;

	/* Discard poisoned page. */
	r = fallocate(memfd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
		      gpa - DATA_GPA, len);
	TEST_ASSERT(!r || (r == -1 && errno == ENOENT),
		    "fallocate(PUNCH_HOLE, PAGE_SIZE) failed at fd = %d, offset = %lx\n",
		    memfd, gpa - DATA_GPA);
}

static void punch_hole_page(struct kvm_vcpu *vcpu, int memfd, bool huge_page,
			 uint64_t gpa)
{
	/* Discard the poisoned page and assign new page. */
	if (huge_page) {
		gpa = align_down(gpa, SZ_2M);
		punch_hole(vcpu, memfd, gpa, SZ_2M);
	} else
		punch_hole(vcpu, memfd, gpa, PAGE_SIZE);
}

static void munmap_hole(struct kvm_vcpu *vcpu, int memfd, uint64_t gpa,
			uint64_t len)
{
	uint8_t *hva = addr_gpa2hva(vcpu->vm, gpa);
	void *v;
	int r;

	/* hwpoison is also recorded in the PTE entry. Clear it. */
	r = munmap(hva, len);
	TEST_ASSERT(!r, "munmap() should succeed");

	/* Map it again with new page for guest to continue. */
	v = mmap(hva, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
		 memfd, gpa - DATA_GPA);
	TEST_ASSERT(v != MAP_FAILED,
		    __KVM_SYSCALL_ERROR("mmap()", (int)(unsigned long)MAP_FAILED));
	TEST_ASSERT(v == hva,
		    "mmap(MAP_FIXED) v %p hva %p", v, hva);
}

static void munmap_page(struct kvm_vcpu *vcpu, int memfd, bool huge_page,
				uint64_t gpa)
{
	if (huge_page) {
		gpa = align_down(gpa, SZ_2M);
		munmap_hole(vcpu, memfd, gpa, SZ_2M);
	} else
		munmap_hole(vcpu, memfd, gpa, PAGE_SIZE);
}

static void test_fadvise(struct kvm_vcpu *vcpu, int memfd, bool huge_page,
			 uint64_t gpa)
{
	/* See vm_mem_add() in test_mem_failure() */
	uint64_t offset = gpa - DATA_GPA;
	int ret;

	discard_nop(vcpu);
	ret = posix_fadvise(memfd, offset, sizeof(u64), FADV_HWPOISON);
	/* posix_fadvise() doesn't set errno, but returns erorr no. */
	if (ret)
		errno = ret;
	__TEST_REQUIRE(ret != EPERM,
		       "Injecting memory fault requires CAP_SYS_ADMIN ret %d",
		       ret);
	TEST_ASSERT(!ret || ret == EBUSY,
		    "posix_fadvise(FADV_HWPOISON) should success ret %d", ret);

	sigbus_handler_set(true);
	if (!sigsetjmp(sigbuf, 1)) {
		/* Trigger SIGBUS */
		fault_addr = addr_gpa2hva(vcpu->vm, gpa);
		vcpu_run(vcpu);
		TEST_FAIL("SIGBUS isn't triggered");
	}

	punch_hole_page(vcpu, memfd, huge_page, gpa);
	if (!huge_page && !sigsetjmp(sigbuf, 1)) {
		fault_addr = addr_gpa2hva(vcpu->vm, gpa);
		vcpu_run(vcpu);
		TEST_FAIL("SIGBUS isn't triggered");
	}
	munmap_page(vcpu, memfd, huge_page, gpa);
	sigbus_handler_set(false);
}

static void test_mce(struct kvm_vcpu *vcpu, int memfd, bool huge_page,
		     uint64_t gpa)
{
	inject_mce(vcpu, memfd, gpa);

	sigbus_handler_set(true);
	if (!sigsetjmp(sigbuf, 1)) {
		/* Give KVM a chance to inject MCE and trigger SIGBUS. */
		fault_addr = addr_gpa2hva(vcpu->vm, gpa);
		discard_nop(vcpu);

		/* As the mce framework uses work queue, give it time. */
		sleep(1);
		TEST_FAIL("SIGBUS isn't triggered");
	}

	if (!sigsetjmp(sigbuf, 1)) {
		/* Trigger SIGBUS */
		fault_addr = addr_gpa2hva(vcpu->vm, gpa);
		vcpu_run(vcpu);
		TEST_FAIL("SIGBUS isn't triggered");
	}

	punch_hole_page(vcpu, memfd, huge_page, gpa);
	if (!huge_page && !sigsetjmp(sigbuf, 1)) {
		fault_addr = addr_gpa2hva(vcpu->vm, gpa);
		vcpu_run(vcpu);
		TEST_FAIL("SIGBUS isn't triggered");
	}
	munmap_page(vcpu, memfd, huge_page, gpa);
	sigbus_handler_set(false);
}

struct inject_mce_args {
	struct kvm_vcpu *vcpu;
	uint64_t gpa;
	int memfd;
};

static void *inject_mce_remote(void *args_)
{
	struct inject_mce_args *args = args_;
	struct kvm_vcpu *vcpu = args->vcpu;
	uint8_t *hva = addr_gpa2hva(vcpu->vm, DATA_GPA);

	/* Wait for vcpu running */
	while (!READ_ONCE(*hva))
		;

	inject_mce(vcpu, args->memfd, args->gpa);
	return NULL;
}

static void test_mce_remote(struct kvm_vcpu *vcpu, int memfd, bool huge_page,
			    uint64_t gpa)
{
	uint64_t *hva = addr_gpa2hva(vcpu->vm, gpa);
	struct inject_mce_args args = {
		.memfd = memfd,
		.vcpu = vcpu,
		.gpa = gpa,
	};
	pthread_t thread;

	/* Make another thread inject mce while vcpu running. */
	fault_addr = hva;
	pthread_create(&thread, NULL, inject_mce_remote, &args);

	sigbus_handler_set(true);
	if (!sigsetjmp(sigbuf, 1)) {
		vcpu_run(vcpu);
		TEST_FAIL("SIGBUS isn't triggered");
	}
	pthread_join(thread, NULL);

	punch_hole_page(vcpu, memfd, huge_page, gpa);
	if (!huge_page && !sigsetjmp(sigbuf, 1)) {
		fault_addr = hva;
		vcpu_run(vcpu);
		TEST_FAIL("SIGBUS isn't triggered");
	}

	munmap_page(vcpu, memfd, huge_page, gpa);
	sigbus_handler_set(false);
	discard_nop(vcpu);
}

/* How to inject failure */
enum failure_injection {
	INJECT_MADVISE,
	INJECT_FADVISE,
	INJECT_MCE,
	INJECT_MCE_REMOTE,
};

struct test_args {
	struct kvm_vcpu *vcpu;
	enum failure_injection how;
	bool huge_page;
	int memfd;
};

static void *__test_mem_failure(void *args_)
{
	struct test_args *args = args_;
	enum failure_injection how = args->how;
	struct kvm_vcpu *vcpu = args->vcpu;
	bool huge_page = args->huge_page;
	struct kvm_run *run = vcpu->run;
	int memfd = args->memfd;
	struct ucall uc;

	for ( ;; ) {
		vcpu_run(vcpu);

		TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
			    "Wanted KVM_EXIT_IO, got exit reason: %u (%s)",
			    run->exit_reason, exit_reason_str(run->exit_reason));

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			break;
		case UCALL_SYNC: {
			uint64_t gpa = uc.args[1];

			if (uc.args[0] == GUEST_NOP)
				break;

			TEST_ASSERT(uc.args[0] == GUEST_HWPOISON,
				    "Unknown sync command '%ld'", uc.args[0]);

			switch (how) {
			case INJECT_MADVISE:
				test_madvise(vcpu, memfd, huge_page, gpa);
				break;
			case INJECT_FADVISE:
				test_fadvise(vcpu, memfd, huge_page, gpa);
				break;
			case INJECT_MCE:
				test_mce(vcpu, memfd, huge_page, gpa);
				break;
			case INJECT_MCE_REMOTE:
				test_mce_remote(vcpu, memfd, huge_page, gpa);
				break;
			default:
				TEST_FAIL("Unknown sync ucall %lu", uc.args[0]);
				break;
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

static void test_mem_failure(enum failure_injection how, bool huge_page)
{
	enum vm_mem_backing_src_type src_type;
	struct userspace_mem_region *region;
	struct test_args args;
	struct kvm_vcpu *vcpu;
	pthread_t thread;
	struct kvm_vm *vm;
	size_t size;
	int r;

	if (how == INJECT_MADVISE) {
		/* madvise(MADV_FREE) requires anonymous region. */
		if (huge_page)
			src_type = VM_MEM_SRC_ANONYMOUS_MEMFD_HUGETLB;
		else
			src_type = VM_MEM_SRC_ANONYMOUS_MEMFD;
	} else {
		/*
		 * Use memfd_create() for fadvise() because * fadvise() doesn't
		 * work on private anonymous page.
		 */
		if (huge_page)
			src_type = VM_MEM_SRC_SHARED_HUGETLB;
		else
			src_type = VM_MEM_SRC_SHMEM;
	}

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	/*
	 * When poisoning memory, the kernel searches mapped pages and inject
	 * sigbus with the virtual address.  Avoid alias mapping for
	 * deterministic result.
	 */
	size = align_up(DATA_SIZE, get_backing_src_pagesz(src_type));
	__vm_userspace_mem_region_add(vm, src_type, DATA_GPA, DATA_SLOT,
				      size / vm->page_size, 0, false);

	region = memslot2region(vm, DATA_SLOT);
	if (huge_page) {
		r = madvise(region->host_mem, size, MADV_HUGEPAGE);
		TEST_ASSERT(!r, "madvise(MADV_HUGEPAGE) should succeed");
	} else {
		r = madvise(region->host_mem, size, MADV_NOHUGEPAGE);
		TEST_ASSERT(!r, "madvise(MADV_NOHUGEPAGE) should succeed");
	}

	virt_map(vm, DATA_GPA, DATA_GPA, size / vm->page_size);
	vcpu_args_set(vcpu, 3, DATA_GPA, huge_page, how == INJECT_MCE_REMOTE);

	args = (struct test_args) {
		.vcpu = vcpu,
		.how = how,
		.huge_page = huge_page,
		.memfd = region->fd,
	};
	pthread_create(&thread, NULL, __test_mem_failure, &args);

	pthread_join(thread, NULL);
	kvm_vm_free(vm);
}

static void help(const char *prog_name)
{
	printf("usage: %s [-f] [-h] [-i] [-m] [-r] [-?]\n"
	       " -f: use fadvise for memory poison\n"
	       " -h: use huge page\n"
	       " -i: use mce injection\n"
	       " -m: use madvise for memory poison\n"
	       " -r: use mce injection remotely\n"
	       " -?: print this message\n",
	       prog_name);
}

int main(int argc, char *argv[])
{
	enum failure_injection how = INJECT_MADVISE;
	bool huge_page = false;
	int opt;

	while ((opt = getopt(argc, argv, "fhimr?")) != -1) {
		switch (opt) {
		case 'f':
			how = INJECT_FADVISE;
			break;
		case 'i':
			how = INJECT_MCE;
			break;
		case 'h':
			huge_page = true;
			break;
		case 'm':
			how = INJECT_MADVISE;
			break;
		case 'r':
			how = INJECT_MCE_REMOTE;
			break;
		case '?':
		default:
			help(argv[0]);
			exit(0);
		}
	}

	test_mem_failure(how, huge_page);

	return 0;
}
