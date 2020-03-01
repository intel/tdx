/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_KVM_TDX_H
#define SELFTEST_KVM_TDX_H

#include <linux/types.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif

#undef SEAMCALL_VERBOSE

#define PAGE_SIZE	4096

#include "../../../../../arch/x86/include/asm/tdx_arch.h"

extern struct tdsysinfo_struct sysinfo;
extern int kvm_fd;

struct td_page {
	char data[PAGE_SIZE];
} __aligned(PAGE_SIZE);

void tdx_enable(int argc, char **argv);
void tdx_disable(void);

static inline void __seamcall(struct kvm_seamcall *seamcall)
{
	long ret;

	memset(&seamcall->out, 0, sizeof(seamcall->out));

#ifdef SEAMCALL_VERBOSE
	printf("SEAMCALL[%llu] in = 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n",
	       seamcall->in.rax, seamcall->in.rcx, seamcall->in.rdx,
	       seamcall->in.r8, seamcall->in.r9, seamcall->in.r10);
#endif

	ret = ioctl(kvm_fd, KVM_SEAMCALL, seamcall);
	TEST_ASSERT(!ret, "KVM_SEAMCALL failed, ret: %ld, errno: %d", ret, errno);

#ifdef SEAMCALL_VERBOSE
	printf("SEAMCALL[%llu] out = 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n",
	       seamcall->in.rax, seamcall->out.rax, seamcall->out.rcx, seamcall->out.rdx,
	       seamcall->out.r8, seamcall->out.r9, seamcall->out.r10);
#endif
}

static inline u64 seamcall(u64 rax, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10)
{
	struct kvm_seamcall seamcall;

	seamcall.in.rax = rax;
	seamcall.in.rcx = rcx;
	seamcall.in.rdx = rdx;
	seamcall.in.r8  = r8;
	seamcall.in.r9  = r9;
	seamcall.in.r10 = r10;

	__seamcall(&seamcall);

	return seamcall.out.rax;
}

#define seamcall5(op, rcx, rdx, r8, r9)						\
({										\
	u64 err = seamcall(SEAMCALL_##op, rcx, rdx, r8, r9, rand_u64());	\
										\
	TEST_ASSERT(!err, "SEAMCALL[" #op "] failed, error code: 0x%lx", err);	\
})

#define seamcall4(op, rcx, rdx, r8) seamcall5(op, (rcx), (rdx), (r8), rand_u64())
#define seamcall3(op, rcx, rdx)     seamcall4(op, (rcx), (rdx), rand_u64())
#define seamcall2(op, rcx)	    seamcall3(op, (rcx), rand_u64())
#define seamcall1(op)		    seamcall2(op, rand_u64())

static inline u64 __pa(void *va)
{
	struct kvm_va_to_pa addr;
	long ret;

	addr.va = (u64)va;

	ret = ioctl(kvm_fd, KVM_TRANSLATE_VA_TO_PA, &addr);
	TEST_ASSERT(!ret, "VA_TO_PA failed, ret: %ld, errno: %d", ret, errno);
	return addr.pa;
}

#endif /* SELFTEST_KVM_TDX_H */
