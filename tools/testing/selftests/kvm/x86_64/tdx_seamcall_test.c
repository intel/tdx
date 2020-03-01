// SPDX-License-Identifier: GPL-2.0-only
/*
 * TDX_SEAMCALL_test
 *
 * Copyright (C) 2019, Intel.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * Author:
 *   Zhang Chen <chen.zhang@intel.com>
 *
 */
#include <linux/bits.h>
#include <linux/kvm.h>

#include <fcntl.h>
#include <limits.h>
#include <kvm_random.h>
#include <kvm_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <test_util.h>
#include <unistd.h>
#include <processor.h>

#include "tdx.h"

static void do_random_seamcalls(void)
{
	struct kvm_seamcall seamcall;
	int i;

	for (i = 0; i < 1000; i++) {
		/* Generate a valid(ish) leaf most of the time. */
		if (rand_bool_p(90))
			seamcall.in.rax = __rand_u8(64);
		else
			seamcall.in.rax = rand_u64();

		seamcall.in.rcx = rand_pa_or_u64();
		seamcall.in.rdx = rand_pa_or_u64();
		seamcall.in.r8  = rand_pa_or_u64();
		seamcall.in.r9  = rand_pa_or_u64();
		seamcall.in.r10 = rand_pa_or_u64();

		__seamcall(&seamcall);
		TEST_ASSERT(seamcall.out.rax,
			    "SEAMCALL[%llu](0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) succeeded",
			    seamcall.in.rax, seamcall.in.rcx, seamcall.in.rdx,
			    seamcall.in.r8,  seamcall.in.r9,  seamcall.in.r10);
	}
}

int main(int argc, char **argv)
{
	tdx_enable(argc, argv);

	do_random_seamcalls();

	tdx_disable();
	return 0;
}
