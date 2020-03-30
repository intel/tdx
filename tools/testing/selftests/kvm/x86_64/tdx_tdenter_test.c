// SPDX-License-Identifier: GPL-2.0-only
#include <fcntl.h>
#include <limits.h>
#include <kvm_util.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <test_util.h>
#include <unistd.h>
#include <processor.h>
#include <time.h>

#include "tdx.h"

/* Global to avoid stack overflow and lack of malloc() alignment. */
static struct test_td td;

int main(int argc, char **argv)
{
	struct kvm_tdenter tdenter;
	long ret;

	tdx_enable(argc, argv);

	tdx_create_td(&td);

	/* Call TDENTER ioctl*/
	memset(&tdenter, 0, sizeof(tdenter));
	tdenter.regs[0] = __pa(&td.tdvpr);

	ret = ioctl(kvm_fd, KVM_TDENTER, &tdenter);
	TEST_ASSERT(!ret, "KVM_TDENTER failed, ret: %ld, errno: %d", ret, errno);

	tdx_destroy_td(&td);

	tdx_disable();
	return 0;
}
