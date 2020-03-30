// SPDX-License-Identifier: GPL-2.0-only
/*
 * TDX_load_SEAM_test
 *
 * Copyright (C) 2019, Intel.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * Author:
 *   Zhang Chen <chen.zhang@intel.com>
 *
 */

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

void intel_seam_load_test(char *path)
{
	int ret, fd;

	fd = open(KVM_DEV_PATH, O_RDWR);
	TEST_ASSERT(fd >= 0, "failed to open /dev/kvm fd: %i errno: %i",
		    fd, errno);

	ret = ioctl(fd, KVM_LOAD_SEAM, path);
	TEST_ASSERT(!ret, "KVM_LOAD_SEAM failed ret: %i errno: %i",
		    ret, errno);

	close(fd);
}

int main(int argc, char **argv)
{
	char path[PATH_MAX];

	TEST_ASSERT(argc == 2, "Must specify path to SEAM module");

	strncpy(path, argv[1], PATH_MAX);

	intel_seam_load_test(path);

	return 0;
}
