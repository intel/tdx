// SPDX-License-Identifier: GPL-2.0-only

#include <sys/syscall.h>
#include <unistd.h>

int memfd_restricted(unsigned int flags, int mount_fd)
{
	return syscall(__NR_memfd_restricted, flags, mount_fd);
}
