// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bits.h>
#include <linux/kvm.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <test_util.h>
#include <unistd.h>

#ifdef __x86_64__
#include <processor.h>

u8 x86_phys_bits;

static inline unsigned int cpuid_eax(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return eax;
}
#endif

unsigned int parse_seed(int argc, char **argv)
{
	unsigned int seed;
	char *tmp = NULL;
	int c;

	c = getopt(argc, argv, "s:");
	if (c == -1)
		return 0;

	TEST_ASSERT(c == 's', "Unknown option '%c'", c);

	seed = (unsigned int)strtoul(optarg, &tmp, 0);
	TEST_ASSERT(*tmp == '\0' && tmp != optarg,
		    "Unabled to parse seed '%s'\n", optarg);

	return seed;
}

void init_random(unsigned int seed)
{
	int fd, ret;

#ifdef __x86_64__
	x86_phys_bits = cpuid_eax(0x80000008) & 0xff;
#endif
	if (seed)
		goto init_srand;

	fd = open("/dev/urandom", O_RDONLY);
	TEST_ASSERT(fd >= 0, "failed to open /dev/urandom, kvm_fd: %i errno: %i",
		    fd, errno);

	ret = read(fd, &seed, sizeof(seed));
	TEST_ASSERT(ret == sizeof(seed),
		    "failed read() on /dev/urandom, ret: %i errno: %i",
		    ret, errno);
	close(fd);

init_srand:
	printf("KVM random seed: %u\n", seed);
	srand(seed);
}
