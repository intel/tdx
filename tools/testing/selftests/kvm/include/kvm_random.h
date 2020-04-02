/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_KVM_RANDOM_H
#define SELFTEST_KVM_RANDOM_H

#include <linux/bits.h>
#include <linux/types.h>

#include <stdlib.h>

#ifdef __x86_64__
extern u8 x86_phys_bits;
#endif

unsigned int parse_seed(int argc, char **argv);
void init_random(unsigned int seed);

static inline u8 __rand_u8(u8 mask)
{
	return (u8)rand() & mask;
}

static inline u8 rand_u8(void)
{
	return __rand_u8(0xff);
}

static inline u16 __rand_u16(u16 mask)
{
	return (u16)rand() & mask;
}

static inline u16 rand_u16(void)
{
	return __rand_u16(0xffff);
}

static inline u32 __rand_u32(u32 mask)
{
	return (u32)rand() & mask;
}

static inline u32 rand_u32(void)
{
	return __rand_u32(-1u);
}

static inline u64 __rand_u64(u64 mask)
{
	return (u64)rand() & mask;
}

static inline u64 rand_u64(void)
{
	return __rand_u64(-1ull);
}

#ifdef __x86_64__
static inline u64 rand_pa(void)
{
	return __rand_u64(GENMASK_ULL(x86_phys_bits - 1, 12));
}
#endif

static inline bool rand_bool(void)
{
	return rand_u32() < 0x80000000u;
}

static inline bool rand_bool_p(int percentage)
{
	if (percentage >= 100)
		return true;

	return rand_u32() < ((-1u / 100) * percentage);
}

static inline u64 rand_pa_or_u64(void)
{
#ifdef __x86_64__
	if (rand_bool())
		return rand_pa();
#endif
	return rand_u64();
}

#endif /* SELFTEST_KVM_RANDOM_H */
