/* SPDX-License-Identifier: GPL-2.0-only */
/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 * ----------------------------------------------------------------------- */

/*
 * Very simple bitops for the boot code.
 */

#ifndef BOOT_BITOPS_H
#define BOOT_BITOPS_H
#define _LINUX_BITOPS_H		/* Inhibit inclusion of <linux/bitops.h> */

#include <linux/types.h>
#include <asm/asm.h>

static inline bool constant_test_bit(int nr, const void *addr)
{
	const u32 *p = (const u32 *)addr;
	return ((1UL << (nr & 31)) & (p[nr >> 5])) != 0;
}
static inline bool variable_test_bit(int nr, const void *addr)
{
	bool v;
	const u32 *p = (const u32 *)addr;

	asm("btl %2,%1" CC_SET(c) : CC_OUT(c) (v) : "m" (*p), "Ir" (nr));
	return v;
}

#define test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 constant_test_bit((nr),(addr)) : \
 variable_test_bit((nr),(addr)))

static inline void set_bit(int nr, void *addr)
{
	asm("btsl %1,%0" : "+m" (*(u32 *)addr) : "Ir" (nr));
}

static __always_inline void __set_bit(long nr, volatile unsigned long *addr)
{
	asm volatile(__ASM_SIZE(bts) " %1,%0" : : "m" (*(volatile long *) addr),
		     "Ir" (nr) : "memory");
}

static __always_inline void __clear_bit(long nr, volatile unsigned long *addr)
{
	asm volatile(__ASM_SIZE(btr) " %1,%0" : : "m" (*(volatile long *) addr),
		     "Ir" (nr) : "memory");
}

/**
 * __ffs - find first set bit in word
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static __always_inline unsigned long __ffs(unsigned long word)
{
	asm("rep; bsf %1,%0"
		: "=r" (word)
		: "rm" (word));
	return word;
}

/**
 * ffz - find first zero bit in word
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
static __always_inline unsigned long ffz(unsigned long word)
{
	asm("rep; bsf %1,%0"
		: "=r" (word)
		: "r" (~word));
	return word;
}

#endif /* BOOT_BITOPS_H */
