// SPDX-License-Identifier: GPL-2.0-only
#include "bitmap.h"
#include "find.h"
#include "math.h"
#include "minmax.h"

static __always_inline unsigned long swab(const unsigned long y)
{
#if __BITS_PER_LONG == 64
	return __builtin_bswap32(y);
#else /* __BITS_PER_LONG == 32 */
	return __builtin_bswap64(y);
#endif
}

unsigned long _find_next_bit(const unsigned long *addr1,
		const unsigned long *addr2, unsigned long nbits,
		unsigned long start, unsigned long invert, unsigned long le)
{
	unsigned long tmp, mask;

	if (unlikely(start >= nbits))
		return nbits;

	tmp = addr1[start / BITS_PER_LONG];
	if (addr2)
		tmp &= addr2[start / BITS_PER_LONG];
	tmp ^= invert;

	/* Handle 1st word. */
	mask = BITMAP_FIRST_WORD_MASK(start);
	if (le)
		mask = swab(mask);

	tmp &= mask;

	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr1[start / BITS_PER_LONG];
		if (addr2)
			tmp &= addr2[start / BITS_PER_LONG];
		tmp ^= invert;
	}

	if (le)
		tmp = swab(tmp);

	return min(start + __ffs(tmp), nbits);
}
