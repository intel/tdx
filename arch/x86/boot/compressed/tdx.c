/* SPDX-License-Identifier: GPL-2.0 */

#include "../cpuflags.h"
#include "../string.h"

#include <asm/shared/tdx.h>

static bool tdx_guest_detected;

bool early_is_tdx_guest(void)
{
	return tdx_guest_detected;
}

void early_tdx_detect(void)
{
	u32 eax, sig[3];

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, 12))
		return;

	/* Cache TDX guest feature status */
	tdx_guest_detected = true;
}
