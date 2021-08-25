// SPDX-License-Identifier: GPL-2.0
/*
 * tdx.c - Early boot code for TDX
 */

#include "../cpuflags.h"
#include "../string.h"
#include "error.h"

#include <asm/page_types.h>

#define TDX_HYPERCALL_STANDARD			0
#define TDX_CPUID_LEAF_ID                       0x21

/*
 * Used in __tdx_module_call() helper function to gather the
 * output registers' values of TDCALL instruction when requesting
 * services from the TDX module. This is software only structure
 * and not related to TDX module/VMM.
 */
struct tdx_module_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

/*
 * Used in __tdx_hypercall() helper function to gather the
 * output registers' values of TDCALL instruction when requesting
 * services from the VMM. This is software only structure
 * and not related to TDX module/VMM.
 */
struct tdx_hypercall_output {
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

static int tdx_guest = -1;

/* Helper function used to communicate with the TDX module */
u64 __tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		      struct tdx_module_output *out);

/* Helper function used to request services from VMM */
u64 __tdx_hypercall(u64 type, u64 fn, u64 r12, u64 r13, u64 r14,
		    u64 r15, struct tdx_hypercall_output *out);

static inline bool early_cpuid_has_tdx_guest(void)
{
	u32 eax = TDX_CPUID_LEAF_ID, sig[3] = {0};

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2], &sig[1]);

	return !memcmp("IntelTDX    ", sig, 12);
}

bool early_is_tdx_guest(void)
{
	if (tdx_guest < 0)
		tdx_guest = early_cpuid_has_tdx_guest();

	return !!tdx_guest;
}

#define TDACCEPTPAGE		6
#define TDVMCALL_MAP_GPA	0x10001

void tdx_accept_memory(phys_addr_t start, phys_addr_t end)
{
	struct tdx_hypercall_output outl = {0};
	int i;

	if (__tdx_hypercall(TDX_HYPERCALL_STANDARD, TDVMCALL_MAP_GPA,
			    start, end, 0, 0, &outl)) {
		error("Cannot accept memory: MapGPA failed\n");
	}

	/*
	 * For shared->private conversion, accept the page using TDACCEPTPAGE
	 * TDX module call.
	 */
	for (i = 0; i < (end - start) / PAGE_SIZE; i++) {
		if (__tdx_module_call(TDACCEPTPAGE, start + i * PAGE_SIZE,
				      0, 0, 0, NULL)) {
			error("Cannot accept memory: page accept failed\n");
		}
	}
}
