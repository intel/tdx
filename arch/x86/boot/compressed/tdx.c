// SPDX-License-Identifier: GPL-2.0

#include "../cpuflags.h"
#include "../string.h"
#include "../io.h"
#include "align.h"
#include "error.h"
#include "pgtable_types.h"

#include <vdso/limits.h>
#include <uapi/asm/vmx.h>

#include <asm/shared/tdx.h>
#include <asm/page_types.h>

static u64 cc_mask;

/* Called from __tdx_hypercall() for unrecoverable failure */
void __tdx_hypercall_failed(void)
{
	error("TDVMCALL failed. TDX module bug?");
}

static u64 get_cc_mask(void)
{
	struct tdx_module_output out;
	unsigned int gpa_width;

	/*
	 * TDINFO TDX module call is used to get the TD execution environment
	 * information like GPA width, number of available vcpus, debug mode
	 * information, etc. More details about the ABI can be found in TDX
	 * Guest-Host-Communication Interface (GHCI), section 2.4.2 TDCALL
	 * [TDG.VP.INFO].
	 *
	 * The GPA width that comes out of this call is critical. TDX guests
	 * can not meaningfully run without it.
	 */
	if (__tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out))
		error("TDCALL GET_INFO failed (Buggy TDX module!)\n");

	gpa_width = out.rcx & GENMASK(5, 0);

	/*
	 * The highest bit of a guest physical address is the "sharing" bit.
	 * Set it for shared pages and clear it for private pages.
	 */
	return BIT_ULL(gpa_width - 1);
}

u64 cc_mkdec(u64 val)
{
	return val & ~cc_mask;
}

static inline unsigned int tdx_io_in(int size, u16 port)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_IO_INSTRUCTION,
		.r12 = size,
		.r13 = 0,
		.r14 = port,
	};

	if (__tdx_hypercall_ret(&args))
		return UINT_MAX;

	return args.r11;
}

static inline void tdx_io_out(int size, u16 port, u32 value)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_IO_INSTRUCTION,
		.r12 = size,
		.r13 = 1,
		.r14 = port,
		.r15 = value,
	};

	__tdx_hypercall(&args);
}

static inline u8 tdx_inb(u16 port)
{
	return tdx_io_in(1, port);
}

static inline void tdx_outb(u8 value, u16 port)
{
	tdx_io_out(1, port, value);
}

static inline void tdx_outw(u16 value, u16 port)
{
	tdx_io_out(2, port, value);
}

void early_tdx_detect(void)
{
	u32 eax, sig[3];

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, sizeof(sig)))
		return;

	cc_mask = get_cc_mask();

	/* Use hypercalls instead of I/O instructions */
	pio_ops.f_inb  = tdx_inb;
	pio_ops.f_outb = tdx_outb;
	pio_ops.f_outw = tdx_outw;
}
