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

/* Called from __tdx_hypercall() for unrecoverable failure */
void __tdx_hypercall_failed(void)
{
	error("TDVMCALL failed. TDX module bug?");
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

	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
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

	__tdx_hypercall(&args, 0);
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

	/* Use hypercalls instead of I/O instructions */
	pio_ops.f_inb  = tdx_inb;
	pio_ops.f_outb = tdx_outb;
	pio_ops.f_outw = tdx_outw;
}

static unsigned long try_accept_one(phys_addr_t start, unsigned long len,
				    enum pg_level level)
{
	unsigned long accept_size = PAGE_SIZE << ((level - 1) * PTE_SHIFT);
	u64 tdcall_rcx;
	u8 page_size;

	if (!IS_ALIGNED(start, accept_size))
		return 0;

	if (len < accept_size)
		return 0;

	/*
	 * Pass the page physical address to the TDX module to accept the
	 * pending, private page.
	 *
	 * Bits 2:0 of RCX encode page size: 0 - 4K, 1 - 2M, 2 - 1G.
	 */
	switch (level) {
	case PG_LEVEL_4K:
		page_size = 0;
		break;
	case PG_LEVEL_2M:
		page_size = 1;
		break;
	case PG_LEVEL_1G:
		page_size = 2;
		break;
	default:
		return 0;
	}

	tdcall_rcx = start | page_size;
	if (__tdx_module_call(TDX_ACCEPT_PAGE, tdcall_rcx, 0, 0, 0, NULL))
		return 0;

	return accept_size;
}

void tdx_accept_memory(phys_addr_t start, phys_addr_t end)
{
	/*
	 * Notify the VMM about page mapping conversion. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface (GHCI),
	 * section "TDG.VP.VMCALL<MapGPA>"
	 */
	if (_tdx_hypercall(TDVMCALL_MAP_GPA, start, end - start, 0, 0))
		error("Accepting memory failed\n");

	/*
	 * For shared->private conversion, accept the page using
	 * TDX_ACCEPT_PAGE TDX module call.
	 */
	while (start < end) {
		unsigned long len = end - start;
		unsigned long accept_size;

		/*
		 * Try larger accepts first. It gives chance to VMM to keep
		 * 1G/2M Secure EPT entries where possible and speeds up
		 * process by cutting number of hypercalls (if successful).
		 */

		accept_size = try_accept_one(start, len, PG_LEVEL_1G);
		if (!accept_size)
			accept_size = try_accept_one(start, len, PG_LEVEL_2M);
		if (!accept_size)
			accept_size = try_accept_one(start, len, PG_LEVEL_4K);
		if (!accept_size)
			error("Accepting memory failed\n");
		start += accept_size;
	}
}
