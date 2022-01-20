/* SPDX-License-Identifier: GPL-2.0 */

#include "../cpuflags.h"
#include "../string.h"
#include "../io.h"

#include <vdso/limits.h>
#include <uapi/asm/vmx.h>

#include <asm/shared/tdx.h>

static bool tdx_guest_detected;

bool early_is_tdx_guest(void)
{
	return tdx_guest_detected;
}

static inline unsigned int tdx_io_in(int size, u16 port)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_IO_INSTRUCTION,
		.r12 = size,
		.r13  = 0,
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
		.r13  = 1,
		.r14 = port,
		.r15 = value,
	};

	__tdx_hypercall(&args, 0);
}

static inline u8 tdx_inb(u16 port)
{
	return tdx_io_in(1, port);
}

static inline u16 tdx_inw(u16 port)
{
	return tdx_io_in(2, port);
}

static inline u32 tdx_inl(u16 port)
{
	return tdx_io_in(4, port);
}

static inline void tdx_outb(u8 value, u16 port)
{
	tdx_io_out(1, port, value);
}

static inline void tdx_outw(u16 value, u16 port)
{
	tdx_io_out(2, port, value);
}

static inline void tdx_outl(u32 value, u16 port)
{
	tdx_io_out(4, port, value);
}

void early_tdx_detect(void)
{
	u32 eax, sig[3];

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, 12))
		return;

	/* Cache TDX guest feature status */
	tdx_guest_detected = true;

	pio_ops.inb = tdx_inb;
	pio_ops.inw = tdx_inw;
	pio_ops.inl = tdx_inl;
	pio_ops.outb = tdx_outb;
	pio_ops.outw = tdx_outw;
	pio_ops.outl = tdx_outl;
}
