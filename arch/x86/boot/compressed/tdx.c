// SPDX-License-Identifier: GPL-2.0
/*
 * tdx.c - Early boot code for TDX
 */

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

static inline unsigned int tdx_io_in(int size, int port)
{
	struct tdx_hypercall_output out;

	__tdx_hypercall(TDX_HYPERCALL_STANDARD, EXIT_REASON_IO_INSTRUCTION,
			size, 0, port, 0, &out);

	return out.r10 ? UINT_MAX : out.r11;
}

static inline void tdx_io_out(int size, int port, u64 value)
{
	struct tdx_hypercall_output out;

	__tdx_hypercall(TDX_HYPERCALL_STANDARD, EXIT_REASON_IO_INSTRUCTION,
			size, 1, port, value, &out);
}

static inline unsigned char tdx_inb(int port)
{
	return tdx_io_in(1, port);
}

static inline unsigned short tdx_inw(int port)
{
	return tdx_io_in(2, port);
}

static inline unsigned int tdx_inl(int port)
{
	return tdx_io_in(4, port);
}

static inline void tdx_outb(unsigned char value, int port)
{
	tdx_io_out(1, port, value);
}

static inline void tdx_outw(unsigned short value, int port)
{
	tdx_io_out(2, port, value);
}

static inline void tdx_outl(unsigned int value, int port)
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
