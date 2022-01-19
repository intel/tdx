/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOOT_IO_H
#define BOOT_IO_H

#include <asm/shared/io.h>

struct port_io_ops {
	u8 (*inb)(u16 port);
	u16 (*inw)(u16 port);
	u32 (*inl)(u16 port);
	void (*outb)(u8 v, u16 port);
	void (*outw)(u16 v, u16 port);
	void (*outl)(u32 v, u16 port);
};

extern struct port_io_ops pio_ops;

static inline void init_io_ops(void)
{
	pio_ops.inb = inb;
	pio_ops.inw = inw;
	pio_ops.inl = inl;
	pio_ops.outb = outb;
	pio_ops.outw = outw;
	pio_ops.outl = outl;
}

#endif
