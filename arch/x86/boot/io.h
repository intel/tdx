/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOOT_IO_H
#define BOOT_IO_H

#include <asm/shared/io.h>

struct port_io_ops {
	unsigned char (*inb)(int port);
	unsigned short (*inw)(int port);
	unsigned int (*inl)(int port);
	void (*outb)(unsigned char v, int port);
	void (*outw)(unsigned short v, int port);
	void (*outl)(unsigned int v, int port);
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
