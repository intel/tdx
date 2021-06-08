/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Intel Corporation */
#ifndef BOOT_COMPRESSED_TDX_H
#define BOOT_COMPRESSED_TDX_H

#include <linux/types.h>

#ifdef CONFIG_INTEL_TDX_GUEST

#include <vdso/limits.h>
#include <uapi/asm/vmx.h>
#include <asm/tdx.h>

void early_tdx_detect(void);
bool early_is_tdx_guest(void);

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

#define __out(bwl, bw, sz)						\
do {									\
	if (early_is_tdx_guest()) {					\
		tdx_io_out(sz, port, value);				\
	} else {							\
		asm volatile("out" #bwl " %" #bw "0, %w1" : :		\
				"a"(value), "Nd"(port));		\
	}								\
} while (0)

#define __in(bwl, bw, sz)						\
do {									\
	if (early_is_tdx_guest()) {					\
		value = tdx_io_in(sz, port);				\
	} else {							\
		asm volatile("in" #bwl " %w1, %" #bw "0" :		\
				"=a"(value) : "Nd"(port));		\
	}								\
} while (0)

#else
static inline void early_tdx_detect(void) { };
static inline bool early_is_tdx_guest(void) { return false; }
#endif

#endif
