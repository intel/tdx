/* SPDX-License-Identifier: GPL-2.0-only */

#include <asm/export.h>

/* Do not export symbols in decompression code */
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(sym)

#define TDX_SKIP_IO_FILTERING

#include "../../kernel/tdx_io.S"
