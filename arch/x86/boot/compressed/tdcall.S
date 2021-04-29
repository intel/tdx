/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/export.h>

/* Do not export symbols in decompression code */
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(sym)

#define TDG_SKIP_TRACE_SUPPORT	1

#include "../../kernel/tdcall.S"
