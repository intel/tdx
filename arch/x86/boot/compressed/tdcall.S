/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/export.h>

/* Do not export symbols in decompression code */
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(sym)

#include "../../kernel/tdcall.S"
