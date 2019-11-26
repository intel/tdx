#include <asm/export.h>

/* Do not export symbols in decompression code */
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(sym)

#include "../../kernel/tdx_io.S"
