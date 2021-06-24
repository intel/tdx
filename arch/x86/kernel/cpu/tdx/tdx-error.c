// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include <linux/kvm_types.h>
#include <linux/trace_events.h>

#include <asm/tdx_errno.h>
#include <asm/tdx_arch.h>

#include "p-seamldr.h"

#define CREATE_TRACE_POINTS
#include <asm/trace/seam.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(seamcall_enter);
EXPORT_TRACEPOINT_SYMBOL_GPL(seamcall_exit);
