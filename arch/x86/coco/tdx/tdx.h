/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __X86_COCO_TDX_H__
#define __X86_COCO_TDX_H__

#include <uapi/asm/tdx.h>

long tdx_get_quote(void __user *argp);
int __init tdx_attest_init(void *data);

#endif /* __X86_COCO_TDX_H__ */
