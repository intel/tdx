/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_COCO_H
#define _ASM_X86_COCO_H

#include <asm/pgtable_types.h>

enum cc_vendor {
	CC_VENDOR_NONE,
	CC_VENDOR_AMD,
	CC_VENDOR_HYPERV,
	CC_VENDOR_INTEL,
};

void cc_init(enum cc_vendor, u64 mask);

#ifdef CONFIG_ARCH_HAS_CC_PLATFORM
u64 cc_get_mask(bool enc);
u64 cc_mkenc(u64 val);
u64 cc_mkdec(u64 val);
#else
#define cc_get_mask(enc)	0
#define cc_mkenc(val)		(val)
#define cc_mkdec(val)		(val)
#endif

#endif /* _ASM_X86_COCO_H */
