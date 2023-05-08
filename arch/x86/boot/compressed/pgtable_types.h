/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOOT_COMPRESSED_PGTABLE_TYPES_H
#define BOOT_COMPRESSED_PGTABLE_TYPES_H
#define _ASM_X86_PGTABLE_DEFS_H /* Inhibit inclusion of <asm/pgtable_types.h> */

#define PAGE_SHIFT	12

#ifdef CONFIG_X86_64
#define PTE_SHIFT	9
#elif defined CONFIG_X86_PAE
#define PTE_SHIFT	9
#else /* 2-level */
#define PTE_SHIFT	10
#endif

enum pg_level {
	PG_LEVEL_NONE,
	PG_LEVEL_4K,
	PG_LEVEL_2M,
	PG_LEVEL_1G,
	PG_LEVEL_512G,
	PG_LEVEL_NUM
};

#endif
