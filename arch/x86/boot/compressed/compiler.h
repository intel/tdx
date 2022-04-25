/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BOOT_COMPILER_H
#define BOOT_COMPILER_H
#define __LINUX_COMPILER_H /* Inhibit inclusion of <linux/compiler.h> */

# define likely(x)	__builtin_expect(!!(x), 1)
# define unlikely(x)	__builtin_expect(!!(x), 0)

#endif
