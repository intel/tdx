/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_UNACCEPTED_MEMORY_H
#define _ASM_X86_UNACCEPTED_MEMORY_H

#include <linux/types.h>

struct boot_params;

void mark_unaccepted(struct boot_params *params, u64 start, u64 num);

#endif
