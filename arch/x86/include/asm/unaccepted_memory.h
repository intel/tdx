/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_UNACCEPTED_MEMORY_H
#define _ASM_X86_UNACCEPTED_MEMORY_H

#include <linux/types.h>

struct boot_params;
struct page;

void mark_unaccepted(struct boot_params *params, u64 start, u64 num);

void accept_memory(phys_addr_t start, phys_addr_t end);

void maybe_set_page_offline(struct page *page, unsigned int order);
void accept_and_clear_page_offline(struct page *page, unsigned int order);
#endif
