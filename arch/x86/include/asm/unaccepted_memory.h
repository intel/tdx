/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_UNACCEPTED_MEMORY_H
#define _ASM_X86_UNACCEPTED_MEMORY_H

struct boot_params;

void process_unaccepted_memory(struct boot_params *params, u64 start, u64 num);

#ifdef CONFIG_UNACCEPTED_MEMORY

void accept_memory(phys_addr_t start, phys_addr_t end);
bool range_contains_unaccepted_memory(phys_addr_t start, phys_addr_t end);

#endif
#endif
