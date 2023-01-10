/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _TOOLS_LINUX_ASM_X86_KVM_HOST_H
#define _TOOLS_LINUX_ASM_X86_KVM_HOST_H

#include <stdbool.h>
#include <stdint.h>

struct kvm_vm_arch {
	uint64_t c_bit;
	uint64_t s_bit;
};

#endif  // _TOOLS_LINUX_ASM_X86_KVM_HOST_H
