/* SPDX-License-Identifier: GPL-2.0-only */

#include "tdx/td_boot_asm.h"

/* Offsets for reading struct td_boot_parameters */
#define TD_BOOT_PARAMETERS_CR0         0
#define TD_BOOT_PARAMETERS_CR3         4
#define TD_BOOT_PARAMETERS_CR4         8
#define TD_BOOT_PARAMETERS_GDT         12
#define TD_BOOT_PARAMETERS_IDT         18
#define TD_BOOT_PARAMETERS_PER_VCPU    24

/* Offsets for reading struct td_per_vcpu_parameters */
#define TD_PER_VCPU_PARAMETERS_ESP_GVA     0
#define TD_PER_VCPU_PARAMETERS_LJMP_TARGET 4

#define SIZEOF_TD_PER_VCPU_PARAMETERS      10

.code32

.globl td_boot
td_boot:
	/* In this procedure, edi is used as a temporary register */
	cli

	/* Paging is off */

	movl $TD_BOOT_PARAMETERS_GPA, %ebx

	/*
	 * Find the address of struct td_per_vcpu_parameters for this
	 * vCPU based on esi (TDX spec: initialized with vcpu id). Put
	 * struct address into register for indirect addressing
	 */
	movl $SIZEOF_TD_PER_VCPU_PARAMETERS, %eax
	mul %esi
	leal TD_BOOT_PARAMETERS_PER_VCPU(%ebx), %edi
	addl %edi, %eax

	/* Setup stack */
	movl TD_PER_VCPU_PARAMETERS_ESP_GVA(%eax), %esp

	/* Setup GDT */
	leal TD_BOOT_PARAMETERS_GDT(%ebx), %edi
	lgdt (%edi)

	/* Setup IDT */
	leal TD_BOOT_PARAMETERS_IDT(%ebx), %edi
	lidt (%edi)

	/*
	 * Set up control registers (There are no instructions to
	 * mov from memory to control registers, hence we need to use ebx
	 * as a scratch register)
	 */
	movl TD_BOOT_PARAMETERS_CR4(%ebx), %edi
	movl %edi, %cr4
	movl TD_BOOT_PARAMETERS_CR3(%ebx), %edi
	movl %edi, %cr3
	movl TD_BOOT_PARAMETERS_CR0(%ebx), %edi
	movl %edi, %cr0

	/* Paging is on after setting the most significant bit on cr0 */

	/*
	 * Jump to selftest guest code. Far jumps read <segment
	 * selector:new eip> from <addr+4:addr>. This location has
	 * already been set up in boot parameters, and we can read boot
	 * parameters because boot code and boot parameters are loaded so
	 * that GVA and GPA are mapped 1:1.
	 */
	ljmp *TD_PER_VCPU_PARAMETERS_LJMP_TARGET(%eax)

.globl reset_vector
reset_vector:
	jmp td_boot
	/*
	 * Pad reset_vector to its full size of 16 bytes so that this
	 * can be loaded with the end of reset_vector aligned to GPA=4G
	 */
	int3
	int3
	int3
	int3
	int3
	int3
	int3
	int3
	int3
	int3
	int3
	int3
	int3
	int3

/* Leave marker so size of td_boot code can be computed */
.globl td_boot_code_end
td_boot_code_end:

/* Disable executable stack */
.section .note.GNU-stack,"",%progbits
