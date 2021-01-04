// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, Microsoft Corporation.
 *
 */
#include <linux/types.h>
#include <asm/io.h>
#include <asm/mshyperv.h>
#include <asm/hyperv-tlfs.h>

#define VMGEXIT()                       { asm volatile("rep; vmmcall\n\r"); }

struct vmcb_seg {
	u16 selector;
	u16 attrib;
	u32 limit;
	u64 base;
} __packed;

struct vmcb_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
	u8 reserved_1[43];
	u8 cpl;
	u8 reserved_2[4];
	u64 efer;
	u8 reserved_3[112];
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
	u8 reserved_4[88];
	u64 rsp;
	u8 reserved_5[24];
	u64 rax;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sfmask;
	u64 kernel_gs_base;
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 cr2;
	u8 reserved_6[32];
	u64 g_pat;
	u64 dbgctl;
	u64 br_from;
	u64 br_to;
	u64 last_excp_from;
	u64 last_excp_to;

	/*
	 * The following part of the save area is valid only for
	 * SEV-ES guests when referenced through the GHCB.
	 */
	u8 reserved_7[104];
	u64 reserved_8;		/* rax already available at 0x01f8 */
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 reserved_9;		/* rsp already available at 0x01d8 */
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u8 reserved_10[16];
	u64 sw_exit_code;
	u64 sw_exit_info_1;
	u64 sw_exit_info_2;
	u64 sw_scratch;
	u8 reserved_11[56];
	u64 xcr0;
	u8 valid_bitmap[16];
	u64 x87_state_gpa;
} __packed;

struct ghcb {
	struct vmcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct vmcb_save_area)];

	u8 shared_buffer[2032];

	u8 reserved_1[10];
	u16 protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	u32 ghcb_usage;
} __packed;


union hv_ghcb {
	struct ghcb ghcb;
	struct {
		u64 hypercalldata[509];
		u64 outputgpa;
		union {
			union {
				struct {
					u32 callcode        : 16;
					u32 isfast          : 1;
					u32 reserved1       : 14;
					u32 isnested        : 1;
					u32 countofelements : 12;
					u32 reserved2       : 4;
					u32 repstartindex   : 12;
					u32 reserved3       : 4;
				};
				u64 asuint64;
			} hypercallinput;
			union {
				struct {
					u16 callstatus;
					u16 reserved1;
					u32 elementsprocessed : 12;
					u32 reserved2         : 20;
				};
				u64 asunit64;
			} hypercalloutput;
		};
		u64 reserved2;
	} hypercall;
} __attribute__ ((__packed__)) __attribute__ ((aligned(PAGE_SIZE)));

void hv_ghcb_msr_write(u64 msr, u64 value)
{
	union hv_ghcb *hv_ghcb;
	unsigned long flags;

	if (!ms_hyperv.ghcb_base)
		return;

	hv_ghcb = (union hv_ghcb *)ms_hyperv.ghcb_base[smp_processor_id()];

	memset(hv_ghcb, 0x00, PAGE_SIZE);

	local_irq_save(flags);

	hv_ghcb->ghcb.protocol_version = 1;
	hv_ghcb->ghcb.ghcb_usage = 0;

	hv_ghcb->ghcb.save.sw_exit_code = 0x7c;
	hv_ghcb->ghcb.save.rcx = msr;
	hv_ghcb->ghcb.save.rax = lower_32_bits(value);
	hv_ghcb->ghcb.save.rdx = value >> 32;
	hv_ghcb->ghcb.save.sw_exit_info_1 = 1;
	hv_ghcb->ghcb.save.sw_exit_info_2 = 0;

	VMGEXIT();

	local_irq_restore(flags);
}

void hv_ghcb_msr_read(u64 msr, u64 *value)
{
	union hv_ghcb *hv_ghcb;
	unsigned long flags;

	if (!ms_hyperv.ghcb_base)
		return;

	hv_ghcb = (union hv_ghcb *)ms_hyperv.ghcb_base[smp_processor_id()];

	memset(hv_ghcb, 0x00, PAGE_SIZE);

	local_irq_save(flags);

	hv_ghcb->ghcb.protocol_version = 1;
	hv_ghcb->ghcb.ghcb_usage = 0;

	hv_ghcb->ghcb.save.sw_exit_code = 0x7c;
	hv_ghcb->ghcb.save.rcx = msr;

	hv_ghcb->ghcb.save.sw_exit_info_1 = 0;
	hv_ghcb->ghcb.save.sw_exit_info_2 = 0;

	VMGEXIT();

	*value = (u64)lower_32_bits(hv_ghcb->ghcb.save.rax)
		| ((u64)lower_32_bits(hv_ghcb->ghcb.save.rdx) << 32);
	local_irq_restore(flags);
}

void hv_sint_rdmsrl_ghcb(u64 msr, u64 *value)
{
	hv_ghcb_msr_read(msr, value);
}
EXPORT_SYMBOL_GPL(hv_sint_rdmsrl_ghcb);

void hv_sint_wrmsrl_ghcb(u64 msr, u64 value)
{
	hv_ghcb_msr_write(msr, value);

	/* Write proxy bit vua wrmsrl instruction. */
	if (msr >= HV_X64_MSR_SINT0 && msr <= HV_X64_MSR_SINT15)
		wrmsrl(msr, value | 1 << 20);
}
EXPORT_SYMBOL_GPL(hv_sint_wrmsrl_ghcb);

inline void hv_signal_eom_ghcb(void)
{
	hv_sint_wrmsrl_ghcb(HV_X64_MSR_EOM, 0);
}
EXPORT_SYMBOL_GPL(hv_signal_eom_ghcb);

inline bool hv_partition_is_isolated(void)
{
	return (ms_hyperv.partition_flags & HV_X64_PARTITION_ISOLATION);
}
EXPORT_SYMBOL(hv_partition_is_isolated);

inline bool hv_isolation_type_snp(void)
{
	return (ms_hyperv.cvm_flag & HV_X64_PARTITION_ISOLATION_SNP);
}
EXPORT_SYMBOL_GPL(hv_isolation_type_snp);

