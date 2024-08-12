/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/init.h>
#include <linux/bits.h>

#include <asm/errno.h>
#include <asm/ptrace.h>
#include <asm/trapnr.h>
#include <asm/shared/tdx.h>

/*
 * SW-defined error codes.
 *
 * Bits 47:40 == 0xFF indicate Reserved status code class that never used by
 * TDX module.
 */
#define TDX_ERROR			_BITUL(63)
#define TDX_SW_ERROR			(TDX_ERROR | GENMASK_ULL(47, 40))
#define TDX_SEAMCALL_VMFAILINVALID	(TDX_SW_ERROR | _UL(0xFFFF0000))

#define TDX_SEAMCALL_GP			(TDX_SW_ERROR | X86_TRAP_GP)
#define TDX_SEAMCALL_UD			(TDX_SW_ERROR | X86_TRAP_UD)

/*
 * TDX module SEAMCALL leaf function error codes
 */
#define TDX_SUCCESS		0ULL
#define TDX_RND_NO_ENTROPY	0x8000020300000000ULL

#ifndef __ASSEMBLY__

#include <uapi/asm/mce.h>

/*
 * Used by the #VE exception handler to gather the #VE exception
 * info from the TDX module. This is a software only structure
 * and not part of the TDX module/VMM ABI.
 */
struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	/* Guest Linear (virtual) Address */
	u64 gla;
	/* Guest Physical Address */
	u64 gpa;
	u32 instr_len;
	u32 instr_info;
};

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);

void tdx_get_ve_info(struct ve_info *ve);

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve);

void tdx_safe_halt(void);

bool tdx_early_handle_ve(struct pt_regs *regs);

int tdx_mcall_get_report0(u8 *reportdata, u8 *tdreport);

u64 tdx_hcall_get_quote(u8 *buf, size_t size);

#else

static inline void tdx_early_init(void) { };
static inline void tdx_safe_halt(void) { };

static inline bool tdx_early_handle_ve(struct pt_regs *regs) { return false; }

#endif /* CONFIG_INTEL_TDX_GUEST */

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_INTEL_TDX_GUEST)
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4);
#else
static inline long tdx_kvm_hypercall(unsigned int nr, unsigned long p1,
				     unsigned long p2, unsigned long p3,
				     unsigned long p4)
{
	return -ENODEV;
}
#endif /* CONFIG_INTEL_TDX_GUEST && CONFIG_KVM_GUEST */

#ifdef CONFIG_INTEL_TDX_HOST

/*
 * Kernel-defined structures to contain "Global Scope Metadata".
 *
 * TDX global metadata fields are categorized by "Class".  See the
 * "global_metadata.json" in the "TDX 1.5 ABI Definitions".
 *
 * 'struct tdx_sysinfo' is the main structure to contain all metadata
 * used by the kernel.  It contains sub-structures with each reflecting
 * the "Class" in the 'global_metadata.json'.
 *
 * Note not all metadata fields in each class are defined, only those
 * used by the kernel are.
 *
 * Also note the "bit/constant definitions" are architectural.
 */

/* Class "TDX Module Info" */
struct tdx_sysinfo_module_info {
	u32 sys_attributes;
	u64 tdx_features0;
};

#define TDX_SYS_ATTR_DEBUG_MODULE	0x1
#define TDX_FEATURES0_NO_RBP_MOD	_BITULL(18)

/* Class "TDX Module Version" */
struct tdx_sysinfo_module_version {
	u16 major;
	u16 minor;
	u16 update;
	u16 internal;
	u16 build_num;
	u32 build_date;
};

/* Class "CMR Info" */
#define TDX_MAX_CMRS	32
struct tdx_sysinfo_cmr_info {
	u16 num_cmrs;
	u64 cmr_base[TDX_MAX_CMRS];
	u64 cmr_size[TDX_MAX_CMRS];
};

/* Class "TDMR Info" */
struct tdx_sysinfo_tdmr_info {
	u16 max_tdmrs;
	u16 max_reserved_per_tdmr;
	u16 pamt_entry_size[TDX_PS_NR];
};

/* Class "TD Control Structures" */
struct tdx_sysinfo_td_ctrl {
	u16 tdr_base_size;
	u16 tdcs_base_size;
	u16 tdvps_base_size;
};

/* Class "TD Configurability" */
#define MAX_CPUID_CONFIG	32

struct tdx_cpuid_config_value {
	u64 eax_ebx;
	u64 ecx_edx;
};

struct tdx_sysinfo_td_conf {
	u64 attributes_fixed0;
	u64 attributes_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;
	u16 num_cpuid_config;
	u16 max_vcpus_per_td;
	u64 cpuid_config_leaves[MAX_CPUID_CONFIG];
	struct tdx_cpuid_config_value cpuid_config_values[MAX_CPUID_CONFIG];
};

struct tdx_sysinfo {
	struct tdx_sysinfo_module_info		module_info;
	struct tdx_sysinfo_module_version	module_version;
	struct tdx_sysinfo_cmr_info		cmr_info;
	struct tdx_sysinfo_tdmr_info		tdmr_info;
	struct tdx_sysinfo_td_ctrl		td_ctrl;
	struct tdx_sysinfo_td_conf		td_conf;
};

const struct tdx_sysinfo *tdx_get_sysinfo(void);

extern u32 tdx_global_keyid;
extern u32 tdx_guest_keyid_start;
extern u32 tdx_nr_guest_keyids;

u64 __seamcall(u64 fn, struct tdx_module_args *args);
u64 __seamcall_ret(u64 fn, struct tdx_module_args *args);
u64 __seamcall_saved_ret(u64 fn, struct tdx_module_args *args);
void tdx_init(void);

#include <asm/archrandom.h>

typedef u64 (*sc_func_t)(u64 fn, struct tdx_module_args *args);

static inline u64 sc_retry(sc_func_t func, u64 fn,
			   struct tdx_module_args *args)
{
	int retry = RDRAND_RETRY_LOOPS;
	u64 ret;

	do {
		ret = func(fn, args);
	} while (ret == TDX_RND_NO_ENTROPY && --retry);

	return ret;
}

#define seamcall(_fn, _args)		sc_retry(__seamcall, (_fn), (_args))
#define seamcall_ret(_fn, _args)	sc_retry(__seamcall_ret, (_fn), (_args))
#define seamcall_saved_ret(_fn, _args)	sc_retry(__seamcall_saved_ret, (_fn), (_args))
int tdx_cpu_enable(void);
int tdx_enable(void);
const char *tdx_dump_mce_info(struct mce *m);
#else
static inline void tdx_init(void) { }
static inline int tdx_cpu_enable(void) { return -ENODEV; }
static inline int tdx_enable(void)  { return -ENODEV; }
static inline const char *tdx_dump_mce_info(struct mce *m) { return NULL; }
#endif	/* CONFIG_INTEL_TDX_HOST */

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_TDX_H */
