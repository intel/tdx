/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel TDX module SEAMCALL wrapper functions
 */

#ifndef _X86_TDX_SEAMCALL_H
#define _X86_TDX_SEAMCALL_H

#include <linux/types.h>
#include <asm/seam.h>
#include "tdx_arch.h"

/* TDX module SEAMCALL leaf function numbers */
#define TDH_SYS_KEY_CONFIG	31
#define TDH_SYS_INFO		32
#define TDH_SYS_INIT		33
#define TDH_SYS_LP_INIT		35
#define TDH_SYS_LP_SHUTDOWN	44
#define TDH_SYS_CONFIG		45

/* TDX module SEAMCALL error codes */
#define TDX_KEY_CONFIGURED                      0x0000081500000000ULL

/**
 * tdh_sys_key_config - Configure the global KeyID on local CPU package
 *
 * Configure the global KeyID to generate the key on the CPU package
 * which the local cpu belongs to.
 *
 * Return: Completion status of TDH.SYS.KEY.CONFIG SEAMCALL.
 */
static inline u64 tdh_sys_key_config(void)
{
	return seamcall(TDH_SYS_KEY_CONFIG, NULL, NULL);
}

/*
 * tdh_sys_info - Get TDX module and CMR array information
 *
 * @tdsysinfo:		Address of TDSYSINFO_STRUCT
 * @cmr_array:		Address of array of CMR_INFO
 * @tdsysinfo_sz:	The actual number of bytes written to @tdsysinfo
 * @cmr_num:		The actual number of CMR_INFO entries written to
 *			@cmr_array
 *
 * Caller guarantees @cmr_array at least has MAX_CMRS entries.
 *
 * Return: Completion status of TDH.SYS.INFO SEAMCALL.
 */
static inline u64 tdh_sys_info(struct tdsysinfo_struct *tdsysinfo,
			       struct cmr_info *cmr_array,
			       u64 *tdsysinfo_sz, u64 *cmr_num)
{
	struct seamcall_regs_in in;
	struct seamcall_regs_out out;
	u64 ret;

	in.rcx = __pa(tdsysinfo);
	in.rdx = sizeof(*tdsysinfo);
	in.r8 = __pa(cmr_array);
	in.r9 = MAX_CMRS;

	ret = seamcall(TDH_SYS_INFO, &in, &out);

	/*
	 * If SEAMCALL succeeds, RDX contains the actual bytes written
	 * to @tdsysinfo and R9 contains the actual written number of
	 * CMR_INFO entries.  Otherwise both fields are 0.
	 */
	*tdsysinfo_sz = out.rdx;
	*cmr_num = out.r9;

	return ret;
}

/**
 * tdh_sys_init - Do platform level initialization
 *
 * Return: Completion status of TDH.SYS.INIT SEMACALL.
 */
static inline u64 tdh_sys_init(void)
{
	struct seamcall_regs_in in;
	u64 ret;

	in.rcx = 0;	/* must be 0 for current TDX generation */
	ret = seamcall(TDH_SYS_INIT, &in, NULL);
	return ret;
}

/**
 * tdh_sys_lp_init - Do logical cpu level initialization for local cpu
 *
 * Return: Completion status of TDH.SYS.LP.INIT SEAMCALL.
 */
static inline u64 tdh_sys_lp_init(void)
{
	return seamcall(TDH_SYS_LP_INIT, NULL, NULL);
}

/**
 * tdh_sys_lp_shutdown - Put TDX module to shutdown mode on local cpu
 *
 * Put TDX module to shutdown mode on local cpu, and prevent further
 * SEAMCALLs being made on this cpu.
 *
 * Return: Completion status of TDH.SYS.LP.SHUTDOWN SEAMCALL.
 */
static inline u64 tdh_sys_lp_shutdown(void)
{
	return seamcall(TDH_SYS_LP_SHUTDOWN, NULL, NULL);
}

/**
 * tdh_sys_config - Configure TDX module with TDMRs and global KeyID
 *
 * Return: Completion status of TDH.SYS.CONFIG SEAMCALL.
 */
static inline u64 tdh_sys_config(u64 *tdmr_pa_array, u64 tdmr_num,
		u64 global_keyid)
{
	struct seamcall_regs_in in;
	u64 ret;

	in.rcx = __pa(tdmr_pa_array);
	in.rdx = tdmr_num;
	in.r8 = global_keyid;

	ret = seamcall(TDH_SYS_CONFIG, &in, NULL);
	return ret;
}

#endif /* _X86_TDX_SEAMCALL_H */
