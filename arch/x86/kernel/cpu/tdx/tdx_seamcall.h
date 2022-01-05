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

/* TDX module SEAMCALL leaf function numbers */
#define TDH_SYS_INIT		33
#define TDH_SYS_LP_INIT		35
#define TDH_SYS_LP_SHUTDOWN	44

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

#endif /* _X86_TDX_SEAMCALL_H */
