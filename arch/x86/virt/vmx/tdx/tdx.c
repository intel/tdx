// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) support
 */

#define pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/tdx.h>

#define seamcall_err(__fn, __err, __args, __prerr_func)			\
	__prerr_func("SEAMCALL (0x%llx) failed: 0x%llx\n",		\
			((u64)__fn), ((u64)__err))

#define SEAMCALL_REGS_FMT						\
	"RCX 0x%llx RDX 0x%llx R8 0x%llx R9 0x%llx R10 0x%llx R11 0x%llx\n"

#define seamcall_err_ret(__fn, __err, __args, __prerr_func)		\
({									\
	seamcall_err((__fn), (__err), (__args), __prerr_func);		\
	__prerr_func(SEAMCALL_REGS_FMT,					\
			(__args)->rcx, (__args)->rdx, (__args)->r8,	\
			(__args)->r9, (__args)->r10, (__args)->r11);	\
})

#define SEAMCALL_EXTRA_REGS_FMT	\
	"RBX 0x%llx RDI 0x%llx RSI 0x%llx R12 0x%llx R13 0x%llx R14 0x%llx R15 0x%llx"

#define seamcall_err_saved_ret(__fn, __err, __args, __prerr_func)	\
({									\
	seamcall_err_ret(__fn, __err, __args, __prerr_func);		\
	__prerr_func(SEAMCALL_EXTRA_REGS_FMT,				\
			(__args)->rbx, (__args)->rdi, (__args)->rsi,	\
			(__args)->r12, (__args)->r13, (__args)->r14,	\
			(__args)->r15);					\
})

static __always_inline bool seamcall_err_is_kernel_defined(u64 err)
{
	/* All kernel defined SEAMCALL error code have TDX_SW_ERROR set */
	return (err & TDX_SW_ERROR) == TDX_SW_ERROR;
}

#define __SEAMCALL_PRERR(__seamcall_func, __fn, __args, __seamcall_err_func,	\
			__prerr_func)						\
({										\
	u64 ___sret = __seamcall_func((__fn), (__args));			\
										\
	/* Kernel defined error code has special meaning, leave to caller */	\
	if (!seamcall_err_is_kernel_defined((___sret)) &&			\
			___sret != TDX_SUCCESS)					\
		__seamcall_err_func((__fn), (___sret), (__args), __prerr_func);	\
										\
	___sret;								\
})

#define SEAMCALL_PRERR(__seamcall_func, __fn, __args, __seamcall_err_func)	\
({										\
	u64 ___sret = __SEAMCALL_PRERR(__seamcall_func, __fn, __args,		\
			__seamcall_err_func, pr_err);				\
	int ___ret;								\
										\
	switch (___sret) {							\
	case TDX_SUCCESS:							\
		___ret = 0;							\
		break;								\
	case TDX_SEAMCALL_VMFAILINVALID:					\
		pr_err("SEAMCALL failed: TDX module not loaded.\n");		\
		___ret = -ENODEV;						\
		break;								\
	case TDX_SEAMCALL_GP:							\
		pr_err("SEAMCALL failed: TDX disabled by BIOS.\n");		\
		___ret = -EOPNOTSUPP;						\
		break;								\
	case TDX_SEAMCALL_UD:							\
		pr_err("SEAMCALL failed: CPU not in VMX operation.\n");		\
		___ret = -EACCES;						\
		break;								\
	default:								\
		___ret = -EIO;							\
	}									\
	___ret;									\
})

#define seamcall_prerr(__fn, __args)						\
	SEAMCALL_PRERR(seamcall, (__fn), (__args), seamcall_err)

#define seamcall_prerr_ret(__fn, __args)					\
	SEAMCALL_PRERR(seamcall_ret, (__fn), (__args), seamcall_err_ret)

#define seamcall_prerr_saved_ret(__fn, __args)					\
	SEAMCALL_PRERR(seamcall_saved_ret, (__fn), (__args),			\
			seamcall_err_saved_ret)

static u32 tdx_global_keyid __ro_after_init;
static u32 tdx_guest_keyid_start __ro_after_init;
static u32 tdx_nr_guest_keyids __ro_after_init;

static int __init record_keyid_partitioning(u32 *tdx_keyid_start,
					    u32 *nr_tdx_keyids)
{
	u32 _nr_mktme_keyids, _tdx_keyid_start, _nr_tdx_keyids;
	int ret;

	/*
	 * IA32_MKTME_KEYID_PARTIONING:
	 *   Bit [31:0]:	Number of MKTME KeyIDs.
	 *   Bit [63:32]:	Number of TDX private KeyIDs.
	 */
	ret = rdmsr_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &_nr_mktme_keyids,
			&_nr_tdx_keyids);
	if (ret)
		return -ENODEV;

	if (!_nr_tdx_keyids)
		return -ENODEV;

	/* TDX KeyIDs start after the last MKTME KeyID. */
	_tdx_keyid_start = _nr_mktme_keyids + 1;

	*tdx_keyid_start = _tdx_keyid_start;
	*nr_tdx_keyids = _nr_tdx_keyids;

	return 0;
}

static int __init tdx_init(void)
{
	u32 tdx_keyid_start, nr_tdx_keyids;
	int err;

	err = record_keyid_partitioning(&tdx_keyid_start, &nr_tdx_keyids);
	if (err)
		return err;

	pr_info("BIOS enabled: private KeyID range [%u, %u)\n",
			tdx_keyid_start, tdx_keyid_start + nr_tdx_keyids);

	/*
	 * The TDX module itself requires one 'global KeyID' to protect
	 * its metadata.  If there's only one TDX KeyID, there won't be
	 * any left for TDX guests thus there's no point to enable TDX
	 * at all.
	 */
	if (nr_tdx_keyids < 2) {
		pr_err("initialization failed: too few private KeyIDs available.\n");
		return -ENODEV;
	}

	/*
	 * Just use the first TDX KeyID as the 'global KeyID' and
	 * leave the rest for TDX guests.
	 */
	tdx_global_keyid = tdx_keyid_start;
	tdx_guest_keyid_start = tdx_keyid_start + 1;
	tdx_nr_guest_keyids = nr_tdx_keyids - 1;

	return 0;
}
early_initcall(tdx_init);

/* Return whether the BIOS has enabled TDX */
bool platform_tdx_enabled(void)
{
	return !!tdx_global_keyid;
}
