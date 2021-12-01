// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel TDX P-SEAMLDR support
 */

#define pr_fmt(fmt)	"p-seamldr: " fmt

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <asm/seam.h>
#include "p-seamldr.h"

/*
 * P-SEAMLDR architectural data structures.
 */
struct tee_tcb_svn {
	u16 seam;
	u8 reserved[14];
} __packed;

/* Low 128 bytes of TEE_TCB_INFO */
struct __tee_tcb_info {
	u64 valid;
	struct tee_tcb_svn tee_tcb_svn;
	u64 mrseam[6];		/* SHA-384 */
	u64 mrsignerseam[6];	/* SHA-384 */
	u64 attributes;
} __packed;

struct p_seamldr_info {
	u32 version;
	u32 attributes;
	u32 vendor_id;
	u32 build_date;
	u16 build_num;
	u16 minor;
	u16 major;
	u8 reserved0[2];
	u32 acm_x2apicid;
	u8 reserved1[4];
	struct __tee_tcb_info seaminfo;
	u8 seam_ready;
	u8 seam_debug;
	u8 p_seamldr_ready;
	u8 reserved2[88];
} __packed __aligned(256);

static struct p_seamldr_info p_seamldr_info;

/* Spinlock to prevent calling P-SEAMLDR SEAMCALLs concurrently */
static DEFINE_SPINLOCK(p_seamldr_seamcall_lock);

static inline u64 p_seamldr_seamcall(u64 op, struct seamcall_regs_in *in,
				     struct seamcall_regs_out *out)
{
	u64 ret;

	/*
	 * P-SEAMLDR SEAMCALL also fails with VMFailInvalid when
	 * P-SEAMLDR is already busy with one SEAMCALL.  Use spinlock
	 * to prevent this case so VMFailInvalid can only happen when
	 * P-SEAMLDR is not loaded, to allow caller to identify such
	 * case.
	 */
	spin_lock(&p_seamldr_seamcall_lock);
	ret = seamcall(op, in, out);
	spin_unlock(&p_seamldr_seamcall_lock);

	return ret;
}

/*
 * P-SEAMLDR SEAMCALL leaf functions
 */
#define SEAMCALL_P_SEAMLDR_BASE		BIT_ULL(63)
#define P_SEAMCALL_SEAMLDR_INFO		(SEAMCALL_P_SEAMLDR_BASE | 0x0)

static inline u64 p_seamcall_seamldr_info(struct p_seamldr_info *info)
{
	struct seamcall_regs_in in;

	in.rcx = __pa(info);
	return p_seamldr_seamcall(P_SEAMCALL_SEAMLDR_INFO, &in, NULL);
}

static inline bool p_seamldr_ready(void)
{
	/*
	 * SEAMLDR_INFO.P_SEAMLDR_READY indicates whether P-SEAMLDR
	 * is (loaded and) ready for SEAMCALLs.  It is always set
	 * if SEAMLDR.INFO SEAMCALL was successful.
	 */
	return !!p_seamldr_info.p_seamldr_ready;
}

/**
 * detect_p_seamldr - Detect whether P-SEAMLDR has been loaded
 *
 * Detect whether P-SEAMLDR is loaded or not by BIOS, via calling
 * SEAMLDR.INFO SEAMCALL to get P-SEAMLDR information.  Caller must
 * ensure SEAMRR is enabled, and cpu is already in VMX operation,
 * otherwise #UD.
 *
 * Return: 0 if P-SEAMLDR has been loaded, otherwise -ENODEV.
 */
int detect_p_seamldr(void)
{
	u64 ret;

	ret = p_seamcall_seamldr_info(&p_seamldr_info);

	if (ret == -ENODEV) {
		pr_info("P-SEAMLDR is not loaded. TDX is not available\n");
		return ret;
	}

	/*
	 * SEAMLDR.INFO can only fail when &p_seamldr_info isn't a
	 * valid address or alignment isn't met, both of which are
	 * kernel bugs.  WARN_ON() in this case.
	 */
	if (WARN(ret, "SEAMLDR.INFO failed: 0x%llx\n", ret))
		return -EFAULT;

	pr_info("version 0x%x, vendor_id: 0x%x, build_date: %u, build_num %u, major %u, minor %u\n",
			p_seamldr_info.version, p_seamldr_info.vendor_id,
			p_seamldr_info.build_date, p_seamldr_info.build_num,
			p_seamldr_info.major, p_seamldr_info.minor);

	return 0;
}

/**
 * tdx_module_ready - Whether TDX module has been loaded
 *
 * Return whether TDX module has been loaded and ready for SEAMCALL.
 */
bool tdx_module_ready(void)
{
	/*
	 * SEAMLDR_INFO.SEAM_READY indicates whether TDX module
	 * is (loaded and) ready for SEAMCALL.
	 */
	return p_seamldr_ready() && !!p_seamldr_info.seam_ready;
}
