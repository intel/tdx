// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "seam: " fmt

#include <linux/kvm_types.h>
#include <linux/types.h>
#include <linux/bits.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <asm/apic.h>
#include <asm/cpu.h>
#include <asm/delay.h>
#include <asm/kvm_boot.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/page_types.h>

#include "vmx/tdx_arch.h"
#include "seamloader.h"
#include "seamcall_boot.h"

/*
 * P-SEAMLDR API function leaves
 */
#define SEAMCALL_SEAMLDR_BASE          BIT_ULL(63)
#define SEAMCALL_SEAMLDR_INFO          SEAMCALL_SEAMLDR_BASE
#define SEAMCALL_SEAMLDR_INSTALL       (SEAMCALL_SEAMLDR_BASE | 1)
#define SEAMCALL_SEAMLDR_SHUTDOWN      (SEAMCALL_SEAMLDR_BASE | 2)

int seamldr_info(u64 seamldr_info)
{
	u64 ret;

	ret = seamcall_boot(SEAMLDR_INFO, seamldr_info, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

int seamldr_install(u64 seamldr_params)
{
	u64 ret;

	ret = seamcall_boot(SEAMLDR_INSTALL, seamldr_params, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

int seamldr_shutdown(void)
{
	u64 ret;

	ret = seamcall_boot(SEAMLDR_SHUTDOWN, 0, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

static bool __init is_seamrr_enabled(void)
{
	u64 mtrrcap, seamrr_base, seamrr_mask;

	if (!boot_cpu_has(X86_FEATURE_MTRR) ||
	    rdmsrl_safe(MSR_MTRRcap, &mtrrcap) || !(mtrrcap & MTRRCAP_SEAMRR))
		return 0;

	if (rdmsrl_safe(MSR_IA32_SEAMRR_PHYS_BASE, &seamrr_base) ||
	    !(seamrr_base & MSR_IA32_SEAMRR_PHYS_BASE_CONFIGURED)) {
		pr_info("SEAMRR base is not configured by BIOS\n");
		return 0;
	}

	if (rdmsrl_safe(MSR_IA32_SEAMRR_PHYS_MASK, &seamrr_mask) ||
	    !(seamrr_mask & MSR_IA32_SEAMRR_PHYS_MASK_ENABLED)) {
		pr_info("SEAMRR is not enabled by BIOS\n");
		return 0;
	}

	return 1;
}

int __init seam_load_module(void *seamldr, unsigned long seamldr_size)
{
	phys_addr_t seamldr_pa;
	int enteraccs_attempts = 10;
	u32 icr_busy;
	int ret;

	if (!is_seamrr_enabled())
		return -EOPNOTSUPP;

	if (!seamldr_size) {
		pr_err("Invalid SEAMLDR ACM size\n");
		return -EINVAL;
	}

	/* GETSEC[EnterACCS] requires the ACM to be 4k aligned and below 4G. */
	seamldr_pa = __pa(seamldr);
	if (seamldr_pa >= BIT_ULL(32) || !IS_ALIGNED(seamldr_pa, 4096)) {
		seamldr_pa = memblock_phys_alloc_range(PAGE_SIZE, PAGE_SIZE, 0,
						       BIT_ULL(32));
		if (!seamldr_pa)
			return -ENOMEM;
		memcpy(__va(seamldr_pa), seamldr, seamldr_size);
	}

	ret = -EIO;
	/* Ensure APs are in WFS. */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_INT_ASSERT |
		       APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto free;

	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto free;
	mb();

retry_enteraccs:
	ret = launch_seamldr(seamldr_pa, seamldr_size);
	if (ret == -EFAULT && !WARN_ON(!enteraccs_attempts--)) {
		/*
		 * Gracefully handle #GPs on ENTERACCS due to APs not in WFS
		 *
		 * ENTERACCS requires APs to be in WFS, but doesn't provide any
		 * way for software to confirm APs are in WFS, i.e. try-catch is
		 * sadly the most optimal approach.
		 */
		udelay(1 * USEC_PER_MSEC);
		goto retry_enteraccs;
	}
	pr_info("Launch SEAMLDR returned %d\n", ret);

free:
	if (seamldr_pa != __pa(seamldr))
		memblock_free_early(seamldr_pa, seamldr_size);

	return ret;
}
