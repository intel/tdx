// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "seam: " fmt

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/memblock.h>
#include <asm/apic.h>
#include <asm/cpu.h>
#include <asm/delay.h>
#include <asm/kvm_boot.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/page_types.h>


#include "seamloader.h"

#define MTRRCAP_SEAMRR	BIT(15)
#define SEAMLDR_MAX_NR_MODULE_PAGES	496

struct seamldr_params {
	u32 version;
	u32 scenario;
	u64 sigstruct_pa;
	u8 reserved[104];
	u64 module_pages;
	u64 module_pa_list[SEAMLDR_MAX_NR_MODULE_PAGES];
} __packed __aligned(PAGE_SIZE);

/* The ACM and input params need to be below 4G. */
static phys_addr_t __init seam_alloc_lowmem(phys_addr_t size)
{
	return memblock_phys_alloc_range(size, PAGE_SIZE, 0, BIT_ULL(32));
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

extern int __init launch_seamldr(unsigned long seamldr_pa,
				 unsigned long seamldr_size,
				 unsigned long params_pa);

int __init seam_load_module(void *module, unsigned long module_size,
			    void *sigstruct, unsigned long sigstruct_size,
			    void *seamldr, unsigned long seamldr_size)
{
	phys_addr_t module_pa, sigstruct_pa, seamldr_pa, params_pa;
	struct seamldr_params *params;
	int enteraccs_attempts = 10;
	u32 icr_busy;
	int ret;
	u64 i;

	if (!is_seamrr_enabled())
		return -ENOTSUPP;

	/* SEAM module must be 4K aligned, and less than 496 pages. */
	if (!module_size || !IS_ALIGNED(module_size, PAGE_SIZE) ||
	    module_size > SEAMLDR_MAX_NR_MODULE_PAGES * PAGE_SIZE) {
		pr_err("Invalid SEAM module size 0x%lx\n", module_size);
		return -EINVAL;
	}
	/* SEAM signature structure must be 0x200 DWORDS, which is 2048 bytes */
	if (sigstruct_size != 2048) {
		pr_err("Invalid SEAM signature structure size 0x%lx\n",
		       sigstruct_size);
		return -EINVAL;
	}
	if (!seamldr_size) {
		pr_err("Invalid SEAMLDR ACM size\n");
		return -EINVAL;
	}

	ret = -ENOMEM;
	/* SEAMLDR requires the SEAM module to be 4k aligned. */
	module_pa = __pa(module);
	if (!IS_ALIGNED(module_pa, 4096)) {
		module_pa = memblock_phys_alloc(module_size, PAGE_SIZE);
		if (!module_pa) {
			pr_err("Unable to allocate memory to copy SEAM module\n");
			goto out;
		}
		memcpy(__va(module_pa), module, module_size);
	}

	/* SEAMLDR requires the sigstruct to be 4K aligned. */
	sigstruct_pa = __pa(sigstruct);
	if (!IS_ALIGNED(sigstruct_pa, 4096)) {
		sigstruct_pa = memblock_phys_alloc(sigstruct_size, PAGE_SIZE);
		if (!sigstruct_pa) {
			pr_err("Unable to allocate memory to copy sigstruct\n");
			goto free_seam_module;
		}
		memcpy(__va(sigstruct_pa), sigstruct, sigstruct_size);
	}

	/* GETSEC[EnterACCS] requires the ACM to be 4k aligned and below 4G. */
	seamldr_pa = __pa(seamldr);
	if (seamldr_pa >= BIT_ULL(32) || !IS_ALIGNED(seamldr_pa, 4096)) {
		seamldr_pa = seam_alloc_lowmem(seamldr_size);
		if (!seamldr_pa)
			goto free_sigstruct;
		memcpy(__va(seamldr_pa), seamldr, seamldr_size);
	}

	/*
	 * Allocate and initialize the SEAMLDR params.  Pages are passed in as
	 * a list of physical addresses.
	 */
	params_pa = seam_alloc_lowmem(PAGE_SIZE);
	if (!params_pa) {
		pr_err("Unable to allocate memory for SEAMLDR_PARAMS\n");
		goto free_seamldr;
	}

	ret = -EIO;
	/* Ensure APs are in WFS. */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_INT_ASSERT |
		       APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto free_params;

	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto free_params;
	mb();

	params = __va(params_pa);
	memset(params, 0, PAGE_SIZE);
	params->sigstruct_pa = sigstruct_pa;
	params->module_pages = PFN_UP(module_size);
	for (i = 0; i < params->module_pages; i++)
		params->module_pa_list[i] = module_pa + i * PAGE_SIZE;

retry_enteraccs:
	ret = launch_seamldr(seamldr_pa, seamldr_size, params_pa);
	if (ret == -EFAULT && !WARN_ON(!enteraccs_attempts--)) {
		udelay(1 * USEC_PER_MSEC);
		goto retry_enteraccs;
	}
	pr_info("Launch SEAMLDR returned %d\n", ret);

free_params:
	memblock_free_early(params_pa, PAGE_SIZE);
free_seamldr:
	if (seamldr_pa != __pa(seamldr))
		memblock_free_early(seamldr_pa, seamldr_size);
free_sigstruct:
	if (sigstruct_pa != __pa(sigstruct))
		memblock_free_early(sigstruct_pa, sigstruct_size);
free_seam_module:
	if (module_pa != __pa(module))
		memblock_free_early(module_pa, module_size);
out:
	return ret;
}
