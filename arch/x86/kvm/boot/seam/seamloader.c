// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "seam: " fmt

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


#define INTEL_TDX_BOOT_TIME_SEAMCALL 1
#include "vmx/tdx_arch.h"
#include "vmx/tdx_ops.h"
#include "vmx/tdx_errno.h"
#include "seamloader.h"

#define MTRRCAP_SEAMRR	BIT(15)
#define SEAMLDR_MAX_NR_MODULE_PAGES	496

/* Seamcalls of p-seamldr cannot be called concurrently. */
static DEFINE_SPINLOCK(seamcall_seamldr_lock);

int seamldr_info(hpa_t seamldr_info)
{
	u64 ret;

	spin_lock(&seamcall_seamldr_lock);
	ret = __seamldr_info(seamldr_info);
	spin_unlock(&seamcall_seamldr_lock);

	if (TDX_ERR(ret, SEAMLDR_INFO, NULL))
		return -EIO;

	return 0;
}

int seamldr_install(hpa_t seamldr_params)
{
	u64 ret;

	spin_lock(&seamcall_seamldr_lock);
	ret = __seamldr_install(seamldr_params);
	spin_unlock(&seamcall_seamldr_lock);

	if (TDX_ERR(ret, SEAMLDR_INSTALL, NULL))
		return -EIO;

	return 0;
}

int seamldr_shutdown(void)
{
	u64 ret;

	spin_lock(&seamcall_seamldr_lock);
	ret = __seamldr_shutdown();
	spin_unlock(&seamcall_seamldr_lock);

	if (TDX_ERR(ret, SEAMLDR_SHUTDOWN, NULL))
		return -EIO;

	return 0;
}

/* The ACM and input params need to be below 4G. */
static phys_addr_t __init seam_alloc_lowmem(phys_addr_t size)
{
	return memblock_phys_alloc_range(size, PAGE_SIZE, 0, BIT_ULL(32));
}

phys_addr_t __init seam_alloc_mem(phys_addr_t size, phys_addr_t align)
{
	struct page *page;

	if (!slab_is_available())
		return memblock_phys_alloc(size, align);

	/* Ensure page allocator can meet the alignment requirement. */
	if (!IS_ALIGNED(PAGE_SIZE, align))
		return 0;

	page = alloc_pages(GFP_KERNEL, get_order(size));
	if (page)
		return __pa(page_address(page));
	else
		return 0;
}

void __init seam_free_mem(phys_addr_t addr, phys_addr_t size)
{
	if (!slab_is_available())
		memblock_free_early(addr, size);
	else
		free_pages((unsigned long)__va(addr), get_order(size));
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

struct seamldr_params * __init init_seamldr_params(void *module,
						   unsigned long module_size,
						   void *sigstruct,
						   unsigned long sigstruct_size)
{
	phys_addr_t module_pa, sigstruct_pa, params_pa;
	struct seamldr_params *params;
	int i;

	/* SEAM module must be 4K aligned, and less than 496 pages. */
	if (!module_size || !IS_ALIGNED(module_size, PAGE_SIZE) ||
	    module_size > SEAMLDR_MAX_NR_MODULE_PAGES * PAGE_SIZE) {
		pr_err("Invalid SEAM module size 0x%lx\n", module_size);
		return ERR_PTR(-EINVAL);
	}
	/* SEAM signature structure must be 0x200 DWORDS, which is 2048 bytes */
	if (sigstruct_size != 2048) {
		pr_err("Invalid SEAM signature structure size 0x%lx\n",
		       sigstruct_size);
		return ERR_PTR(-EINVAL);
	}

	params = ERR_PTR(-ENOMEM);
	/* SEAMLDR requires the SEAM module to be 4k aligned. */
	module_pa = seam_alloc_mem(module_size, PAGE_SIZE);
	if (!module_pa) {
		pr_err("Unable to allocate memory to copy SEAM module\n");
		goto out;
	}
	memcpy(__va(module_pa), module, module_size);

	/* SEAMLDR requires the sigstruct to be 4K aligned. */
	sigstruct_pa = seam_alloc_mem(sigstruct_size, PAGE_SIZE);
	if (!sigstruct_pa) {
		pr_err("Unable to allocate memory to copy sigstruct\n");
		goto free_seam_module;
	}
	memcpy(__va(sigstruct_pa), sigstruct, sigstruct_size);

	/*
	 * Allocate and initialize the SEAMLDR params.  Pages are passed in as
	 * a list of physical addresses.
	 */
	if (!slab_is_available())
		params_pa = seam_alloc_lowmem(PAGE_SIZE);
	else
		/* P-SEAMLDR doesn't request low memory. */
		params_pa = seam_alloc_mem(PAGE_SIZE, PAGE_SIZE);
	if (!params_pa) {
		pr_err("Unable to allocate memory for SEAMLDR_PARAMS\n");
		goto free_sigstruct;
	}

	params = __va(params_pa);
	memset(params, 0, PAGE_SIZE);
	params->sigstruct_pa = sigstruct_pa;
	params->module_pages = PFN_UP(module_size);
	for (i = 0; i < params->module_pages; i++)
		params->module_pa_list[i] = module_pa + i * PAGE_SIZE;

	return params;

free_sigstruct:
	seam_free_mem(sigstruct_pa, sigstruct_size);
free_seam_module:
	seam_free_mem(module_pa, module_size);
out:
	return params;
}

void __init free_seamldr_params(struct seamldr_params *params)
{
	seam_free_mem(params->sigstruct_pa, PAGE_SIZE);
	seam_free_mem(params->module_pa_list[0],
		      params->module_pages * PAGE_SIZE);
	seam_free_mem(__pa(params), PAGE_SIZE);
}

extern int __init launch_seamldr(unsigned long seamldr_pa,
				 unsigned long seamldr_size,
				 unsigned long params_pa);

int __init seam_load_module(void *seamldr, unsigned long seamldr_size,
			    const struct seamldr_params *params)
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
		seamldr_pa = seam_alloc_lowmem(seamldr_size);
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
	ret = launch_seamldr(seamldr_pa, seamldr_size, params ? __pa(params) : 0);
	if (ret == -EFAULT && !WARN_ON(!enteraccs_attempts--)) {
		udelay(1 * USEC_PER_MSEC);
		goto retry_enteraccs;
	}
	pr_info("Launch SEAMLDR returned %d\n", ret);

free:
	if (seamldr_pa != __pa(seamldr))
		memblock_free_early(seamldr_pa, seamldr_size);

	return ret;
}
