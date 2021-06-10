// SPDX-License-Identifier: GPL-2.0
/* C-wrapper functions for P-SEAMLDR SEAMCALLs and functions for P-SEAMLDR */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/earlycpio.h>
#include <linux/kvm_types.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/cpu.h>

#include <asm/seamcall.h>
#include <asm/delay.h>
#include <asm/apic.h>
#include <asm/cmdline.h>
#include <asm/virtext.h>

#include "seamcall-boot.h"
#include "p-seamldr.h"
#include "seam.h"

static char np_seamldr_name[128] __initdata = "intel-seam/np-seamldr.acm";

static int __init seamldr_param(char *str)
{
	strscpy(np_seamldr_name, str, sizeof(np_seamldr_name));
	return 0;
}
early_param("np_seamldr", seamldr_param);

int seamldr_info(phys_addr_t seamldr_info)
{
	u64 ret;

	ret = seamcall_boot(SEAMCALL_SEAMLDR_INFO, seamldr_info, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

int seamldr_install(phys_addr_t seamldr_params)
{
	u64 ret;

	ret = seamcall_boot(SEAMCALL_SEAMLDR_INSTALL, seamldr_params, 0, 0, 0,
			    NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

int seamldr_shutdown(void)
{
	u64 ret;

	ret = seamcall_boot(SEAMCALL_SEAMLDR_SHUTDOWN, 0, 0, 0, 0, NULL);
	if (WARN_ON_ONCE(ret))
		return -EIO;
	return 0;
}

/*
 * is_seamrr_enabled - check if seamrr is supported.
 */
static bool __init is_seamrr_enabled(void)
{
	u64 mtrrcap, seamrr_base, seamrr_mask;

	if (!boot_cpu_has(X86_FEATURE_MTRR) ||
	    rdmsrl_safe(MSR_MTRRcap, &mtrrcap) || !(mtrrcap & MTRRCAP_SEAMRR))
		return false;

	if (rdmsrl_safe(MSR_IA32_SEAMRR_PHYS_BASE, &seamrr_base) ||
	    !(seamrr_base & MSR_IA32_SEAMRR_PHYS_BASE_CONFIGURED)) {
		pr_info("SEAMRR base is not configured by BIOS\n");
		return false;
	}

	if (rdmsrl_safe(MSR_IA32_SEAMRR_PHYS_MASK, &seamrr_mask) ||
	    !(seamrr_mask & MSR_IA32_SEAMRR_PHYS_MASK_ENABLED)) {
		pr_info("SEAMRR is not enabled by BIOS\n");
		return false;
	}

	return true;
}

asmlinkage u64 __init np_seamldr_launch(unsigned long seamldr_pa,
					unsigned long seamldr_size);

/*
 * p_seamldr_load - load P-SEAMLDR by invoking NP-SEAMLDR ACM.
 * @np_seamldr: cpio data to np_sealdr image
 * @return: 0 on success, error code on failure.
 *
 * Put all APs into Wait-For-SIPI state and then, launch Authenticated Code
 * Module(ACM) by GETSEC[ENTERACC] on BSP.  It's caller's responsibility to
 * ensure that all the APs are okay to receive INIT.  i.e. call this function
 * before SMP initialization smp_init(). (or ensure all the APs are offline with
 * cpu lock held.)
 *
 * KASAN think memcpy from initrd image via cpio_data invalid access.
 */
static int __init __no_sanitize_address
p_seamldr_load(struct cpio_data *np_seamldr)
{
	unsigned long np_seamldr_size = np_seamldr->size;
	unsigned long np_seamldr_va;
	phys_addr_t np_seamldr_pa;
	int enteraccs_attempts = 10;
	u32 icr_busy;
	int ret;
	u64 err;

	if (!np_seamldr_size) {
		pr_info("Invalid NP-SEAMLDR ACM size\n");
		return -EINVAL;
	}

	/* GETSEC[EnterACCS] requires the ACM to be 4k aligned and below 4G. */
	np_seamldr_va = __get_free_pages(GFP_KERNEL | __GFP_ZERO | __GFP_DMA32,
					 get_order(np_seamldr_size));
	if (!np_seamldr_va) {
		ret = -ENOMEM;
		goto out;
	}
	np_seamldr_pa = __pa(np_seamldr_va);
	memcpy((void *)np_seamldr_va, np_seamldr->data, np_seamldr->size);

	/*
	 * Because this is early boot phase, it's assumed that VMX isn't enabled
	 * yet.  SEAMLDR spec requires VMXOFF on all LPs.
	 *
	 * SEAMLDR spec Chapter 2 step 4
	 * 4. The NP-SEAMLDR ACM also requires that the OS/VMM loader has
	 * invoked the shutdown function provided by the Intel P-SEAMLDR module
	 * (if it was previously installed), and VMXOFF has been executed on all
	 * logical processors in the platform.
	 */
	WARN_ON(__read_cr4() & X86_CR4_VMXE);
	WARN_ON(cr4_read_shadow() & X86_CR4_VMXE);

	ret = -EIO;
	/* Ensure APs are in WFS. */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_INT_ASSERT |
		       APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto out;

	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto out;
	mb();

	while (1) {
		int i;
		/*
		 * np_seamldr_launch() doesn't save/restore following MSRs
		 * because it doesn't know whether they are available or not.
		 */
		struct {
			u64 val;
			int err;
			int msr;
		} *msr, msrs[] = {
			{ .msr = MSR_IA32_DEBUGCTLMSR },
			{ .msr = MSR_CORE_PERF_GLOBAL_CTRL },
			{ .msr = MSR_IA32_PEBS_ENABLE },
			{ .msr = MSR_IA32_RTIT_CTL },
			{ .msr = MSR_ARCH_LBR_CTL },
		};

		for (i = 0; i < ARRAY_SIZE(msrs); i++) {
			msr = &msrs[i];
			msr->err = rdmsrl_safe(msr->msr, &msr->val);
		}

		err = np_seamldr_launch(np_seamldr_pa, np_seamldr_size);

		for (i = 0; i < ARRAY_SIZE(msrs); i++) {
			msr = &msrs[i];
			if (!msr->err) {
				msr->err = wrmsrl_safe(msr->msr, msr->val);
				if (!err)
					err = msr->err;
			}
		}

		/* P_SEAMLDR was already loaded. */
		if (err == NP_SEAMLDR_EMODBUSY) {
			err = 0;
			break;
		}

		/*
		 * Gracefully handle #GPs on ENTERACCS due to APs not in WFS
		 *
		 * ENTERACCS requires APs to be in WFS, but doesn't provide any
		 * way for software to confirm APs are in WFS, i.e. try-catch is
		 * sadly the most optimal approach.
		 *
		 * NP_SEAMLDR_EUNSPECERR: entropy is lacking.
		 */
		if (!((err == -EFAULT || err == NP_SEAMLDR_EUNSPECERR) &&
		      !WARN_ON(!enteraccs_attempts--)))
			break;
		udelay(1 * USEC_PER_MSEC);
	}
	pr_info("Launch NP-SEAMLDR returned 0x%llx\n", err);
	ret = err ? -EIO : 0;

out:
	if (np_seamldr_va)
		free_pages(np_seamldr_va, get_order(np_seamldr_size));
	return ret;
}

static struct p_seamldr_info *p_seamldr_info;

static int __init p_seamldr_get_info(void)
{
	int err = 0;
	int vmxoff = 0;
	struct vmcs *vmcs = NULL;

	BUILD_BUG_ON((PAGE_SIZE % P_SEAMLDR_INFO_ALIGNMENT) != 0);
	p_seamldr_info = (struct p_seamldr_info *)__get_free_pages(
		GFP_KERNEL | __GFP_ZERO, get_order(sizeof(*p_seamldr_info)));
	if (!p_seamldr_info)
		return -ENOMEM;

	/* P-SEAMLDR executes in SEAM VMX-root that requires VMXON. */
	vmcs = (struct vmcs *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!vmcs) {
		err = -ENOMEM;
		goto out;
	}
	err = seam_init_vmxon_vmcs(vmcs);
	if (err)
		goto out;
	/* Because it's before kvm_init, VMX shouldn't be enabled. */
	WARN_ON(cr4_read_shadow() & X86_CR4_VMXE);
	err = cpu_vmxon(__pa(vmcs));
	if (err)
		goto out;

	err = seamldr_info(__pa(p_seamldr_info));

	vmxoff = cpu_vmxoff();
	if (!err && vmxoff)
		err = vmxoff;
	if (err)
		goto out;

	pr_info("TDX P-SEAMLDR: version 0x%0x attributes 0x%0x vendor_id 0x%x "
		"build_date %d build_num 0x%x minor 0x%x major 0x%x.\n",
		p_seamldr_info->version, p_seamldr_info->attributes,
		p_seamldr_info->vendor_id, p_seamldr_info->build_date,
		p_seamldr_info->build_num,
		p_seamldr_info->minor, p_seamldr_info->major);

out:
	if (vmcs)
		free_pages((unsigned long)vmcs, get_order(seam_vmxon_size));
	if (err) {
		free_pages((unsigned long)p_seamldr_info,
			   get_order(sizeof(*p_seamldr_info)));
		p_seamldr_info = NULL;
	}
	return err;
}

/*
 * tdx_p_seamldr_init() - load P-SEAMLDR
 *
 * Call this function
 *  - only BSP is running before bringing up all APs by smp_init().
 *  - after MTRR is setup for BSP.
 *  - after mcheck is ready.
 */
int __init load_p_seamldr(void)
{
	int err;
	struct cpio_data np_seamldr;

	/* SEAM mode is needed for TDX. */
	if (!is_seamrr_enabled())
		return 0;
	/* VMX is needed for TDX. */
	if (seam_init_vmx_early())
		return 0;

	/*
	 *  Optin-option because it requires memory overhead to load TDX module.
	 */
	if (!cmdline_find_option_bool(boot_command_line, "enable_tdx_host"))
		return 0;

	if (!seam_get_firmware(&np_seamldr, np_seamldr_name)) {
		pr_err("no NP-SEAMLDR found\n");
		return -ENOENT;
	}

	err = p_seamldr_load(&np_seamldr);
	if (err) {
		pr_err("failed to load TDX P-SEAMLDR\n");
		return err;
	}

	err = p_seamldr_get_info();
	if (err) {
		pr_err("failed to get TDX P-SEAMLDR info\n");
		return err;
	}

	setup_force_cpu_cap(X86_FEATURE_SEAM);
	pr_info("Successfully loaded TDX P-SEAMLDR.\n");

	return 0;
}
