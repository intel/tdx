// SPDX-License-Identifier: GPL-2.0
/* C-wrapper functions for P-SEAMLDR SEAMCALLs and functions for P-SEAMLDR */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/earlycpio.h>
#include <linux/memblock.h>
#include <linux/slab.h>

#include <asm/debugreg.h>
#include <asm/cmdline.h>
#include <asm/delay.h>
#include <asm/apic.h>
#include <asm/virtext.h>
#include <asm/trapnr.h>
#include <asm/perf_event.h>

#include "../../events/perf_event.h"
#include "p-seamldr.h"
#include "seamcall.h"
#include "seam.h"

static char *np_seamldr_name __initdata = "intel-seam/np-seamldr.acm";
static size_t np_seamldr_len __initdata;

static int __init seamldr_param(char *str)
{
	np_seamldr_len = strlen(str) + 1;

	np_seamldr_name = memblock_alloc(np_seamldr_len, 0);
	if (!np_seamldr_name) {
		np_seamldr_len = 0;
		return -ENOMEM;
	}

	strscpy(np_seamldr_name, str, np_seamldr_len);
	return 0;
}
early_param("np_seamldr", seamldr_param);

int seamldr_info(phys_addr_t seamldr_info)
{
	u64 ret;

	ret = seamcall(SEAMCALL_SEAMLDR_INFO, seamldr_info, 0, 0, 0, NULL);
	if (ret) {
		pr_err("SEAMCALL[SEAMLDR_INFO] failed %s (0x%llx)\n",
		       p_seamldr_error_name(ret), ret);
		return -EIO;
	}
	return 0;
}

int seamldr_install(phys_addr_t seamldr_params)
{
	u64 ret;

	ret = seamcall(SEAMCALL_SEAMLDR_INSTALL, seamldr_params, 0, 0, 0, NULL);
	if (ret) {
		pr_err_ratelimited(
			"SEAMCALL[SEAMLDR_INSTALL] failed %s (0x%llx)\n",
			p_seamldr_error_name(ret), ret);
		return -EIO;
	}
	return 0;
}

/*
 * is_seamrr_enabled - check if seamrr is supported.
 */
static bool __init is_seamrr_enabled(void)
{
	u64 mtrrcap, seamrr_base, seamrr_mask;

	if (!boot_cpu_has(X86_FEATURE_MTRR))
		return false;

	/* MTRRcap.SEAMRR indicates the support of SEAMRR_PHYS_{BASE, MASK} */
	rdmsrl(MSR_MTRRcap, mtrrcap);
	if (!(mtrrcap & MTRRCAP_SEAMRR))
		return false;

	rdmsrl(MSR_IA32_SEAMRR_PHYS_BASE, seamrr_base);
	if (!(seamrr_base & MSR_IA32_SEAMRR_PHYS_BASE_CONFIGURED)) {
		pr_info("SEAMRR base is not configured by BIOS\n");
		return false;
	}

	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, seamrr_mask);
	if (!(seamrr_mask & MSR_IA32_SEAMRR_PHYS_MASK_ENABLED)) {
		pr_info("SEAMRR is not enabled by BIOS\n");
		return false;
	}

	return true;
}

/*
 * The NP-SEAMLDR returns with the clobbered CS/SS with the flat cached
 * descriptors.  If NMI happens before restoring segment selectors, the
 * clobbered values of CS/SS are saved and the following iret tries to re-load
 * the clobbered segment selector to trigger #GP.  Correct the saved CS/SS so
 * that iret loads the intended segment selectors.
 */
extern unsigned long np_seamldr_saved_cr4 __initdata;

static int __init np_seamldr_die_notify(struct notifier_block *nb,
					unsigned long cmd, void *args)
{
	struct die_args *die_args = args;
	struct pt_regs *regs = die_args->regs;

	if (cmd == DIE_TRAP && die_args->trapnr == X86_TRAP_UD &&
	    np_seamldr_saved_cr4) {
		/*
		 * #UD on rdfsbase/wrfsbase due to CR4.FSGSBASE = 0. Forcibly
		 * restore CR4 to the saved one.
		 * cr4_set_bits() doesn't work as it checks shadowed CR4 because
		 * The NP-SEAMLDR clobbers CR4 outside of shadowed CR4.
		 */
		__write_cr4(np_seamldr_saved_cr4);
		/*
		 * Saved CS is clobbered value by NP-SEAMLDR.  Store correct
		 * value.
		 */
		regs->cs = __KERNEL_CS;
		/* SS is zero. no need to correct. */
		return NOTIFY_STOP;
	}

	if (cmd == DIE_GPF && die_args->trapnr == X86_TRAP_GP &&
	    np_seamldr_saved_cr4) {
		/*
		 * iretq in nmi_restore causes #GP due to clobbered %CS/%SS.
		 * Correct them.
		 */
		struct iretq_frame {
			unsigned long ip;
			unsigned long cs;
			unsigned long flags;
			unsigned long sp;
			unsigned long ss;
		};
		struct iretq_frame *iret = (struct iretq_frame *)regs->sp;

		regs->cs = __KERNEL_CS;
		iret->cs = __KERNEL_CS;
		iret->ss = __KERNEL_DS;
		return NOTIFY_STOP;
	}

	return NOTIFY_DONE;
}

static struct notifier_block np_seamldr_die_notifier __initdata = {
	.notifier_call = np_seamldr_die_notify,
};

asmlinkage u64 __init np_seamldr_launch(unsigned long seamldr_pa,
					unsigned long seamldr_size);

static u64 __init __p_seamldr_load(void *np_seamldr,
				unsigned long np_seamldr_size)
{
	/*
	 * The NP-SEAMLDR will clobber some MSRs and DR7.  Save and restore
	 * them.
	 */
	unsigned long debugctlmsr;

	bool has_core_perf_global_ctrl = false;
	union cpuid10_eax eax;
	unsigned long core_perf_global_ctrl;

	bool has_pebs_enable = false;
	union perf_capabilities perf_cap;
	unsigned long pebs_enable;

	unsigned long rtit_ctl;
	unsigned long arch_lbr;
	unsigned long misc_enable;
	unsigned long efer;
	unsigned long cr_pat;
	unsigned long dr7;

	u64 err;

	debugctlmsr = get_debugctlmsr();
	if (boot_cpu_has(X86_FEATURE_ARCH_PERFMON)) {
		eax.full = cpuid_eax(0xa);
		if (eax.split.version_id > 0) {
			has_core_perf_global_ctrl = true;
			rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, core_perf_global_ctrl);
		}
	}
	if (boot_cpu_has(X86_FEATURE_PDCM)) {
		rdmsrl(MSR_IA32_PERF_CAPABILITIES, perf_cap.capabilities);
		if (perf_cap.pebs_baseline) {
			has_pebs_enable = true;
			rdmsrl(MSR_IA32_PEBS_ENABLE, pebs_enable);
		}
	}
	if (boot_cpu_has(X86_FEATURE_INTEL_PT))
		rdmsrl(MSR_IA32_RTIT_CTL, rtit_ctl);
	if (boot_cpu_has(X86_FEATURE_ARCH_LBR))
		rdmsrl(MSR_ARCH_LBR_CTL, arch_lbr);
	rdmsrl(MSR_IA32_MISC_ENABLE, misc_enable);
	rdmsrl(MSR_EFER, efer);
	rdmsrl(MSR_IA32_CR_PAT, cr_pat);
	dr7 = local_db_save();

	err = np_seamldr_launch(__pa(np_seamldr), np_seamldr_size);

	local_db_restore(dr7);
	wrmsrl(MSR_IA32_CR_PAT, cr_pat);
	wrmsrl(MSR_EFER, efer);
	wrmsrl(MSR_IA32_MISC_ENABLE, misc_enable);
	update_debugctlmsr(debugctlmsr);
	if (has_core_perf_global_ctrl)
		wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, core_perf_global_ctrl);
	if (has_pebs_enable)
		wrmsrl(MSR_IA32_PEBS_ENABLE, pebs_enable);
	if (boot_cpu_has(X86_FEATURE_INTEL_PT))
		wrmsrl(MSR_IA32_RTIT_CTL, rtit_ctl);
	if (boot_cpu_has(X86_FEATURE_ARCH_LBR))
		wrmsrl(MSR_ARCH_LBR_CTL, arch_lbr);

	return err;
}

/*
 * p_seamldr_load - load the P-SEAMLDR by launching the NP-SEAMLDR ACM.
 * @np_seamldr: cpio data to np_sealdr image
 * @return: 0 on success, error code on failure.
 *
 * Put all APs into Wait-For-SIPI state and then, launch Authenticated Code
 * Module(ACM) by invoking GETSEC[EnterACCS] on BSP.  It's caller's
 * responsibility to ensure that all the APs are safe to receive INIT.
 * Call this function before SMP initialization smp_init() (or ensure all
 * the APs are offline with CPU lock held.)
 *
 * KASAN thinks that memcpy from initrd image via cpio_data is invalid access
 * because the boot loader allocates the region of initrd image.  Not by the
 * kernel memory allocator.  Add the annotation of __no_sanitize_address to
 * apiece KASAN.
 */
static int __init __no_sanitize_address
p_seamldr_load(struct cpio_data *cpio_np_seamldr)
{
	unsigned long np_seamldr_size = cpio_np_seamldr->size;
	void *np_seamldr;
	u32 icr_busy;
	int enteraccs_attempts = 10;
	int ret;
	u64 err;

	if (!np_seamldr_size) {
		pr_info("Invalid NP-SEAMLDR ACM size\n");
		return -EINVAL;
	}

	/* GETSEC[EnterACCS] requires the ACM to be 4k aligned and below 4G. */
	np_seamldr = alloc_pages_exact(np_seamldr_size,
				GFP_KERNEL | __GFP_DMA32);
	if (!np_seamldr) {
		pr_info("failed to allocate memory for NP-SEAMLDR ACM. size 0x%lx\n",
			np_seamldr_size);
		return -ENOMEM;
	}

	/*
	 * KASAN thinks that (cpio_np_seamldr->data, cpio_np_seamldr->data)
	 * is invalid address because the region comes from the initrd placed
	 * by boot loader, not by the kernel memory allocator.
	 */
	memcpy(np_seamldr, cpio_np_seamldr->data, np_seamldr_size);

	/*
	 * Because this is early boot phase, it's assumed that VMX isn't enabled
	 * yet. (kvm_intel.ko isn't loaded yet.) SEAMLDR spec requires VMXOFF on
	 * all LPs.
	 *
	 * When normal (re)boot, VMX is off as reset value..  Also in kexec
	 * case, VMX is also disabled by cpu_emergency_vmxoff() on reboot.
	 */
	WARN_ON(__read_cr4() & X86_CR4_VMXE);

	ret = -EIO;
	/* Ensure APs are in Wait-For-SIPI. */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_INT_ASSERT |
		       APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto out;

	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto out;

	ret = register_die_notifier(&np_seamldr_die_notifier);
	if (ret)
		goto out_unregister;

	while (1) {
		err = __p_seamldr_load(np_seamldr, np_seamldr_size);

		/*
		 * P_SEAMLDR was already loaded.  For example in the case of
		 * kexec reboot.  Re-use the already loaded one.
		 */
		if (err == NP_SEAMLDR_EMODBUSY) {
			pr_info("P-SEAMLDR was already loaded. reusing it.\n");
			err = 0;
			break;
		}

		/*
		 * Gracefully handle special error cases.
		 * - NP_SEAMLDR_EUNSPECERR: entropy is lacking.
		 * - -EFAULT: #GPs on EnterACCS due to APs not in Wait-For-SIPI
		 *    state.  EnterACCS requires APs to be in Wait-For-SIPI
		 *    state, but doesn't provide any way for software to confirm
		 *    APs are in Wait-For-SIPI state, i.e. try-catch is sadly
		 *    the most optimal approach.
		 */
		if (err != NP_SEAMLDR_EUNSPECERR && err != -EFAULT)
			break;

		/* reach retry limit */
		if (WARN_ON(!enteraccs_attempts--))
			break;

		/*
		 * Wait for APs to be in Wait-For-SIPI state or for enough
		 * entropy.
		 */
		udelay(1 * USEC_PER_MSEC);
	}
	pr_info("Launch NP-SEAMLDR returned 0x%llx\n", err);
	ret = err ? -EIO : 0;

out_unregister:
	unregister_die_notifier(&np_seamldr_die_notifier);
out:
	free_pages_exact(np_seamldr, np_seamldr_size);
	return ret;
}

static struct p_seamldr_info *p_seamldr_info;

static int __init p_seamldr_get_info(void)
{
	struct vmcs *vmcs = NULL;
	int vmxoff_err = 0;
	int err = 0;

	BUILD_BUG_ON((sizeof(*p_seamldr_info) % P_SEAMLDR_INFO_ALIGNMENT) != 0);
	p_seamldr_info = kmalloc(sizeof(*p_seamldr_info), GFP_KERNEL);
	if (!p_seamldr_info)
		return -ENOMEM;

	/* P-SEAMLDR executes in SEAM VMX-root that requires VMXON. */
	vmcs = (struct vmcs *)get_zeroed_page(GFP_KERNEL);
	if (!vmcs) {
		err = -ENOMEM;
		goto out;
	}
	seam_init_vmxon_vmcs(vmcs);

	/* Because it's before kvm_init, VMX shouldn't be enabled. */
	WARN_ON(__read_cr4() & X86_CR4_VMXE);
	err = cpu_vmxon(__pa(vmcs));
	if (err)
		goto out;

	err = seamldr_info(__pa(p_seamldr_info));

	/*
	 * Other initialization codes expect that no one else uses VMX and that
	 * VMX is off.  Disable VMX to keep such assumptions.
	 */
	vmxoff_err = cpu_vmxoff();
	if (!err && vmxoff_err)
		err = vmxoff_err;
	if (err)
		goto out;

	pr_info("TDX P-SEAMLDR: version 0x%0x attributes 0x%0x vendor_id 0x%x "
		"build_date %d build_num 0x%x minor 0x%x major 0x%x.\n",
		p_seamldr_info->version, p_seamldr_info->attributes,
		p_seamldr_info->vendor_id, p_seamldr_info->build_date,
		p_seamldr_info->build_num,
		p_seamldr_info->minor, p_seamldr_info->major);
out:
	free_page((unsigned long)vmcs);	/* free_page() ignores NULL */

	/* On success, keep p_seamldr_info to export the info via sysfs. */
	if (err) {
		kfree(p_seamldr_info);
		p_seamldr_info = NULL;
	}
	return err;
}

/*
 * load_p_seamldr() - load P-SEAMLDR
 *
 * Call this function
 *  - only BSP is running before bringing up all APs by smp_init().
 *  - after MTRR is setup for BSP.
 *  - after mcheck is ready.
 */
int __init load_p_seamldr(void)
{
	struct cpio_data np_seamldr;
	int err;

	/* TDX requires SEAM mode. */
	if (!is_seamrr_enabled())
		return -EOPNOTSUPP;

	/* TDX requires VMX. */
	err = seam_init_vmx_early();
	if (err)
		return err;

	if (!seam_get_firmware(&np_seamldr, np_seamldr_name)) {
		pr_err("no NP-SEAMLDR found %s\n", np_seamldr_name);
		return -ENOENT;
	}

	pr_info("Loading TDX P-SEAMLDR %s.\n", np_seamldr_name);
	err = p_seamldr_load(&np_seamldr);
	if (np_seamldr_len)
		memblock_free_late(__pa(np_seamldr_name), np_seamldr_len);
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
