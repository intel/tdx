// SPDX-License-Identifier: GPL-2.0
/* common helper functions for the P-SEAMLDR and the TDX module to VMXON/VMXOFF */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/earlycpio.h>
#include <linux/memblock.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/slab.h>

#include <asm/virtext.h>
#include <asm/cpu.h>

#include "seam.h"

/*
 * In early boot phase before filesystem, request_firmware() isn't available yet
 * which relies on filesystem to find a file.  Instead traverse CPIO image.
 */
bool __init seam_get_firmware(struct cpio_data *blob, const char *name)
{
#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start) {
		*blob = find_cpio_file(name, (void *)initrd_start,
				initrd_end - initrd_start);
		if (blob->data)
			return true;
	}
#endif
	return false;
}

/*
 * is_seamrr_enabled - check if seamrr is supported.
 */
bool __init is_seamrr_enabled(void)
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

static u32 seam_vmxon_version_id __initdata;
static DEFINE_PER_CPU(struct vmcs *, seam_vmxon_region);

/*
 * This function must be called after init_ia32_feat_ctl() that sets
 * X86_FEATURE_VMX.
 */
int __init seam_init_vmx_early(void)
{
	u32 vmx_msr_low, vmx_msr_high;

	if (!this_cpu_has(X86_FEATURE_VMX))
		return -EOPNOTSUPP;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/*
	 * IA-32 SDM Vol 3C: VMCS size is never greater than 4kB.  The size of
	 * VMXON region is same to VMCS size.
	 */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

	seam_vmxon_version_id = vmx_msr_low;

	return 0;
}

/*
 * seam_init_vmxon_vmcs - initialize VMXON region with version id for this CPU.
 * @vmcs: vmxon region to initialize.  zero it before call.
 *
 * VMXON region has the same header format as the vmcs region.  It is assumed
 * that all CPUs have the same vmcs version.  The KVM kernel module has this
 * same assumption.  Even if the version differs, VMXON fails with
 * seam_vmxon_on_each_cpu() to catch it.
 */
void __init seam_init_vmxon_vmcs(struct vmcs *vmcs)
{
	vmcs->hdr.revision_id = seam_vmxon_version_id;
}

void __init seam_free_vmcs_tmp_set(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		/* It's safe to pass NULL to free_page() that ignores NULL. */
		free_page((unsigned long)per_cpu(seam_vmxon_region, cpu));
		per_cpu(seam_vmxon_region, cpu) = NULL;
	}
}

/*
 * seam_alloc_init_vmcs_tmp_set -
 *	allocate temporary one page for VMXON region for each CPU and stash
 *	pages to the per-cpu variable, seam_vmxon_region, and initialize those
 *	regions on each CPU for later VMXON.
 * @return: 0 on success, -ENOMEM on failure.
 *
 * Call this function before use of seam_vmxon_on_each_cpu() and
 * seam_vmxoff_on_each_cpu().
 *
 * Disable cpu hotplug by cpus_read_lock() and cpus_read_unlock() until
 * seam_free_vmcs_tmp_set().
 */
int __init seam_alloc_init_vmcs_tmp_set(void)
{
	int cpu;
	struct vmcs *vmxon_region;

	if (!this_cpu_has(X86_FEATURE_VMX))
		return -EOPNOTSUPP;

	for_each_online_cpu(cpu) {
		/* VMXON region must be 4K-aligned. */
		vmxon_region = (struct vmcs *)get_zeroed_page(GFP_KERNEL);
		if (!vmxon_region)
			goto err;
		seam_init_vmxon_vmcs(vmxon_region);
		per_cpu(seam_vmxon_region, cpu) = vmxon_region;
	}

	return 0;

err:
	seam_free_vmcs_tmp_set();
	return -ENOMEM;
}

static void __init seam_vmxon(void *data)
{
	atomic_t *error = data;
	int r;

	r = cpu_vmxon(__pa(this_cpu_read(seam_vmxon_region)));
	if (r)
		atomic_set(error, r);
}

int __init seam_vmxon_on_each_cpu(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxon, &error, 1);

	/*
	 * Check if any of the CPUs fail.  Don't care how many CPUs failed and
	 * about the exact error code.
	 */
	return atomic_read(&error);
}

static void __init seam_vmxoff(void *data)
{
	atomic_t *error = data;
	int r;

	r = cpu_vmxoff();
	if (r)
		atomic_set(error, r);
}

int __init seam_vmxoff_on_each_cpu(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxoff, &error, 1);

	/*
	 * Check if any of the CPUs fail.  Don't care how many CPUs failed and
	 * about the exact error code.
	 */
	return atomic_read(&error);
}
