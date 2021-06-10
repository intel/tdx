// SPDX-License-Identifier: GPL-2.0
/* common helper functions for P-SEAMLDR and TDX module. */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/earlycpio.h>
#include <linux/init.h>
#include <linux/initrd.h>

#include <asm/virtext.h>
#include <asm/cpu.h>

#include "seam.h"

bool __init seam_get_firmware(struct cpio_data *blob, const char *name)
{
	char path[128];
	long offset;
	void *data;
	size_t size;
	static const char * const search_path[] = {
		"lib/firmware/%s",
		"usr/lib/firmware/%s",
		"opt/intel/%s"
	};
	int i;

	if (get_builtin_firmware(blob, name))
		return true;

	if (!IS_ENABLED(CONFIG_BLK_DEV_INITRD) || !initrd_start)
		return false;

	for (i = 0; i < ARRAY_SIZE(search_path); i++) {
		offset = 0;
		data = (void *)initrd_start;
		size = initrd_end - initrd_start;
		snprintf(path, sizeof(path), search_path[i], name);
		while (size > 0) {
			*blob = find_cpio_data(path, data, size, &offset);

			/* find the filename, the returned blob name is empty */
			if (blob->data && blob->name[0] == '\0')
				return true;

			if (!blob->data)
				break;

			/* match the item with the same path prefix, skip it*/
			data += offset;
			size -= offset;
		}
	}

	return false;
}

/*
 * page for VMXON for each CPUs.  Because SEAMCALLs requires VMX enabled, vmxon
 * before SEAMCALLs if necessary and vmxoff after SEAMCALLs if VMX was enabled.
 */
int seam_vmxon_size __initdata;
static int seam_vmxon_order __initdata;
static u32 seam_vmxon_version_id __initdata;
static DEFINE_PER_CPU(unsigned long, seam_vmxon_vmcs);

static int __init msr_vmx_basic(int *vmcs_size, u32 *version_id)
{
	u64 msr;

	/*
	 * Can't enable TDX if VMX is unsupported or disabled by BIOS.
	 * cpu_has(X86_FEATURE_VMX) can be used after identify_boot_cpu() or
	 * identify_secondary_cpu(). which eventually calls init_ia32_feat_ctl()
	 * that sets up X86_FEATURE_VMX.
	 */
	if (!this_cpu_has(X86_FEATURE_VMX))
		return -EOPNOTSUPP;

	if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &msr))
		return -EOPNOTSUPP;

	*vmcs_size = (msr >> 32) & 0x1fff;
	*version_id = (u32)msr;

	return 0;
}

/*
 * seam_init_vmx_early - check if VMX is available and get basic parameters to
 *                       enable VMX at early boot phase.
 * @return: 0 on success, error code on failure.
 *
 * Call this function before using related seam vmx functions at early phase
 * before SMP.  After SMP is initialized, use seam_init_vmcs() with
 * seam_alloc_vmcs/seam_free_vmcs().
 */
int __init seam_init_vmx_early(void)
{
	int ret;

	ret = msr_vmx_basic(&seam_vmxon_size, &seam_vmxon_version_id);
	if (ret)
		return ret;
	seam_vmxon_order = get_order(seam_vmxon_size);
	return 0;
}

/*
 * seam_init_vmxon_vmcs - initialize VMXON region with size and version id for
 *                        this CPU.
 * @vmcs: vmxon region to initialize. which must be zeroed before call.
 *        __GFP_ZERO or memblock_alloc() satisfies it.
 *
 * Call this function with preemption disabled as it reads basic information
 * about VMX from MSR_IA32_VMX_BASIC.
 */
int __init seam_init_vmxon_vmcs(struct vmcs *vmcs)
{
	int ret;
	int vmcs_size;
	u32 version_id;

	ret = msr_vmx_basic(&vmcs_size, &version_id);
	if (ret)
		return -EIO;

	if (vmcs_size > seam_vmxon_size || version_id != seam_vmxon_version_id) {
		/* It's assumed that CPU has same vmcs size and version_id */
		pr_err("CPU %d inconsistency vmcs size found %d > %d\n",
		       smp_processor_id(), vmcs_size, seam_vmxon_size);
		return -EIO;
	}

	vmcs->hdr.revision_id = version_id;
	return 0;
}

void __init seam_free_vmcs(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		free_pages(per_cpu(seam_vmxon_vmcs, cpu), seam_vmxon_order);
		per_cpu(seam_vmxon_vmcs, cpu) = 0;
	}
}

/*
 * seam_alloc_vmcs - allocate pages for VMXON for each CPUs and stash pages to
 *                   per-cpu variable, seam_vmxon_vmcs, for later use.
 * @return: 0 on success, -ENOMEM on failure.
 *
 * allocate pages for VMXON for each CPUs initialize vmxon region and stash
 * pages to per-cpu variable, seam_vmxon_vmcs for later use.  Call this function
 * before use of seam_vmxon() and seam_vmxon().
 */
int __init seam_alloc_vmcs(void)
{
	int cpu;
	unsigned long vmcs;

	if (!seam_vmxon_size)
		return -EOPNOTSUPP;

	for_each_possible_cpu(cpu) {
		vmcs = __get_free_pages(GFP_KERNEL | __GFP_ZERO,
					seam_vmxon_order);
		if (!vmcs)
			goto err;
		per_cpu(seam_vmxon_vmcs, cpu) = vmcs;
	}
	return 0;

err:
	seam_free_vmcs();
	return -ENOMEM;
}

static void __init seam_init_vmcs_cpu(void *data)
{
	atomic_t *error = data;
	int ret;

	ret = seam_init_vmxon_vmcs(
		(struct vmcs *)__this_cpu_read(seam_vmxon_vmcs));
	if (ret)
		atomic_set(error, ret);
}

/*
 * seam_init_vmcs - initialize VMXON region for each CPUs allocated by
 *                  seam_alloc_vmcs.
 * @return: 0 on success, error code on failure.
 */
int __init seam_init_vmcs(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_init_vmcs_cpu, &error, 1);
	return atomic_read(&error);
}

static void __init seam_vmxon_cpu(void *data)
{
	atomic_t *error = data;
	int r;

	r = cpu_vmxon(__pa(this_cpu_read(seam_vmxon_vmcs)));
	if (r)
		atomic_set(error, r);
}

/*
 * seam_vmxon - enable VMX(VMXON) on all CPUs
 * @return: 0 on success, error code on failure
 */
int __init seam_vmxon(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxon_cpu, &error, 1);
	return atomic_read(&error);
}

static void __init seam_vmxoff_cpu(void *data)
{
	atomic_t *error = data;
	int r;

	r = cpu_vmxoff();
	if (r)
		atomic_set(error, r);
}

/*
 * seam_vmxoff - disable VMX(VMXOFF) on all CPUs
 * @return: 0 on success, error code on failure
 */
int __init seam_vmxoff(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxoff_cpu, &error, 1);
	return atomic_read(&error);
}
