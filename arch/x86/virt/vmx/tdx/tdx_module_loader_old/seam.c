// SPDX-License-Identifier: GPL-2.0
/* common helper functions for the P-SEAMLDR and the TDX module to VMXON/VMXOFF */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/earlycpio.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/slab.h>

#include <asm/microcode.h>
#include <asm/cpu.h>

#include "seam.h"

struct builtin_fw {
	char *name;
	void *data;
	unsigned long size;
};

extern struct builtin_fw __start_builtin_fw[];
extern struct builtin_fw __end_builtin_fw[];

static bool get_builtin_firmware(struct cpio_data *cd, const char *name)
{
        struct builtin_fw *b_fw;

        for (b_fw = __start_builtin_fw; b_fw != __end_builtin_fw; b_fw++) {
                if (!strcmp(name, b_fw->name)) {
                        cd->size = b_fw->size;
                        cd->data = b_fw->data;
                        return true;
                }
        }
        return false;
}

/**
 * find_cpio_file - Search for a filename in an uncompressed cpio
 * @path:       The filename to search for without a slash at the end.
 * @data:       Pointer to the cpio archive or a header inside
 * @len:        Remaining length of the cpio based on data pointer
 *
 * Return:      struct cpio_data containing the address, length. The filename
 *              is set to empty filename string.
 *              If the file is not found, set the address to NULL.
 */
static struct cpio_data find_cpio_file(const char *path, void *data, size_t len)
{
	struct cpio_data blob;
	long offset = 0;

	while (len > 0) {
		blob = find_cpio_data(path, data, len, &offset);

		/*
		 * find the filename, the returned blob name is empty.  See the
		 * comment of the return value of find_cpio_data().
		 */
		if (blob.data && blob.name[0] == '\0')
			return blob;

		if (!blob.data)
			break;

		/* match the item with the same path prefix, skip it */
		data += offset;
		len -= offset;
	}

	/* The file was not found. */
	return (struct cpio_data) { .data = NULL, .size = 0, .name = "" };
}

bool __init seam_get_firmware(struct cpio_data *blob, const char *name)
{
	if (get_builtin_firmware(blob, name))
		return true;

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start) {
		static const char * const prepend[] = {
			"lib/firmware",
			/*
			 * Some tools which generate initrd image, for example,
			 * dracut, creates a symbolic link from lib/ to
			 * usr/lib/.  In such case, search in lib/firmware/
			 * doesn't find the file.  Search usr/lib too.
			 */
			"usr/lib/firmware",
		};
		int i;
		size_t len = strlen(name) + 18;
		char *path = kmalloc(len, GFP_KERNEL);

		if (!path)
			return false;

		for (i = 0; i < ARRAY_SIZE(prepend); i++) {
			sprintf(path, "%s/%s", prepend[i], name);
			*blob = find_cpio_file(path, (void *)initrd_start,
					       initrd_end - initrd_start);
			if (blob->data) {
				kfree(path);
				return true;
			}
		}
		kfree(path);
	}
#endif

	return false;
}

static u32 seam_vmxon_version_id;

static int cpu_vmx_get_basic_info(struct vmx_basic_info *info)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return -EIO;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return -EIO;

	info->size = vmx_msr_high & 0x1fff;
	info->cap = vmx_msr_high & ~0x1fff;
	info->rev_id = vmx_msr_low;

	return 0;
}

/*
 * This function must be called after init_ia32_feat_ctl() that sets
 * X86_FEATURE_VMX.
 */
int __init seam_init_vmx_early(void)
{
	struct vmx_basic_info info;

	if (!this_cpu_has(X86_FEATURE_VMX))
		return -EOPNOTSUPP;

	if (cpu_vmx_get_basic_info(&info))
		return -EIO;

	seam_vmxon_version_id = info.rev_id;

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
void seam_init_vmxon_vmcs(struct vmcs *vmcs)
{
	vmcs->hdr.revision_id = seam_vmxon_version_id;
}

static DEFINE_PER_CPU(unsigned long, percpu_vmcs);
static void seam_vmxon(void *data)
{
	atomic_t *error = data;
	int r;

	seam_init_vmxon_vmcs((void *)this_cpu_read(percpu_vmcs));

	r = cpu_vmxon(__pa(this_cpu_read(percpu_vmcs)));
	if (r)
		atomic_set(error, r);
}

static void seam_vmcs_free(void)
{
	int cpu;
	unsigned long *vmcs;

	for_each_online_cpu(cpu) {
		vmcs = per_cpu_ptr(&percpu_vmcs, cpu);
		free_page(*vmcs);
	}
}

int seam_vmxon_on_each_cpu(void)
{
	int cpu;
	atomic_t error;
	struct vmcs *vmcs = NULL;

	for_each_online_cpu(cpu) {
		vmcs = (struct vmcs *)get_zeroed_page(GFP_KERNEL);
		if (!vmcs) {
			seam_vmcs_free();
			return -ENOMEM;
		}
		*per_cpu_ptr(&percpu_vmcs, cpu) = (unsigned long)vmcs;
	}

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxon, &error, 1);

	/*
	 * Check if any of the CPUs fail.  Don't care how about many CPUs failed
	 * and about the exact error code.
	 */
	return atomic_read(&error);
}

static void seam_vmxoff(void *data)
{
	cpu_vmxoff();
}

int seam_vmxoff_on_each_cpu(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxoff, &error, 1);
	seam_vmcs_free();

	/*
	 * Check if any of the CPUs fail.  Don't care how many CPUs failed and
	 * about the exact error code.
	 */
	return atomic_read(&error);
}
