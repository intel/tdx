// SPDX-License-Identifier: GPL-2.0
/* C-wrapper functions for P-SEAMLDR SEAMCALLs and functions for P-SEAMLDR */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/slab.h>

#include <asm/virtext.h>

#include "p-seamldr.h"
#include "seamcall.h"
#include "seam.h"

static int seamldr_info(phys_addr_t seamldr_info)
{
	u64 ret;

	ret = seamcall(SEAMCALL_SEAMLDR_INFO, seamldr_info, 0, 0, 0, NULL);
	if (ret) {
		if (ret == P_SEAMLDR_VMFAILINVALID)
			pr_info("The P-SEAMLDR is not loaded by BIOS.  Skip TDX initialization.\n");
		else
			pr_err("SEAMCALL[SEAMLDR_INFO] failed 0x%llx\n", ret);
		return -EIO;
	}
	return 0;
}

int __init p_seamldr_get_info(void)
{
	struct p_seamldr_info *p_seamldr_info;
	struct vmcs *vmcs = NULL;
	int vmxoff_err = 0;
	int err = 0;

	/* p_seamldr_info requires P_SEAMLDR_INFO_ALIGNMENT-aligned. */
	BUILD_BUG_ON(!is_power_of_2(sizeof(*p_seamldr_info)));
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

	/*
	 * Because it's before kvm_init, VMX shouldn't be enabled as initial
	 * reset value.  In kexec case, cpu_emergency_vmxoff() disables VMX on
	 * kexec reboot.
	 */
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
	free_page((unsigned long)vmcs); /* free_page() ignores NULL */
	kfree(p_seamldr_info); /* kfree() is NULL-safe. */
	return err;
}
