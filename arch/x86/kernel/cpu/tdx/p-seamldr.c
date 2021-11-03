// SPDX-License-Identifier: GPL-2.0
/* C-wrapper functions for P-SEAMLDR SEAMCALLs and functions for P-SEAMLDR */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/kobject.h>
#include <linux/slab.h>

#include <asm/trace/seam.h>
#include <asm/virtext.h>

#include "p-seamldr.h"
#include "seamcall.h"
#include "seam.h"
#include "tdx.h"

static int seamldr_info(phys_addr_t seamldr_info)
{
	u64 ret;

	ret = seamcall(SEAMCALL_SEAMLDR_INFO, seamldr_info, 0, 0, 0, NULL);
	if (ret) {
		if (ret == P_SEAMLDR_VMFAILINVALID)
			pr_info("The P-SEAMLDR is not loaded by BIOS.  Skip TDX initialization.\n");
		else
			pr_err("SEAMCALL[SEAMLDR_INFO] failed %s (0x%llx)\n",
				p_seamldr_error_name(ret), ret);
		return -EIO;
	}
	return 0;
}

static struct p_seamldr_info *p_seamldr_info;

int __init p_seamldr_get_info(void)
{
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
	/* On success, keep p_seamldr_info to export the info via sysfs. */
	if (err) {
		kfree(p_seamldr_info); /* kfree() is NULL-safe. */
		p_seamldr_info = NULL;
	}
	return err;
}

#ifdef CONFIG_SYSFS

static struct kobject *p_seamldr_kobj;

#define P_SEAMLDR_ATTR_SHOW_FMT(name, fmt)				\
static ssize_t name ## _show(						\
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)	\
{									\
	return sprintf(buf, fmt, p_seamldr_info->name);			\
}									\
static struct kobj_attribute p_seamldr_##name = __ATTR_RO(name)

#define P_SEAMLDR_ATTR_SHOW_DEC(name)	P_SEAMLDR_ATTR_SHOW_FMT(name, "%d\n")
#define P_SEAMLDR_ATTR_SHOW_HEX(name)	P_SEAMLDR_ATTR_SHOW_FMT(name, "0x%x\n")

P_SEAMLDR_ATTR_SHOW_HEX(version);
P_SEAMLDR_ATTR_SHOW_FMT(attributes, "0x08%x\n");
P_SEAMLDR_ATTR_SHOW_HEX(vendor_id);
P_SEAMLDR_ATTR_SHOW_DEC(build_date);
P_SEAMLDR_ATTR_SHOW_HEX(build_num);
P_SEAMLDR_ATTR_SHOW_HEX(minor);
P_SEAMLDR_ATTR_SHOW_HEX(major);

static struct attribute *p_seamldr_attrs[] = {
	&p_seamldr_version.attr,
	&p_seamldr_attributes.attr,
	&p_seamldr_vendor_id.attr,
	&p_seamldr_build_date.attr,
	&p_seamldr_build_num.attr,
	&p_seamldr_minor.attr,
	&p_seamldr_major.attr,
	NULL,
};

static const struct attribute_group p_seamldr_attr_group = {
	.attrs = p_seamldr_attrs,
};

static int __init p_seamldr_sysfs_init(void)
{
	int ret = 0;

	ret = tdx_sysfs_init();
	if (ret)
		goto out;

	if (!p_seamldr_info)
		goto out;

	p_seamldr_kobj = kobject_create_and_add("p_seamldr", tdx_kobj);
	if (!p_seamldr_kobj) {
		pr_err("kobject_create_and_add p_seamldr failed\n");
		ret = -EINVAL;
		goto out;
	}

	ret = sysfs_create_group(p_seamldr_kobj, &p_seamldr_attr_group);
	if (ret) {
		pr_err("Sysfs exporting attribute failed with error %d", ret);
		kobject_put(p_seamldr_kobj);
		p_seamldr_kobj = NULL;
	}

out:
	return ret;
}
device_initcall(p_seamldr_sysfs_init);
#endif
