// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * svkl.c - ACPI SVKL interface driver.
 *
 * Copyright (C) 2020 Intel Corporation
 *
 * Parses the ACPI SVKL table and adds support to access/modify
 * the SVKL table entries via set of user IOCTLs.
 *
 * Author:
 *     Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */

#define pr_fmt(fmt) "SVKL: " fmt

#include <linux/acpi.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/svkl.h>
#include <linux/fs.h>

/* SVKL table header */
static struct acpi_table_header *svkl_tbl_hdr;
/* Lock to protect access to SVKL table */
static struct mutex svkl_lock;

static void dump_svkl_header(void)
{
	struct acpi_table_svkl *svkl_ktbl;
	struct acpi_svkl_key *svkl_key;
	int i;

	svkl_ktbl = (struct acpi_table_svkl *)svkl_tbl_hdr;
	svkl_key = (struct acpi_svkl_key *)(&svkl_ktbl[1]);

	pr_info("Key Count   :%x\n", svkl_ktbl->count);

	mutex_lock(&svkl_lock);
	for (i = 0; i < svkl_ktbl->count; i++) {
		svkl_key = &svkl_key[i];
		pr_info("Key%d Type   :%x\n", i, svkl_key->type);
		pr_info("Key%d Format :%x\n", i, svkl_key->format);
		pr_info("Key%d Size   :%d\n", i, svkl_key->size);
		pr_info("Key%d Addr   :%llx\n", i, svkl_key->address);
	}
	mutex_unlock(&svkl_lock);
}

static int get_index(void __user *argp, u32 *index)
{
	struct acpi_table_svkl *svkl_ktbl;

	svkl_ktbl = (struct acpi_table_svkl *)svkl_tbl_hdr;

	if (get_user(*index, (u32 __user *)argp))
		return -EFAULT;

	if (*index >= svkl_ktbl->count)
		return -EINVAL;

	return 0;
}

static long acpi_svkl_ioctl(struct file *f, unsigned int cmd,
			    unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct acpi_table_svkl *svkl_ktbl;
	struct acpi_svkl_key *svkl_key;
	struct acpi_svkl_key_info *kinfo;
	char *kdata;
	int ret = 0;
	u32 index = 0;

	svkl_ktbl = (struct acpi_table_svkl *)svkl_tbl_hdr;
	/* SVKL Key headers are at svkl_tbl_hdr + sizeof(*svkl_ktbl) */
	svkl_key = (struct acpi_svkl_key *)(&svkl_ktbl[1]);

	mutex_lock(&svkl_lock);
	switch (cmd) {
	case ACPI_SVKL_GET_KEY_COUNT:
		if (put_user(svkl_ktbl->count, (u32 __user *)argp))
			ret = -EFAULT;
		break;
	case ACPI_SVKL_GET_KEY_INFO:
		ret = get_index(argp, &index);
		if (ret)
			break;
		kinfo = (struct acpi_svkl_key_info *)(&svkl_key[index]);
		if (copy_to_user(argp, kinfo, sizeof(*kinfo)))
			ret = -EFAULT;
		break;
	case ACPI_SVKL_GET_KEY_DATA:
		ret = get_index(argp, &index);
		if (ret)
			break;
		svkl_key = (struct acpi_svkl_key *)(&svkl_key[index]);
		kdata = memremap(svkl_key->address, svkl_key->size,
				 MEMREMAP_WB);
		if (!kdata) {
			ret = -ENOMEM;
			break;
		}
		if (copy_to_user(argp, kdata, svkl_key->size))
			ret = -EFAULT;
		memunmap(kdata);
		break;
	case ACPI_SVKL_CLEAR_KEY:
		ret = get_index(argp, &index);
		if (ret)
			break;
		svkl_key = (struct acpi_svkl_key *)(&svkl_key[index]);
		kdata = memremap(svkl_key->address, svkl_key->size,
				 MEMREMAP_WB);
		if (!kdata) {
			ret = -ENOMEM;
			break;
		}
		memset(kdata, 0, svkl_key->size);
		memunmap(kdata);
		break;
	}
	mutex_unlock(&svkl_lock);

	return ret;
}

static const struct file_operations acpi_svkl_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= acpi_svkl_ioctl,
	.llseek		= no_llseek,
};

static struct miscdevice acpi_svkl_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "svkl",
	.fops	= &acpi_svkl_ops,
};

static int __init acpi_svkl_init(void)
{
	acpi_status status = AE_OK;
	int ret;

	ret = misc_register(&acpi_svkl_dev);
	if (ret) {
		pr_err("SVKL: can't misc_register on minor=%d\n",
		       MISC_DYNAMIC_MINOR);
		return ret;
	}

	mutex_init(&svkl_lock);

	status = acpi_get_table(ACPI_SIG_SVKL, 0, &svkl_tbl_hdr);
	if (ACPI_FAILURE(status) || !svkl_tbl_hdr) {
		pr_err("get table failed\n");
		return -ENODEV;
	}

	dump_svkl_header();

	pr_info("ACPI: SVKL module loaded\n");

	return 0;
}

static void __exit acpi_svkl_exit(void)
{
	acpi_put_table(svkl_tbl_hdr);
	misc_deregister(&acpi_svkl_dev);
}

module_init(acpi_svkl_init);
module_exit(acpi_svkl_exit);

MODULE_AUTHOR(" Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("ACPI SVKL table interface driver");
MODULE_LICENSE("GPL v2");
