// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * tdx-attest.c - TDX attestation interface driver.
 *
 * Implements user interface to trigger attestation process and
 * read the TD Quote result.
 *
 * Copyright (C) 2020 Intel Corporation
 *
 * Author:
 *     Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */

#define pr_fmt(fmt) "TDX: " fmt

#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/set_memory.h>
#include <asm/apic.h>
#include <asm/tdx.h>
#include <asm/io.h>
#include <asm/irq_vectors.h>
#include <uapi/asm/tdx.h>

/* Used in Quote memory allocation */
static u64 quote_size = 2 * PAGE_SIZE;

/* Mutex to synchronize attestation requests */
static DEFINE_MUTEX(attestation_lock);
/* Completion object to track attestation status */
static DECLARE_COMPLETION(attestation_done);

static void attestation_callback_handler(void)
{
	complete(&attestation_done);
}

static long tdx_attest_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg)
{
	u8 *reportdata;
	long ret = 0;
	u64 data = virt_to_phys(filp->private_data);
	void __user *argp = (void __user *)arg;

	if (!data)
		return -EINVAL;

	reportdata = kzalloc(TDX_TDREPORT_LEN, GFP_KERNEL);
	if (!reportdata)
		return -ENOMEM;

	mutex_lock(&attestation_lock);

	switch (cmd) {
	case TDX_CMD_GET_TDREPORT:
		if (copy_from_user(reportdata, argp, TDX_REPORT_DATA_LEN)) {
			ret = -EFAULT;
			break;
		}

		/* Generate TDREPORT_STRUCT */
		if (tdx_get_tdreport(data, virt_to_phys(reportdata))) {
			ret = -EIO;
			break;
		}

		if (copy_to_user(argp, filp->private_data, TDX_TDREPORT_LEN))
			ret = -EFAULT;
		break;
	case TDX_CMD_GEN_QUOTE:
		if (copy_from_user(reportdata, argp, TDX_REPORT_DATA_LEN)) {
			ret = -EFAULT;
			break;
		}

		/* Generate TDREPORT_STRUCT */
		if (tdx_get_tdreport(data, virt_to_phys(reportdata))) {
			ret = -EIO;
			break;
		}

		ret = set_memory_decrypted((unsigned long) filp->private_data,
				1UL << get_order(quote_size));
		if (ret)
			break;

		/* Submit GetQuote Request */
		if (tdx_get_quote(data)) {
			ret = -EIO;
			break;
		}

		apic->send_IPI_all(HYPERVISOR_CALLBACK_VECTOR);

		/* Wait for attestation completion */
		wait_for_completion_interruptible(&attestation_done);

		ret = set_memory_encrypted((unsigned long) filp->private_data,
				1UL << get_order(quote_size));

		break;
	case TDX_CMD_GET_QUOTE_SIZE:
		if (put_user(quote_size, (u64 __user *)argp))
			ret = -EFAULT;

		break;
	default:
		pr_err("TDX attestation cmd %d not supported\n", cmd);
		break;
	}

	mutex_unlock(&attestation_lock);

	kfree(reportdata);

	return ret;
}

static vm_fault_t tdx_attest_vm_fault(struct vm_fault *vmf)
{
	struct page *page;

	if (vmf->vma->vm_private_data) {
		page = virt_to_page(vmf->vma->vm_private_data);
		get_page(page);
		vmf->page = page;
	}

	return 0;
}

static const struct vm_operations_struct tdx_attest_vm_ops = {
	.fault = tdx_attest_vm_fault,
};

static int tdx_attest_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_ops = &tdx_attest_vm_ops;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = filp->private_data;

	return 0;
}

static int tdx_attest_open(struct inode *inode, struct file *filp)
{
	if (tdx_guest_register_callback_handler(attestation_callback_handler))
		return -ENODEV;

	filp->private_data = (void *) __get_free_pages(GFP_KERNEL | __GFP_ZERO,
			get_order(quote_size));

	return !filp->private_data ? -ENOMEM : 0;
}

static int tdx_attest_release(struct inode *inode, struct file *filp)
{
	tdx_guest_unregister_callback_handler();
	free_pages((unsigned long) filp->private_data, get_order(quote_size));
	filp->private_data = NULL;

	return 0;
}

static const struct file_operations tdx_attest_fops = {
	.owner		= THIS_MODULE,
	.open		= tdx_attest_open,
	.release	= tdx_attest_release,
	.mmap		= tdx_attest_mmap,
	.unlocked_ioctl	= tdx_attest_ioctl,
	.llseek		= no_llseek,
};

static struct miscdevice tdx_attest_device = {
	.minor          = MISC_DYNAMIC_MINOR,
	.name           = "tdx-attest",
	.fops           = &tdx_attest_fops,
};
builtin_misc_device(tdx_attest_device);
