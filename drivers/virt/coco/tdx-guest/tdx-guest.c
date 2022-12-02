// SPDX-License-Identifier: GPL-2.0
/*
 * TDX guest user interface driver
 *
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/dma-mapping.h>

#include <uapi/linux/tdx-guest.h>

#include <asm/cpu_device_id.h>
#include <asm/tdx.h>

/* List entry of quote_list */
struct quote_entry {
	/* Flag to check validity of the GetQuote request */
	bool valid;
	/* Kernel buffer to share data with VMM (size is page aligned) */
	u8 *buf;
	/* Size of the allocated memory */
	size_t buf_len;
	/* DMA handle for buf memory allocation */
	dma_addr_t handle;
	/* Completion object to track completion of GetQuote request */
	struct completion compl;
	struct list_head list;
};

/*
 * To support parallel GetQuote requests, use the list
 * to track active GetQuote requests.
 */
static LIST_HEAD(quote_list);

/* Lock to protect quote_list */
static DEFINE_MUTEX(quote_lock);

/*
 * Workqueue to handle Quote data after Quote generation
 * notification from VMM.
 */
static struct workqueue_struct *quote_wq;
static struct work_struct quote_work;

static struct platform_device *tdx_dev;

static struct quote_entry *alloc_quote_entry(u64 buf_len)
{
	struct quote_entry *entry = NULL;
	size_t new_len = PAGE_ALIGN(buf_len);

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->buf = dma_alloc_coherent(&tdx_dev->dev, new_len, &entry->handle,
					GFP_KERNEL);
	if (!entry->buf) {
		pr_err("Shared buffer allocation failed\n");
		kfree(entry);
		return NULL;
	}

	entry->buf_len = new_len;
	init_completion(&entry->compl);
	entry->valid = true;

	return entry;
}

static void free_quote_entry(struct quote_entry *entry)
{
	dma_free_coherent(&tdx_dev->dev, entry->buf_len, entry->buf,
			  entry->handle);
	kfree(entry);
}

/* Must be called with quote_lock held */
static void _del_quote_entry(struct quote_entry *entry)
{
	list_del(&entry->list);
	free_quote_entry(entry);
}

static void del_quote_entry(struct quote_entry *entry)
{
	mutex_lock(&quote_lock);
	_del_quote_entry(entry);
	mutex_unlock(&quote_lock);
}

/* Handles early termination of GetQuote requests */
static void terminate_quote_request(struct quote_entry *entry)
{
	struct tdx_quote_hdr *quote_hdr;

	/*
	 * For early termination, if the request is not yet
	 * processed by VMM (GET_QUOTE_IN_FLIGHT), the VMM
	 * still owns the shared buffer, so mark the request
	 * invalid to let quote_callback_handler() handle the
	 * memory cleanup function. If the request is already
	 * processed, then do the cleanup and return.
	 */

	mutex_lock(&quote_lock);
	quote_hdr = (struct tdx_quote_hdr *)entry->buf;
	if (quote_hdr->status == GET_QUOTE_IN_FLIGHT) {
		entry->valid = false;
		mutex_unlock(&quote_lock);
		return;
	}
	_del_quote_entry(entry);
	mutex_unlock(&quote_lock);
}

static irqreturn_t attestation_callback_handler(int irq, void *dev_id)
{
	queue_work(quote_wq, &quote_work);
	return IRQ_HANDLED;
}

static void quote_callback_handler(struct work_struct *work)
{
	struct tdx_quote_hdr *quote_hdr;
	struct quote_entry *entry, *next;

	/* Find processed quote request and mark it complete */
	mutex_lock(&quote_lock);
	list_for_each_entry_safe(entry, next, &quote_list, list) {
		quote_hdr = (struct tdx_quote_hdr *)entry->buf;
		if (quote_hdr->status == GET_QUOTE_IN_FLIGHT)
			continue;
		/*
		 * If user invalidated the current request, remove the
		 * entry from the quote list and free it. If the request
		 * is still valid, mark it complete.
		 */
		if (entry->valid)
			complete(&entry->compl);
		else
			_del_quote_entry(entry);
	}
	mutex_unlock(&quote_lock);
}

static long tdx_get_report0(struct tdx_report_req __user *req)
{
	u8 *reportdata, *tdreport;
	long ret;

	reportdata = kmalloc(TDX_REPORTDATA_LEN, GFP_KERNEL);
	if (!reportdata)
		return -ENOMEM;

	tdreport = kzalloc(TDX_REPORT_LEN, GFP_KERNEL);
	if (!tdreport) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(reportdata, req->reportdata, TDX_REPORTDATA_LEN)) {
		ret = -EFAULT;
		goto out;
	}

	/* Generate TDREPORT0 using "TDG.MR.REPORT" TDCALL */
	ret = tdx_mcall_get_report0(reportdata, tdreport);
	if (ret)
		goto out;

	if (copy_to_user(req->tdreport, tdreport, TDX_REPORT_LEN))
		ret = -EFAULT;

out:
	kfree(reportdata);
	kfree(tdreport);

	return ret;
}

static long tdx_verify_report(struct tdx_verify_report_req __user *req)
{
	u8 *reportmac;
	long ret = 0;
	u64 err;

	reportmac = kmalloc(sizeof(req->reportmac), GFP_KERNEL);
	if (!reportmac)
		return -ENOMEM;

	if (copy_from_user(reportmac, req->reportmac, sizeof(req->reportmac))) {
		ret = -EFAULT;
		goto out;
	}

	/* Verify REPORTMACSTRUCT using "TDG.MR.VERIFYREPORT" TDCALL */
	err = tdx_mcall_verify_report(reportmac);
	if (err)
		ret = -EIO;

	if (copy_to_user(&req->err_code, &err, sizeof(u64)))
		ret = -EFAULT;
out:
	kfree(reportmac);

	return ret;
}

static long tdx_extend_rtmr(struct tdx_extend_rtmr_req __user *req)
{
	u8 *data, index;
	int ret;

	if (copy_from_user(&index, &req->index, sizeof(u8)))
		return -EFAULT;

	/*
	 * RTMR index 0 and 1 is used by BIOS and kernel and are not
	 * allowed for userspace update.
	 */
	if (index < 2)
		return -EPERM;

	/* TDG.MR.RTMR.EXTEND TDCALL expects buffer to be 64B aligned */
	data = kmalloc(ALIGN(sizeof(req->data), 64), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	if (copy_from_user(data, req->data, sizeof(req->data))) {
		ret = -EFAULT;
		goto out;
	}

	/* Extend RTMR registers using "TDG.MR.RTMR.EXTEND" TDCALL */
	ret = tdx_mcall_extend_rtmr(data, index);
out:
	kfree(data);

	return ret;
}

static long tdx_get_quote(struct tdx_quote_req __user *ureq)
{
	struct tdx_quote_req req;
	struct quote_entry *entry;
	long ret;

	if (copy_from_user(&req, ureq, sizeof(req)))
		return -EFAULT;

	/* Make sure the length is valid */
	if (!req.len) {
		pr_err("Invalid Quote buffer length\n");
		return -EINVAL;
	}

	entry = alloc_quote_entry(req.len);
	if (!entry) {
		pr_err("Quote entry allocation failed\n");
		return -ENOMEM;
	}

	/* Copy data (with TDREPORT) from user buffer to kernel Quote buffer */
	if (copy_from_user(entry->buf, (void __user *)req.buf, req.len)) {
		free_quote_entry(entry);
		return -EFAULT;
	}

	mutex_lock(&quote_lock);

	/* Submit GetQuote Request */
	ret = tdx_hcall_get_quote(entry->buf, entry->buf_len);
	if (ret) {
		mutex_unlock(&quote_lock);
		pr_err("GetQuote hypercall failed, status:%lx\n", ret);
		free_quote_entry(entry);
		return -EIO;
	}

	/* Add current quote entry to quote_list to track active requests */
	list_add_tail(&entry->list, &quote_list);

	mutex_unlock(&quote_lock);

	/* Wait for attestation completion */
	ret = wait_for_completion_interruptible(&entry->compl);
	if (ret < 0) {
		pr_err("GetQuote request terminated\n");
		terminate_quote_request(entry);
		return -EINTR;
	}

	/*
	 * If GetQuote request completed successfully, copy the result
	 * back to the user and do the cleanup.
	 */
	if (copy_to_user((void __user *)req.buf, entry->buf, req.len))
		ret = -EFAULT;

	/*
	 * Reaching here means GetQuote request is processed
	 * successfully. So do the cleanup and return 0.
	 */
	del_quote_entry(entry);

	return 0;
}

static long tdx_guest_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) {
	case TDX_CMD_GET_REPORT0:
		return tdx_get_report0((struct tdx_report_req __user *)arg);
	case TDX_CMD_VERIFY_REPORT:
		return tdx_verify_report((struct tdx_verify_report_req __user *)arg);
	case TDX_CMD_EXTEND_RTMR:
		return tdx_extend_rtmr((struct tdx_extend_rtmr_req __user *)arg);
	case TDX_CMD_GET_QUOTE:
		return tdx_get_quote((struct tdx_quote_req *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations tdx_guest_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tdx_guest_ioctl,
	.llseek = no_llseek,
};

static struct miscdevice tdx_misc_dev = {
	.name = KBUILD_MODNAME,
	.minor = MISC_DYNAMIC_MINOR,
	.fops = &tdx_guest_fops,
};

static const struct x86_cpu_id tdx_guest_ids[] = {
	X86_MATCH_FEATURE(X86_FEATURE_TDX_GUEST, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, tdx_guest_ids);

static int tdx_guest_probe(struct platform_device *pdev)
{
	quote_wq = create_singlethread_workqueue("tdx_quote_handler");

	INIT_WORK(&quote_work, quote_callback_handler);

	/*
	 * Register event notification IRQ to get Quote completion
	 * notification. Since tdx_notify_irq is not specific to the
	 * attestation feature, use IRQF_SHARED to make it shared IRQ.
	 * Use IRQF_NOBALANCING to make sure the IRQ affinity will not
	 * be changed.
	 */
	if (request_irq(tdx_notify_irq, attestation_callback_handler,
				IRQF_NOBALANCING | IRQF_SHARED,
				"tdx_quote_irq", &tdx_misc_dev)) {
		pr_err("notify IRQ request failed\n");
		destroy_workqueue(quote_wq);
		return -EIO;
	}

	return misc_register(&tdx_misc_dev);
}

static int tdx_guest_remove(struct platform_device *pdev)
{
	misc_deregister(&tdx_misc_dev);
	return 0;
}

static struct platform_driver tdx_guest_driver = {
	.probe = tdx_guest_probe,
	.remove = tdx_guest_remove,
	.driver.name = KBUILD_MODNAME,
};

static int __init tdx_guest_init(void)
{
	int ret;

	if (!x86_match_cpu(tdx_guest_ids))
		return -ENODEV;

	ret = platform_driver_register(&tdx_guest_driver);
	if (ret) {
		pr_err("failed to register driver, err=%d\n", ret);
		return ret;
	}

	tdx_dev = platform_device_register_simple(KBUILD_MODNAME, -1, NULL, 0);
	if (IS_ERR(tdx_dev)) {
		ret = PTR_ERR(tdx_dev);
		pr_err("failed to allocate device, err=%d\n", ret);
		platform_driver_unregister(&tdx_guest_driver);
		return ret;
	}

	return 0;
}

static void __exit tdx_guest_exit(void)
{
	platform_device_unregister(tdx_dev);
	platform_driver_unregister(&tdx_guest_driver);
}
module_init(tdx_guest_init);
module_exit(tdx_guest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX Guest Driver");
MODULE_LICENSE("GPL");
