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
#include <linux/set_memory.h>

#include <uapi/linux/tdx-guest.h>

#include <asm/cpu_device_id.h>
#include <asm/tdx.h>

#define GET_QUOTE_MAX_SIZE		(4 * PAGE_SIZE)

/**
 * struct quote_entry - Quote request struct
 * @valid: Flag to check validity of the GetQuote request.
 * @buf: Kernel buffer to share data with VMM (size is page aligned).
 * @buf_len: Size of the buf in bytes.
 * @compl: Completion object to track completion of GetQuote request.
 */
struct quote_entry {
	bool valid;
	void *buf;
	size_t buf_len;
	struct completion compl;
};

/* Quote data entry */
static struct quote_entry *qentry;

/* Lock to streamline quote requests */
static DEFINE_MUTEX(quote_lock);

static int quote_cb_handler(void *dev_id)
{
	struct quote_entry *entry = dev_id;
	struct tdx_quote_hdr *quote_hdr = qentry->buf;

	if (entry->valid && quote_hdr->status != GET_QUOTE_IN_FLIGHT)
		complete(&entry->compl);

	return 0;
}

static void free_shared_pages(void *buf, size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;

	if (!buf)
		return;

	set_memory_encrypted((unsigned long)buf, count);

	__free_pages(virt_to_page(buf), get_order(len));
}

static void *alloc_shared_pages(size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;
	struct page *page;
	int ret;

	page = alloc_pages(GFP_KERNEL, get_order(len));
	if (!page)
		return NULL;

	ret = set_memory_decrypted((unsigned long)page_address(page), count);
	if (ret) {
		__free_pages(page, get_order(len));
		return NULL;
	}

	return page_address(page);
}

static struct quote_entry *alloc_quote_entry(size_t len)
{
	struct quote_entry *entry = NULL;
	size_t new_len = PAGE_ALIGN(len);

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->buf = alloc_shared_pages(new_len);
	if (!entry->buf) {
		kfree(entry);
		return NULL;
	}

	entry->buf_len = new_len;
	init_completion(&entry->compl);
	entry->valid = false;

	return entry;
}

static void free_quote_entry(struct quote_entry *entry)
{
	free_shared_pages(entry->buf, entry->buf_len);
	kfree(entry);
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

static long tdx_get_quote(struct tdx_quote_req __user *ureq)
{
	struct tdx_quote_req req;
	long ret;

	if (copy_from_user(&req, ureq, sizeof(req)))
		return -EFAULT;

	mutex_lock(&quote_lock);

	if (!req.len || req.len > qentry->buf_len) {
		ret = -EINVAL;
		goto quote_failed;
	}

	if (copy_from_user(qentry->buf, (void __user *)req.buf, req.len)) {
		ret = -EFAULT;
		goto quote_failed;
	}

	qentry->valid = true;

	reinit_completion(&qentry->compl);

	/* Submit GetQuote Request using GetQuote hypercall */
	ret = tdx_hcall_get_quote(qentry->buf, qentry->buf_len);
	if (ret) {
		pr_err("GetQuote hypercall failed, status:%lx\n", ret);
		ret = -EIO;
		goto quote_failed;
	}

	/* Wait till GetQuote completion */
	wait_for_completion(&qentry->compl);

	if (copy_to_user((void __user *)req.buf, qentry->buf, req.len))
		ret = -EFAULT;

quote_failed:
	qentry->valid = false;
	mutex_unlock(&quote_lock);

	return ret;
}

static long tdx_guest_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) {
	case TDX_CMD_GET_REPORT0:
		return tdx_get_report0((struct tdx_report_req __user *)arg);
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

static int __init tdx_guest_init(void)
{
	int ret;

	if (!x86_match_cpu(tdx_guest_ids))
		return -ENODEV;

	ret = misc_register(&tdx_misc_dev);
	if (ret)
		return ret;

	qentry = alloc_quote_entry(GET_QUOTE_MAX_SIZE);
	if (!qentry) {
		pr_err("Quote entry allocation failed\n");
		ret = -ENOMEM;
		goto free_misc;
	}

	ret = tdx_register_event_irq_cb(quote_cb_handler, qentry);
	if (ret)
		goto free_quote;

	return 0;

free_quote:
	free_quote_entry(qentry);
free_misc:
	misc_deregister(&tdx_misc_dev);

	return ret;
}
module_init(tdx_guest_init);

static void __exit tdx_guest_exit(void)
{
	tdx_unregister_event_irq_cb(quote_cb_handler, qentry);
	free_quote_entry(qentry);
	misc_deregister(&tdx_misc_dev);
}
module_exit(tdx_guest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX Guest Driver");
MODULE_LICENSE("GPL");
