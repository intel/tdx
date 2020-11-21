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
#include <linux/set_memory.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/tsm.h>
#include <linux/sizes.h>

#include <uapi/linux/tdx-guest.h>

#include <asm/cpu_device_id.h>
#include <asm/tdx.h>

/*
 * Intel's SGX QE implementation generally uses Quote size less
 * than 8K; Use 16K as MAX size to handle future updates and other
 * 3rd party implementations.
 */
#define GET_QUOTE_MAX_SIZE		(4 * PAGE_SIZE)

/*
 * Intel's SGX QE implementation generally uses Quote size less
 * than 8K (2K Quote data + ~5K of certificate blob).
 */
#define GET_QUOTE_BUF_SIZE		SZ_8K

#define GET_QUOTE_CMD_VER		1

/* TDX GetQuote status codes */
#define GET_QUOTE_SUCCESS		0
#define GET_QUOTE_IN_FLIGHT		0xffffffffffffffff

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

/* Quote data buffer */
static void *quote_data;

/* Lock to streamline quote requests */
static DEFINE_MUTEX(quote_lock);

/*
 * GetQuote request timeout in seconds. Expect that 30 seconds
 * is enough time for QE to respond to any Quote requests.
 */
static u32 getquote_timeout = 30;

static int quote_cb_handler(void *dev_id)
{
	struct quote_entry *entry = dev_id;
	struct tdx_quote_buf *quote_buf = entry->buf;

	if (entry->valid && quote_buf->status != GET_QUOTE_IN_FLIGHT)
		complete(&entry->compl);

	return 0;
}

static void free_shared_pages(void *buf, size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;

	set_memory_encrypted((unsigned long)buf, count);

	free_pages_exact(buf, PAGE_ALIGN(len));
}

static void *alloc_shared_pages(size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;
	void *addr;
	int ret;

	addr = alloc_pages_exact(len, GFP_KERNEL);
	if (!addr)
		return NULL;

	ret = set_memory_decrypted((unsigned long)addr, count);
	if (ret) {
		free_pages_exact(addr, PAGE_ALIGN(len));
		return NULL;
	}

	return addr;
}

static struct quote_entry *alloc_quote_entry(size_t len)
{
	struct quote_entry *entry = NULL;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->buf = alloc_shared_pages(len);
	if (!entry->buf) {
		kfree(entry);
		return NULL;
	}

	entry->buf_len = PAGE_ALIGN(len);
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
	u64 err;

	if (copy_from_user(&req, ureq, sizeof(req)))
		return -EFAULT;

	mutex_lock(&quote_lock);

	if (!req.len || req.len > qentry->buf_len) {
		ret = -EINVAL;
		goto quote_failed;
	}

	memset(qentry->buf, 0, qentry->buf_len);
	reinit_completion(&qentry->compl);
	qentry->valid = true;

	if (copy_from_user(qentry->buf, (void __user *)req.buf, req.len)) {
		ret = -EFAULT;
		goto quote_failed;
	}

	/* Submit GetQuote Request using GetQuote hypercall */
	err = tdx_hcall_get_quote(qentry->buf, qentry->buf_len);
	if (err) {
		pr_err("GetQuote hypercall failed, status:%lx\n", err);
		ret = -EIO;
		goto quote_failed;
	}

	ret = 0;

	/*
	 * Although the GHCI specification does not state explicitly that
	 * the VMM must not wait indefinitely for the Quote request to be
	 * completed, a sane VMM should always notify the guest after a
	 * certain time, regardless of whether the Quote generation is
	 * successful or not.  For now just assume the VMM will do so.
	 */
	wait_for_completion(&qentry->compl);

	if (copy_to_user((void __user *)req.buf, qentry->buf, req.len))
		ret = -EFAULT;

quote_failed:
	qentry->valid = false;
	mutex_unlock(&quote_lock);

	return ret;
}

static void free_quote_buf(void *buf)
{
	size_t len = PAGE_ALIGN(GET_QUOTE_BUF_SIZE);
	unsigned int count = len >> PAGE_SHIFT;

	if (set_memory_encrypted((unsigned long)buf, count)) {
		pr_err("Failed to restore encryption mask for Quote buffer, leak it\n");
		return;
	}

	free_pages_exact(buf, len);
}

static void *alloc_quote_buf(void)
{
	size_t len = PAGE_ALIGN(GET_QUOTE_BUF_SIZE);
	unsigned int count = len >> PAGE_SHIFT;
	void *addr;

	addr = alloc_pages_exact(len, GFP_KERNEL | __GFP_ZERO);
	if (!addr)
		return NULL;

	if (set_memory_decrypted((unsigned long)addr, count)) {
		free_pages_exact(addr, len);
		return NULL;
	}

	return addr;
}

/*
 * wait_for_quote_completion() - Wait for Quote request completion
 * @quote_buf: Address of Quote buffer.
 * @timeout: Timeout in seconds to wait for the Quote generation.
 *
 * As per TDX GHCI v1.0 specification, sec titled "TDG.VP.VMCALL<GetQuote>",
 * the status field in the Quote buffer will be set to GET_QUOTE_IN_FLIGHT
 * while VMM processes the GetQuote request, and will change it to success
 * or error code after processing is complete. So wait till the status
 * changes from GET_QUOTE_IN_FLIGHT or the request being timed out.
 */
static int wait_for_quote_completion(struct tdx_quote_buf *quote_buf, u32 timeout)
{
	int i = 0;

	/*
	 * Quote requests usually take a few seconds to complete, so waking up
	 * once per second to recheck the status is fine for this use case.
	 */
	while (quote_buf->status == GET_QUOTE_IN_FLIGHT && i++ < timeout) {
		if (msleep_interruptible(MSEC_PER_SEC))
			return -EINTR;
	}

	return (i == timeout) ? -ETIMEDOUT : 0;
}

static u8 *tdx_report_new(const struct tsm_desc *desc, void *data, size_t *outblob_len)
{
	struct tdx_quote_buf *quote_buf = quote_data;
	int ret;
	u8 *buf;
	u64 err;

	if (mutex_lock_interruptible(&quote_lock))
		return ERR_PTR(-EINTR);

	/*
	 * If the previous request is timedout or interrupted, and the
	 * Quote buf status is still in GET_QUOTE_IN_FLIGHT (owned by
	 * VMM), don't permit any new request.
	 */
	if (quote_buf->status == GET_QUOTE_IN_FLIGHT) {
		ret = -EBUSY;
		goto done;
	}

	if (desc->inblob_len != TDX_REPORTDATA_LEN) {
		ret = -EINVAL;
		goto done;
	}

	/* TDX attestation only supports default format request */
	if (desc->outblob_format != TSM_FORMAT_DEFAULT) {
		ret = -EINVAL;
		goto done;
	}

	u8 *reportdata __free(kfree) = kmalloc(TDX_REPORTDATA_LEN, GFP_KERNEL);
	if (!reportdata) {
		ret = -ENOMEM;
		goto done;
	}

	u8 *tdreport __free(kfree) = kzalloc(TDX_REPORT_LEN, GFP_KERNEL);
	if (!tdreport) {
		ret = -ENOMEM;
		goto done;
	}

	memcpy(reportdata, desc->inblob, desc->inblob_len);

	/* Generate TDREPORT0 using "TDG.MR.REPORT" TDCALL */
	ret = tdx_mcall_get_report0(reportdata, tdreport);
	if (ret) {
		pr_err("GetReport call failed\n");
		goto done;
	}

	memset(quote_data, 0, GET_QUOTE_BUF_SIZE);

	/* Update Quote buffer header */
	quote_buf->version = GET_QUOTE_CMD_VER;
	quote_buf->in_len = TDX_REPORT_LEN;

	memcpy(quote_buf->data, tdreport, TDX_REPORT_LEN);

	err = tdx_hcall_get_quote(quote_data, GET_QUOTE_BUF_SIZE);
	if (err) {
		pr_err("GetQuote hypercall failed, status:%llx\n", err);
		ret = -EIO;
		goto done;
	}

	ret = wait_for_quote_completion(quote_buf, getquote_timeout);
	if (ret) {
		pr_err("GetQuote request timedout\n");
		goto done;
	}

	buf = kvmemdup(quote_buf->data, quote_buf->out_len, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto done;
	}

	*outblob_len = quote_buf->out_len;

done:
	mutex_unlock(&quote_lock);
	return ret ? ERR_PTR(ret) : buf;
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

static const struct tsm_ops tdx_tsm_ops = {
	.name = KBUILD_MODNAME,
	.report_new = tdx_report_new,
};

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
		ret = -ENOMEM;
		goto free_misc;
	}

	quote_data = alloc_quote_buf();
	if (!quote_data) {
		pr_err("Failed to allocate Quote buffer\n");
		ret = -ENOMEM;
		goto free_quote_entry;
	}

	ret = tdx_register_event_irq_cb(quote_cb_handler, qentry);
	if (ret)
		goto free_quote_buf;

	ret = register_tsm(&tdx_tsm_ops, NULL, NULL);
	if (ret)
		goto free_irq_cb;

	return 0;

free_irq_cb:
	tdx_unregister_event_irq_cb(quote_cb_handler, qentry);
free_quote_buf:
	free_quote_buf(quote_data);
free_quote_entry:
	free_quote_entry(qentry);
free_misc:
	misc_deregister(&tdx_misc_dev);

	return ret;
}
module_init(tdx_guest_init);

static void __exit tdx_guest_exit(void)
{
	tdx_unregister_event_irq_cb(quote_cb_handler, qentry);
	unregister_tsm(&tdx_tsm_ops);
	free_quote_entry(qentry);
	free_quote_buf(quote_data);
	misc_deregister(&tdx_misc_dev);
}
module_exit(tdx_guest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX Guest Driver");
MODULE_LICENSE("GPL");
