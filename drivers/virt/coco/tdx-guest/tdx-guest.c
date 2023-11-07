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
 * than 8K (2K Quote data + ~5K of certificate blob).
 */
#define GET_QUOTE_BUF_SIZE		SZ_8K

#define GET_QUOTE_CMD_VER		1

/* TDX GetQuote status codes */
#define GET_QUOTE_SUCCESS		0
#define GET_QUOTE_IN_FLIGHT		0xffffffffffffffff

#define TDX_RTMR_EXTEND_LEN		48
#define TDX_RTMR_BUF_LEN		64

/* TDX GetQuote service codes */
#define SERVICE_QUOTE_REQ_BUF_LEN	SZ_4K
#define SERVICE_QUOTE_RESP_BUF_LEN	SZ_16K

#define SERVICE_QUOTE_SEND_CMD		0x03
#define SERVICE_QUOTE_CMD_TIMEOUT	5000

/* struct tdx_quote_buf: Format of Quote request buffer.
 * @version: Quote format version, filled by TD.
 * @status: Status code of Quote request, filled by VMM.
 * @in_len: Length of TDREPORT, filled by TD.
 * @out_len: Length of Quote data, filled by VMM.
 * @data: Quote data on output or TDREPORT on input.
 *
 * More details of Quote request buffer can be found in TDX
 * Guest-Host Communication Interface (GHCI) for Intel TDX 1.0,
 * section titled "TDG.VP.VMCALL<GetQuote>"
 */
struct tdx_quote_buf {
	u64 version;
	u64 status;
	u32 in_len;
	u32 out_len;
	u8 data[];
};

/**
 * struct att_service_req - Attestation Service command buffer
 * hdr: Command buffer header.
 * @version: Command version (default is 0).
 * @cmd: Command ID.
 * @rsvd: Reserved for future use.
 * @len: Length of the report data.
 * @data: Report data used in Quote generation
 */
struct att_service_req
{
	/* Command buffer header */
	struct tdx_service_req_hdr hdr;

	/* Command data */
	u8 version;
	u8 cmd;
	u16 rsvd;

	/* Report data */
	u32 len;
	u8 data[];
} __packed;

/**
 * struct att_service_resp - Attestation Service response buffer
 * @hdr: Response buffer header.
 * @version: Command version (default is 0).
 * @cmd: Command ID.
 * @status: Response status.
 * @len: Length of the Quote data
 * @data: Quote data.
 */
struct att_service_resp
{
	/* Response buffer header */
	struct tdx_service_resp_hdr hdr;

	/* Command data */
	u8 version;
	u8 cmd;
	u16 status;

	/* Quote data */
	u32 len;
	u8 data[];
} __packed;


/* Quote data buffer */
static void *quote_data;

/* Lock to streamline quote requests */
static DEFINE_MUTEX(quote_lock);

/*
 * GetQuote request timeout in seconds. Expect that 30 seconds
 * is enough time for QE to respond to any Quote requests.
 */
static u32 getquote_timeout = 30;

/* TDX service command request/response buffers */
static void *req_buf, *resp_buf;

static guid_t att_service_guid = GUID_INIT(0xdeadbeef, 0xdead, 0xbeef, 0xde, 0xad, 0xde, 0xad, 0xbe, 0xaf, 0xbe, 0xaf);

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

static void free_shared_pages(void *addr, size_t len)
{
	size_t aligned_len = PAGE_ALIGN(len);
	unsigned int count = aligned_len >> PAGE_SHIFT;

	if (set_memory_encrypted((unsigned long)addr, count)) {
		pr_err("Failed to restore encryption mask for Quote buffer, leak it\n");
		return;
	}

	free_pages_exact(addr, aligned_len);

}

static void *alloc_shared_pages(size_t len)
{
	size_t aligned_len = PAGE_ALIGN(len);
	unsigned int count = aligned_len >> PAGE_SHIFT;
	void *addr;

	addr = alloc_pages_exact(aligned_len, GFP_KERNEL | __GFP_ZERO);
	if (!addr)
		return NULL;

	if (set_memory_decrypted((unsigned long)addr, count)) {
		free_pages_exact(addr, aligned_len);
		return NULL;
	}

	return addr;

}

static int tdx_service_gen_quote(struct tsm_report *report, u8 *tdreport)
{
	struct att_service_resp *resp = resp_buf;
	struct att_service_req *req = req_buf;
	int ret;
	u8 *buf;
	u64 err;

	/* Check whether the service is supported */
	ret = tdx_hcall_query_service(req_buf, resp_buf, (u8 *)&att_service_guid);
	if (ret < 0)
		return ret;

	/* Initialize request service header */
	memcpy(req->hdr.guid, &att_service_guid, sizeof(guid_t));
	req->hdr.buf_len = sizeof(*req) + TDX_REPORT_LEN;

	/* Initialize request command header */
	req->version = 0;
	req->cmd = SERVICE_QUOTE_SEND_CMD;

	/* Initialize request command data */
	req->len = TDX_REPORT_LEN;
	memcpy(req->data, tdreport, TDX_REPORT_LEN);

	/* Initialize response service header */
	memcpy(resp->hdr.guid, &att_service_guid, sizeof(guid_t));

	/* Initialize response header */
	resp->version = 0;
	resp->cmd = SERVICE_QUOTE_SEND_CMD;

	err = tdx_hcall_service(req_buf, resp_buf, 0, SERVICE_QUOTE_CMD_TIMEOUT);
	if (err)
		return -EIO;

	if (resp->status) {
		pr_err("Quote Service hypercall failed, err:%x\n", resp->status);
		return -EIO;
	}

	buf = kvmemdup(resp->data, resp->len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	report->outblob = buf;
	report->outblob_len = resp->len;

	return 0;
}

static int tdx_quote_service_init(void)
{
	req_buf = alloc_shared_pages(SERVICE_QUOTE_REQ_BUF_LEN);
	if (!req_buf)
		return -ENOMEM;

	resp_buf = alloc_shared_pages(SERVICE_QUOTE_RESP_BUF_LEN);
	if (!resp_buf) {
		free_shared_pages(req_buf, SERVICE_QUOTE_REQ_BUF_LEN);
		return -ENOMEM;
	}

	return 0;

}

static void tdx_quote_service_deinit(void)
{
	if (req_buf)
		free_shared_pages(req_buf, SERVICE_QUOTE_REQ_BUF_LEN);
	if (resp_buf)
		free_shared_pages(req_buf, SERVICE_QUOTE_RESP_BUF_LEN);
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


static int tdx_report_new(struct tsm_report *report, void *data)
{
	u8 *buf, *reportdata = NULL, *tdreport = NULL;
	struct tdx_quote_buf *quote_buf = quote_data;
	struct tsm_desc *desc = &report->desc;
	int ret;
	u64 err;

	/* TODO: switch to guard(mutex_intr) */
	if (mutex_lock_interruptible(&quote_lock))
		return -EINTR;

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

	reportdata = kmalloc(TDX_REPORTDATA_LEN, GFP_KERNEL);
	if (!reportdata) {
		ret = -ENOMEM;
		goto done;
	}

	tdreport = kzalloc(TDX_REPORT_LEN, GFP_KERNEL);
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

	if (!guid_is_null(&desc->remote_guid)) {
		ret = tdx_service_gen_quote(data, tdreport);
		if (ret)
			pr_err("GetQuote service request failed\n");
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

	report->outblob = buf;
	report->outblob_len = quote_buf->out_len;

	/*
	 * TODO: parse the PEM-formatted cert chain out of the quote buffer when
	 * provided
	 */
done:
	mutex_unlock(&quote_lock);
	kfree(reportdata);
	kfree(tdreport);

	return ret;
}

static long tdx_guest_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) {
	case TDX_CMD_GET_REPORT0:
		return tdx_get_report0((struct tdx_report_req __user *)arg);
	default:
		return -ENOTTY;
	}
}

static int tdx_update_rtmr(struct tsm_rtmr *rtmr, void *data)
{
	pr_info("%s:%d called for index:%d\n", __func__, __LINE__, rtmr->index);

	if (rtmr->data_len != TDX_RTMR_EXTEND_LEN)
		return -EINVAL;

	void *buf __free(kfree) = kzalloc(TDX_RTMR_BUF_LEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, rtmr->data, rtmr->data_len);

	/* Extend RTMR registers using "TDG.MR.RTMR.EXTEND" TDCALL */
	return tdx_mcall_extend_rtmr(buf, rtmr->index);
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
	.min_rtmr_index = 2,
	.max_rtmr_index = 2,
	.report_new = tdx_report_new,
	.update_rtmr = tdx_update_rtmr,
};

static int __init tdx_guest_init(void)
{
	int ret;

	if (!x86_match_cpu(tdx_guest_ids))
		return -ENODEV;

	ret = misc_register(&tdx_misc_dev);
	if (ret)
		return ret;

	quote_data = alloc_shared_pages(GET_QUOTE_BUF_SIZE);
	if (!quote_data) {
		pr_err("Failed to allocate Quote buffer\n");
		ret = -ENOMEM;
		goto free_misc;
	}

	ret = tdx_quote_service_init();
	if (ret) {
		pr_err("Failed to allocate service buffers\n");
		ret = -ENOMEM;
		goto free_quote;
	}

	ret = tsm_register(&tdx_tsm_ops, NULL, NULL);
	if (ret)
		goto free_service;

	return 0;

free_service:
	tdx_quote_service_deinit();
free_quote:
	free_shared_pages(quote_data, GET_QUOTE_BUF_SIZE);
free_misc:
	misc_deregister(&tdx_misc_dev);

	return ret;
}
module_init(tdx_guest_init);

static void __exit tdx_guest_exit(void)
{
	tsm_unregister(&tdx_tsm_ops);
	free_shared_pages(quote_data, GET_QUOTE_BUF_SIZE);
	tdx_quote_service_deinit();
	misc_deregister(&tdx_misc_dev);
}
module_exit(tdx_guest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX Guest Driver");
MODULE_LICENSE("GPL");
