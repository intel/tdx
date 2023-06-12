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
#include <linux/acpi.h>
#include <crypto/sha2.h>
#include <linux/tpm.h>

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

#define EV_NO_ACTION		0x03
#define EV_EVENT_TAG		0x00000006U
#define CC_INVALID_RTMR_IDX	0xFFFFFFFF

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

struct cc_event_head {
	u32 mr_idx;
	u32 event_type;
	u32 count;
};

struct cc_event_data {
	u32 size;
	u8 data[];
} __packed;

struct cc_sha384_event {
	struct cc_event_head head;
	u16 algo_id;
	u8 digest[SHA384_DIGEST_SIZE];
	struct cc_event_data data;
} __packed;

struct spec_id_head {
	u8 signature[16];
	u32 platform_class;
	u8 minor_ver;
	u8 major_ver;
	u8 errata;
	u8 uintn_size;
	u32 algo_count;
} __packed;

struct spec_id_algo_node {
	u16 type;
	u16 size;
};

struct spec_id_event {
	struct cc_event_head cc_head;
	u8 digest[20];
	struct spec_id_head sid_head;
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

static struct spec_id_algo_node *algo_list;
static void *next_event;
static void __iomem *ccel_addr;
static u64 ccel_len;
static u16 algo_count;

static u64 parse_spec_id_event(void *data)
{
	struct spec_id_event *event = data;
	u8 *vendor_size;
	u64 index = 0;

	index += sizeof(*event);

	algo_list = data + index;
	algo_count = event->sid_head.algo_count;
	index += sizeof(struct spec_id_algo_node) * algo_count;

	vendor_size = data + index;
	index += (sizeof(*vendor_size) + *vendor_size);

	return index;
}

static u64 parse_cc_event(void *data)
{
	struct cc_event_head *evhead = data;
	struct cc_event_data *evdata;
	u16 *algo_id, algo_size;
	u64 index = 0;
	int i, j;

	if (!algo_list)
		return 0;

	index += sizeof(*evhead);

	for (i = 0; i < evhead->count; i++) {
		algo_size = 0;
		algo_id = data + index;
		for (j = 0; j < algo_count; j++) {
			if (algo_list[j].type == *algo_id) {
				algo_size = algo_list[j].size;
				break;
			}
		}
		index += sizeof(*algo_id) + algo_size;
	}
	evdata = data + index;
	index += sizeof(*evdata) + evdata->size;

	return index;
}


static void* acpi_ccel_next_event(void)
{
	struct cc_event_head *evhead;
	struct acpi_table_ccel *ccel;
	u64 index = 0, start = 0, size = 0;
	acpi_status status;
	void *data;

	status = acpi_get_table(ACPI_SIG_CCEL, 0, (struct acpi_table_header **)&ccel);
	if (ACPI_FAILURE(status))
		return NULL;

	data = acpi_os_map_iomem(ccel->log_area_start_address, ccel->log_area_minimum_length);

	ccel_addr = data;
	ccel_len = ccel->log_area_minimum_length;

	while (index < ccel->log_area_minimum_length) {
		evhead = data + index;
		start = index;

		if (evhead->mr_idx == CC_INVALID_RTMR_IDX)
	                break;

		if (evhead->event_type == EV_NO_ACTION)
			index += parse_spec_id_event(evhead);
		else
			index += parse_cc_event(evhead);

		size = index - start;
	}

	return evhead;
}

static void acpi_ccel_release(void)
{
	if (!ccel_addr)
		return;

	acpi_os_unmap_iomem(ccel_addr, ccel_len);
}

static void ccel_record_eventlog(void *data, u8 index)
{
	struct cc_sha384_event *event = next_event;
	char event_data[] = "Runtime RTMR event log extend success";

	if (!event)
		return;

	/* Setup Evenlog header */
	event->head.mr_idx = index + 1;
	event->head.event_type = EV_EVENT_TAG;
	event->head.count = 1;
	event->algo_id = TPM_ALG_SHA384;
	memcpy(event->digest, data, SHA384_DIGEST_SIZE);

	event->data.size = strlen(event_data);
	memcpy(event->data.data, event_data, event->data.size);

	next_event += (sizeof(*event) + event->data.size);
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

	if (!ret)
		ccel_record_eventlog(data, index);
out:
	kfree(data);

	return ret;
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

	next_event = acpi_ccel_next_event();

	ret = misc_register(&tdx_misc_dev);
	if (ret)
		return ret;

	quote_data = alloc_quote_buf();
	if (!quote_data) {
		pr_err("Failed to allocate Quote buffer\n");
		ret = -ENOMEM;
		goto free_misc;
	}

	ret = tsm_register(&tdx_tsm_ops, NULL, NULL);
	if (ret)
		goto free_quote;

	return 0;

free_quote:
	free_quote_buf(quote_data);
free_misc:
	misc_deregister(&tdx_misc_dev);

	return ret;
}
module_init(tdx_guest_init);

static void __exit tdx_guest_exit(void)
{
	tsm_unregister(&tdx_tsm_ops);
	free_quote_buf(quote_data);
	acpi_ccel_release();
	misc_deregister(&tdx_misc_dev);
}
module_exit(tdx_guest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX Guest Driver");
MODULE_LICENSE("GPL");
