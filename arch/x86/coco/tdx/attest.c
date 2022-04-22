// SPDX-License-Identifier: GPL-2.0
/*
 * attest.c - TDX attestation feature support.
 *
 * Implements attestation related IOCTL handlers.
 *
 * Copyright (C) 2022 Intel Corporation
 *
 */

#define pr_fmt(fmt) "x86/tdx: attest: " fmt

#include <linux/mm.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <asm/tdx.h>
#include <asm/coco.h>

#include "tdx.h"

/* GetQuote hypercall leaf ID */
#define TDVMCALL_GET_QUOTE             0x10002

/* Used for buffer allocation in GetQuote request */
struct quote_buf {
	/* Address of kernel buffer (size is page aligned) */
	void *vmaddr;
	/* Size of the allocated memory */
	int size;
};

/* List entry of quote_list */
struct quote_entry {
	/* Flag to check validity of the GetQuote request */
	bool valid;
	/* Kernel buffer to share data with VMM */
	struct quote_buf buf;
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
struct workqueue_struct *quote_wq;
struct work_struct quote_work;

/* tdx_get_quote_hypercall() - Request to get TD Quote using TDREPORT */
static long tdx_get_quote_hypercall(struct quote_buf *buf)
{
	struct tdx_hypercall_args args = {0};

	args.r10 = TDX_HYPERCALL_STANDARD;
	args.r11 = TDVMCALL_GET_QUOTE;
	args.r12 = cc_mkdec(virt_to_phys(buf->vmaddr));
	args.r13 = buf->size;

	/*
	 * Pass the physical address of TDREPORT to the VMM and
	 * trigger the Quote generation. It is not a blocking
	 * call, hence completion of this request will be notified to
	 * the TD guest via a callback interrupt. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec titled "TDG.VP.VMCALL<GetQuote>".
	 */
	return __tdx_hypercall(&args, 0);
}

/*
 * init_quote_buf() - Initialize the quote buffer by allocating
 *                    a shared buffer of given size.
 *
 * Size is page aligned and the allocated memory is decrypted
 * to allow VMM to access it.
 */
static int init_quote_buf(struct quote_buf *buf, u64 req_size)
{
	int size = PAGE_ALIGN(req_size);
	void *vmaddr;

	vmaddr = cc_decrypted_alloc(size, GFP_KERNEL);
	if (!vmaddr)
		return -ENOMEM;

	buf->vmaddr = vmaddr;
	buf->size = size;

	return 0;
}

/* Free the decrypted memory */
static void deinit_quote_buf(struct quote_buf *buf)
{
	cc_decrypted_free(buf->vmaddr, buf->size);
}

static struct quote_entry *alloc_quote_entry(u64 buf_len)
{
	struct quote_entry *entry = NULL;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	/* Init buffer for quote request */
	if (init_quote_buf(&entry->buf, buf_len)) {
		pr_err("Shared buffer allocation failed\n");
		kfree(entry);
		return NULL;
	}

	init_completion(&entry->compl);
	entry->valid = true;

	return entry;
}

static void free_quote_entry(struct quote_entry *entry)
{
	deinit_quote_buf(&entry->buf);
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
	quote_hdr = (struct tdx_quote_hdr *)entry->buf.vmaddr;
	if (quote_hdr->status == GET_QUOTE_IN_FLIGHT) {
		entry->valid = false;
		mutex_unlock(&quote_lock);
		return;
	}
	_del_quote_entry(entry);
	mutex_unlock(&quote_lock);
}

long tdx_get_quote(void __user *argp)
{
	struct quote_entry *entry;
	struct tdx_quote_req req;
	struct quote_buf *buf;
	long ret;

	/* Copy GetQuote request struct from user buffer */
	if (copy_from_user(&req, argp, sizeof(struct tdx_quote_req)))
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

	buf = &entry->buf;

	/* Copy data (with TDREPORT) from user buffer to kernel Quote buffer */
	if (copy_from_user(buf->vmaddr, (void __user *)req.buf, req.len)) {
		free_quote_entry(entry);
		return -EFAULT;
	}

	mutex_lock(&quote_lock);

	/* Submit GetQuote Request */
	ret = tdx_get_quote_hypercall(buf);
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
	if (copy_to_user((void __user *)req.buf, buf->vmaddr, req.len))
		ret = -EFAULT;

	/*
	 * Reaching here means GetQuote request is processed
	 * successfully. So do the cleanup and return 0.
	 */
	del_quote_entry(entry);

	return 0;
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
		quote_hdr = (struct tdx_quote_hdr *)entry->buf.vmaddr;
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

int __init tdx_attest_init(void *data)
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
				"tdx_quote_irq", data)) {
		pr_err("notify IRQ request failed\n");
		destroy_workqueue(quote_wq);
		return -EIO;
	}

	return 0;
}
