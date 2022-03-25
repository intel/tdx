// SPDX-License-Identifier: GPL-2.0
/*
 * intel_tdx_attest.c - TDX guest attestation interface driver.
 *
 * Implements user interface to trigger attestation process and
 * read the TD Quote result.
 *
 * Copyright (C) 2020 Intel Corporation
 *
 * Author:
 *     Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */

#define pr_fmt(fmt) "x86/tdx: attest: " fmt

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/set_memory.h>
#include <linux/dma-mapping.h>
#include <linux/jiffies.h>
#include <linux/io.h>
#include <asm/apic.h>
#include <asm/tdx.h>
#include <asm/irq_vectors.h>
#include <uapi/misc/tdx.h>

/* Used in Quote memory allocation */
#define QUOTE_SIZE			(2 * PAGE_SIZE)
/* Used in Get Quote request memory allocation */
#define GET_QUOTE_MAX_SIZE		(4 * PAGE_SIZE)
/* Get Quote timeout in msec */
#define GET_QUOTE_TIMEOUT		(5000)

/* Mutex to synchronize attestation requests */
static DEFINE_MUTEX(attestation_lock);
/* Completion object to track attestation status */
static DECLARE_COMPLETION(attestation_done);
/* Buffer used to copy report data in attestation handler */
static u8 report_data[TDX_REPORT_DATA_LEN] __aligned(64);
/* Data pointer used to get TD Quote data in attestation handler */
static void *tdquote_data;
/* Data pointer used to get TDREPORT data in attestation handler */
static void *tdreport_data;
/* DMA handle used to allocate and free tdquote DMA buffer */
dma_addr_t tdquote_dma_handle;

struct tdx_gen_quote {
	void *buf __user;
	size_t len;
};

static void attestation_callback_handler(void)
{
	complete(&attestation_done);
}

static long tdx_attest_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	long ret = 0;
	u64 rtmr;
	struct tdx_gen_quote tdquote_req;

	mutex_lock(&attestation_lock);

	switch (cmd) {
	case TDX_CMD_GET_TDREPORT:
		if (copy_from_user(report_data, argp, TDX_REPORT_DATA_LEN)) {
			ret = -EFAULT;
			break;
		}

		/* Generate TDREPORT_STRUCT */
		if (tdx_mcall_tdreport(virt_to_phys(tdreport_data),
				       virt_to_phys(report_data))) {
			ret = -EIO;
			break;
		}

		if (copy_to_user(argp, tdreport_data, TDX_TDREPORT_LEN))
			ret = -EFAULT;
		break;
	case TDX_CMD_GEN_QUOTE:
		reinit_completion(&attestation_done);

		/* Copy TDREPORT data from user buffer */
		if (copy_from_user(&tdquote_req, argp, sizeof(struct tdx_gen_quote))) {
			ret = -EFAULT;
			break;
		}

		if (tdquote_req.len <= 0 || tdquote_req.len > GET_QUOTE_MAX_SIZE) {
			ret = -EINVAL;
			break;
		}

		if (copy_from_user(tdquote_data, tdquote_req.buf, tdquote_req.len)) {
			ret = -EFAULT;
			break;
		}

		/* Submit GetQuote Request */
		if (tdx_hcall_get_quote(virt_to_phys(tdquote_data))) {
			ret = -EIO;
			break;
		}

		/* Wait for attestation completion */
		ret = wait_for_completion_interruptible_timeout(
				&attestation_done,
				msecs_to_jiffies(GET_QUOTE_TIMEOUT));
		if (ret <= 0) {
			ret = -EIO;
			break;
		}

		/* ret will be positive if completed. */
		ret = 0;

		if (copy_to_user(tdquote_req.buf, tdquote_data, tdquote_req.len))
			ret = -EFAULT;

		break;
	case TDX_CMD_GET_QUOTE_SIZE:
		ret = put_user(QUOTE_SIZE, (u64 __user *)argp);
		break;

	case TDX_CMD_EXTEND_RTMR:
		BUILD_BUG_ON(TDX_TDREPORT_LEN < TDX_EXTEND_LEN);

		ret = -EFAULT;

		if (get_user(rtmr, (u64 __user *)argp))
			break;
		/* Don't allow to extend BIOS/kernel RTMRs */
		if (rtmr == 0 || rtmr == 1) {
			ret = -EINVAL;
			break;
		}
		if (copy_from_user(report_data, argp + 8, TDX_EXTEND_LEN))
			break;

		ret = 0;
		if (tdx_mcall_rtmr_extend(virt_to_phys(report_data), rtmr))
			ret = -EIO;

		break;

	case TDX_CMD_GET_EXTEND_SIZE:
		ret = put_user(TDX_EXTEND_LEN, (u64 __user *)argp);
		break;

	default:
		pr_err("cmd %d not supported\n", cmd);
		break;
	}

	mutex_unlock(&attestation_lock);

	return ret;
}

static const struct file_operations tdx_attest_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= tdx_attest_ioctl,
	.llseek		= no_llseek,
};

static struct miscdevice tdx_attest_device = {
	.minor          = MISC_DYNAMIC_MINOR,
	.name           = "tdx-attest",
	.fops           = &tdx_attest_fops,
};

static int __init tdx_attest_init(void)
{
	dma_addr_t handle;
	long ret = 0;

	ret = misc_register(&tdx_attest_device);
	if (ret) {
		pr_err("misc device registration failed\n");
		return ret;
	}

	/*
	 * tdreport_data needs to be 64-byte aligned.
	 * Full page alignment is more than enough.
	 */
	tdreport_data = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
	if (!tdreport_data) {
		ret = -ENOMEM;
		goto failed;
	}

	ret = dma_set_coherent_mask(tdx_attest_device.this_device,
				    DMA_BIT_MASK(64));
	if (ret) {
		pr_err("dma set coherent mask failed\n");
		goto failed;
	}

	/* Allocate DMA buffer to get TDQUOTE data from the VMM */
	tdquote_data = dma_alloc_coherent(tdx_attest_device.this_device,
					  GET_QUOTE_MAX_SIZE, &handle,
					  GFP_KERNEL | __GFP_ZERO);
	if (!tdquote_data) {
		ret = -ENOMEM;
		goto failed;
	}

	tdquote_dma_handle =  handle;

	/*
	 * Currently tdx_event_notify_handler is only used in attestation
	 * driver. But, WRITE_ONCE is used as benign data race notice.
	 */
	WRITE_ONCE(tdx_event_notify_handler, attestation_callback_handler);

	pr_debug("module initialization success\n");

	return 0;

failed:
	if (tdreport_data)
		free_pages((unsigned long)tdreport_data, 0);

	misc_deregister(&tdx_attest_device);

	pr_debug("module initialization failed\n");

	return ret;
}

static void __exit tdx_attest_exit(void)
{
	mutex_lock(&attestation_lock);

	dma_free_coherent(tdx_attest_device.this_device, GET_QUOTE_MAX_SIZE,
			  tdquote_data, tdquote_dma_handle);
	free_pages((unsigned long)tdreport_data, 0);
	misc_deregister(&tdx_attest_device);
	/*
	 * Currently tdx_event_notify_handler is only used in attestation
	 * driver. But, WRITE_ONCE is used as benign data race notice.
	 */
	WRITE_ONCE(tdx_event_notify_handler, NULL);
	mutex_unlock(&attestation_lock);
	pr_debug("module is successfully removed\n");
}

module_init(tdx_attest_init);
module_exit(tdx_attest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX attestation driver");
MODULE_LICENSE("GPL");
