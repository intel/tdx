// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/cc_platform.h>
#include <linux/export.h>
#include <uapi/linux/virtio_ids.h>

#include <asm/tdx.h>
#include <asm/cmdline.h>

/*
 * Allow list for PCI bus
 *
 * NOTE: Device ID is duplicated here. But for small list
 * of devices, it is easier to maintain the duplicated list
 * here verses exporting the device ID table from the driver
 * and use it.
 */
struct pci_device_id pci_allow_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_NET) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_BLOCK) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_CONSOLE) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO_TRANS_ID_9P) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_NET) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_BLOCK) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_CONSOLE) },
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_9P) },
	{ 0, },
};

bool dev_authorized_init(void)
{
	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return false;

	return true;
}

bool arch_dev_authorized(struct device *dev)
{
	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return true;

	if (!dev_is_pci(dev))
		return dev->authorized;

	if (pci_match_id(pci_allow_ids, to_pci_dev(dev)))
		return true;

	return false;
}

void __init tdx_filter_init(void)
{
	if (!cc_platform_has(CC_ATTR_GUEST_DEVICE_FILTER))
		return;

	pr_info("Enabled TDX guest device filter\n");
}
