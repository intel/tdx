// SPDX-License-Identifier: GPL-2.0
/*
 * TDX host user interface driver
 *
 * Copyright (C) 2025 Intel Corporation
 */

#include <linux/bitfield.h>
#include <linux/device/faux.h>
#include <linux/dmar.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/sysfs.h>
#include <linux/pci.h>
#include <linux/pci-tsm.h>
#include <linux/tsm.h>

#include <asm/cpu_device_id.h>
#include <asm/seamldr.h>
#include <asm/tdx.h>

static const struct x86_cpu_id tdx_host_ids[] = {
	X86_MATCH_FEATURE(X86_FEATURE_TDX_HOST_PLATFORM, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, tdx_host_ids);

static const struct tdx_sys_info *tdx_sysinfo;

#define TDISP_FUNC_ID		GENMASK(15, 0)
#define TDISP_FUNC_ID_SEGMENT		GENMASK(23, 16)
#define TDISP_FUNC_ID_SEG_VALID		BIT(24)

static inline u32 tdisp_func_id(struct pci_dev *pdev)
{
	u32 func_id;

	func_id = FIELD_PREP(TDISP_FUNC_ID_SEGMENT, pci_domain_nr(pdev->bus));
	if (func_id)
		func_id |= TDISP_FUNC_ID_SEG_VALID;
	func_id |= FIELD_PREP(TDISP_FUNC_ID,
			      PCI_DEVID(pdev->bus->number, pdev->devfn));

	return func_id;
}

struct tdx_tsm_link {
	struct pci_tsm_pf0 pci;
	u32 func_id;

	u64 spdm_id;
	unsigned int spdm_mt_nr_pages;
	void *spdm_mt;
};

static struct tdx_tsm_link *to_tdx_tsm_link(struct pci_tsm *tsm)
{
	return container_of(tsm, struct tdx_tsm_link, pci.base_tsm);
}

static int tdx_spdm_create(struct tdx_tsm_link *tlink)
{
	unsigned int nr_pages = tdx_sysinfo->tdx_connect.spdm_mt_page_count;
	struct tdx_hpa_list_info info;
	u64 spdm_id, sret;
	void *spdm_mt;
	int ret;

	spdm_mt = alloc_pages_exact(nr_pages * PAGE_SIZE,
				    GFP_KERNEL | __GFP_ZERO);
	if (!spdm_mt)
		return -ENOMEM;

	ret = tdx_hpa_list_info_setup(&info, spdm_mt, nr_pages);
	if (ret)
		goto out_spdm_mt_free;

	sret = tdh_spdm_create(tlink->func_id, &info, &spdm_id);

	tdx_hpa_list_info_free(&info);

	if (sret) {
		ret = -EIO;
		goto out_spdm_mt_free;
	}

	tlink->spdm_id = spdm_id;
	tlink->spdm_mt = spdm_mt;
	tlink->spdm_mt_nr_pages = nr_pages;
	return 0;

out_spdm_mt_free:
	free_pages_exact(tlink->spdm_mt, nr_pages * PAGE_SIZE);
	return ret;
}

static void tdx_spdm_delete(struct tdx_tsm_link *tlink)
{
	struct pci_dev *pdev = tlink->pci.base_tsm.pdev;
	u64 sret;

	sret = tdh_spdm_delete(tlink->spdm_id);
	if (sret) {
		/* leak the metadata pages */
		pci_err(pdev, "fail to delete spdm 0x%llx\n", sret);
		return;
	}

	free_pages_exact(tlink->spdm_mt, tlink->spdm_mt_nr_pages * PAGE_SIZE);
	return;
}

static int tdx_spdm_session_setup(struct tdx_tsm_link *tlink)
{
	return tdx_spdm_create(tlink);
}

static void tdx_spdm_session_teardown(struct tdx_tsm_link *tlink)
{
	tdx_spdm_delete(tlink);
}

static int tdx_tsm_link_connect(struct pci_dev *pdev)
{
	struct tdx_tsm_link *tlink = to_tdx_tsm_link(pdev->tsm);

	return tdx_spdm_session_setup(tlink);
}

static void tdx_tsm_link_disconnect(struct pci_dev *pdev)
{
	struct tdx_tsm_link *tlink = to_tdx_tsm_link(pdev->tsm);

	tdx_spdm_session_teardown(tlink);
}

static struct pci_tsm *tdx_tsm_link_pf0_probe(struct tsm_dev *tsm_dev,
					      struct pci_dev *pdev)
{
	struct tdx_tsm_link *tlink;
	int ret;

	tlink = kzalloc_obj(*tlink);
	if (!tlink)
		return NULL;

	ret = pci_tsm_pf0_constructor(pdev, &tlink->pci, tsm_dev);
	if (ret) {
		kfree(tlink);
		return NULL;
	}

	tlink->func_id = tdisp_func_id(pdev);

	return &tlink->pci.base_tsm;
}

static void tdx_tsm_link_pf0_remove(struct pci_tsm *tsm)
{
	struct tdx_tsm_link *tlink = to_tdx_tsm_link(tsm);

	pci_tsm_pf0_destructor(&tlink->pci);
	kfree(tlink);
}

static struct pci_tsm *tdx_tsm_link_fn_probe(struct tsm_dev *tsm_dev,
					     struct pci_dev *pdev)
{
	struct pci_tsm *tsm;
	int ret;

	tsm = kzalloc_obj(*tsm);
	if (!tsm)
		return NULL;

	ret = pci_tsm_link_constructor(pdev, tsm, tsm_dev);
	if (ret) {
		kfree(tsm);
		return NULL;
	}

	return tsm;
}

static struct pci_tsm *tdx_tsm_link_probe(struct tsm_dev *tsm_dev,
					  struct pci_dev *pdev)
{
	if (is_pci_tsm_pf0(pdev))
		return tdx_tsm_link_pf0_probe(tsm_dev, pdev);

	return tdx_tsm_link_fn_probe(tsm_dev, pdev);
}

static void tdx_tsm_link_remove(struct pci_tsm *tsm)
{
	if (is_pci_tsm_pf0(tsm->pdev)) {
		tdx_tsm_link_pf0_remove(tsm);
		return;
	}

	/* for sub-functions */
	kfree(tsm);
}

static struct pci_tsm_ops tdx_tsm_link_ops = {
	.probe = tdx_tsm_link_probe,
	.remove = tdx_tsm_link_remove,
	.connect = tdx_tsm_link_connect,
	.disconnect = tdx_tsm_link_disconnect,
};

static void unregister_link_tsm(void *link)
{
	tsm_unregister(link);
}

static void release_intel_tdxc(void *data)
{
	intel_tdxc_exit();
}

static int tdx_tdisp_init(struct device *dev)
{
	struct tsm_dev *link;
	int ret;

	if (!tdx_supports_tdisp(tdx_sysinfo))
		return 0;

	ret = intel_tdxc_init();
	if (ret)
		return dev_err_probe(dev, ret, "Enable tdx iommu failed\n");

	ret = devm_add_action_or_reset(dev, release_intel_tdxc, NULL);
	if (ret)
		return ret;

	link = tsm_register(dev, &tdx_tsm_link_ops);
	if (IS_ERR(link))
		return dev_err_probe(dev, PTR_ERR(link),
				     "failed to register TSM\n");

	return devm_add_action_or_reset(dev, unregister_link_tsm, link);
}

static ssize_t version_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	const struct tdx_sys_info *tdx_sysinfo = tdx_get_sysinfo();
	const struct tdx_sys_info_version *ver;
	int ret;

	if (!tdx_sysinfo)
		return -ENXIO;

	/*
	 * The version number can change during an update.
	 * Lock out updates while printing the version.
	 */
	seamldr_lock_module_update();

	ver = &tdx_sysinfo->version;
	ret = sysfs_emit(buf, TDX_VERSION_FMT "\n", ver->major_version,
						    ver->minor_version,
						    ver->update_version);
	seamldr_unlock_module_update();

	return ret;
}
static DEVICE_ATTR_RO(version);

static struct attribute *tdx_host_attrs[] = {
	&dev_attr_version.attr,
	NULL,
};

static const struct attribute_group tdx_host_group = {
	.attrs = tdx_host_attrs,
};

static ssize_t seamldr_version_show(struct device *dev, struct device_attribute *attr,
				    char *buf)
{
	struct seamldr_info info;
	int ret;

	ret = seamldr_get_info(&info);
	if (ret)
		return ret;

	return sysfs_emit(buf, TDX_VERSION_FMT "\n", info.major_version,
						     info.minor_version,
						     info.update_version);
}

static ssize_t num_remaining_updates_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct seamldr_info info;
	int ret;

	ret = seamldr_get_info(&info);
	if (ret)
		return ret;

	return sysfs_emit(buf, "%u\n", info.num_remaining_updates);
}

/*
 * These attributes are intended for managing TDX module updates. Reading
 * them issues a slow, serialized P-SEAMLDR query, so keep them admin-only.
 */
static DEVICE_ATTR_ADMIN_RO(seamldr_version);
static DEVICE_ATTR_ADMIN_RO(num_remaining_updates);

static struct attribute *seamldr_attrs[] = {
	&dev_attr_seamldr_version.attr,
	&dev_attr_num_remaining_updates.attr,
	NULL,
};

static bool supports_runtime_update(void)
{
	const struct tdx_sys_info *sysinfo = tdx_get_sysinfo();

	if (!sysinfo)
		return false;

	if (!tdx_supports_runtime_update(sysinfo))
		return false;

	/*
	 * This bug makes P-SEAMLDR calls clobber the current VMCS
	 * which breaks KVM. Avoid P-SEAMLDR calls by hiding all
	 * attributes if the CPU has this bug.
	 */
	if (boot_cpu_has_bug(X86_BUG_SEAMRET_INVD_VMCS))
		return false;

	return true;
}

static umode_t seamldr_group_visible(struct kobject *kobj, struct attribute *attr, int idx)
{
	if (!supports_runtime_update())
		return 0;

	return attr->mode;
}

static const struct attribute_group seamldr_group = {
	.attrs = seamldr_attrs,
	.is_visible = seamldr_group_visible,
};

static const struct attribute_group *tdx_host_groups[] = {
	&tdx_host_group,
	&seamldr_group,
	NULL,
};

static enum fw_upload_err tdx_fw_prepare(struct fw_upload *fwl,
					 const u8 *data, u32 data_len)
{
	return FW_UPLOAD_ERR_NONE;
}

static enum fw_upload_err tdx_fw_write(struct fw_upload *fwl, const u8 *data,
				       u32 offset, u32 data_len, u32 *written)
{
	int ret;

	ret = seamldr_install_module(data, data_len);
	switch (ret) {
	case 0:
		*written = data_len;
		return FW_UPLOAD_ERR_NONE;
	default:
		return FW_UPLOAD_ERR_FW_INVALID;
	}
}

static enum fw_upload_err tdx_fw_poll_complete(struct fw_upload *fwl)
{
	/*
	 * The upload completed during tdx_fw_write().
	 * Never poll for completion.
	 */
	return FW_UPLOAD_ERR_NONE;
}

static void tdx_fw_cancel(struct fw_upload *fwl)
{
	/*
	 * TDX module updates are not cancellable.
	 * Provide a no-op callback to satisfy fw_upload_ops.
	 */
}

static const struct fw_upload_ops tdx_fw_ops = {
	.prepare	= tdx_fw_prepare,
	.write		= tdx_fw_write,
	.poll_complete	= tdx_fw_poll_complete,
	.cancel		= tdx_fw_cancel,
};

static void seamldr_deinit(void *tdx_fwl)
{
	firmware_upload_unregister(tdx_fwl);
}

static int seamldr_init(struct device *dev)
{
	struct fw_upload *tdx_fwl;

	if (!supports_runtime_update())
		return 0;

	tdx_fwl = firmware_upload_register(THIS_MODULE, dev, "tdx_module",
					   &tdx_fw_ops, NULL);
	if (IS_ERR(tdx_fwl))
		return PTR_ERR(tdx_fwl);

	return devm_add_action_or_reset(dev, seamldr_deinit, tdx_fwl);
}

static int tdx_host_probe(struct faux_device *fdev)
{
	int ret;

	ret = seamldr_init(&fdev->dev);
	if (ret)
		return ret;

	return tdx_tdisp_init(&fdev->dev);
}

static const struct faux_device_ops tdx_host_ops = {
	.probe		= tdx_host_probe,
};

static struct faux_device *fdev;

static int __init tdx_host_init(void)
{
	if (!x86_match_cpu(tdx_host_ids))
		return -ENODEV;

	tdx_sysinfo = tdx_get_sysinfo();
	if (!tdx_sysinfo)
		return -ENODEV;

	fdev = faux_device_create_with_groups(KBUILD_MODNAME, NULL,
					      &tdx_host_ops,
					      tdx_host_groups);
	if (!fdev)
		return -ENODEV;

	return 0;
}
module_init(tdx_host_init);

static void __exit tdx_host_exit(void)
{
	faux_device_destroy(fdev);
}
module_exit(tdx_host_exit);

MODULE_DESCRIPTION("TDX Host Services");
MODULE_LICENSE("GPL");
