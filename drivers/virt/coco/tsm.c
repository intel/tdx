// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. All rights reserved. */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/tsm.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/cleanup.h>
#include <linux/configfs.h>

static struct tsm_provider {
	const struct tsm_ops *ops;
	const struct config_item_type *type;
	void *data;
} provider;
static DECLARE_RWSEM(tsm_rwsem);

/**
 * DOC: Trusted Security Module (TSM) Attestation Report Interface
 *
 * The TSM report interface is a common provider of blobs that facilitate
 * attestation of a TVM (confidential computing guest) by an attestation
 * service. A TSM report combines a user-defined blob (likely a public-key with
 * a nonce for a key-exchange protocol) with a signed attestation report. That
 * combined blob is then used to obtain secrets provided by an agent that can
 * validate the attestation report. The expectation is that this interface is
 * invoked infrequently, likely only once at TVM boot time.
 *
 * The attestation report format is TSM provider specific, when / if a standard
 * materializes that can be published instead of the vendor layout. Until then
 * the 'provider' attribute indicates the format of 'outblob'.
 */

/**
 * struct tsm_report - track state of report generation relative to options
 * @desc: report generation options / cached report state
 * @outblob: generated evidence to provider to the attestation agent
 * @outblob_len: sizeof(outblob)
 * @write_generation: conflict detection, and report regeneration tracking
 * @read_generation: cached report invalidation tracking
 * @cfg: configfs interface
 */
struct tsm_report {
	struct tsm_desc desc;
	size_t outblob_len;
	u8 *outblob;
	unsigned long write_generation;
	unsigned long read_generation;
	struct config_item cfg;
};

static struct tsm_report *to_tsm_report(struct config_item *cfg)
{
	return container_of(cfg, struct tsm_report, cfg);
}

static int try_advance_write_generation(struct tsm_report *report)
{
	lockdep_assert_held_write(&tsm_rwsem);

	/*
	 * malicious or broken userspace is attempting to wrap read_generation,
	 * stop accepting updates until current report configuration is read.
	 */
	if (report->write_generation == report->read_generation - 1)
		return -EBUSY;
	report->write_generation++;
	return 0;
}

static ssize_t tsm_report_privlevel_store(struct config_item *cfg,
					  const char *buf, size_t len)
{
	struct tsm_report *report = to_tsm_report(cfg);
	unsigned int val;
	int rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc)
		return rc;

	/*
	 * The valid privilege levels that a TSM might accept, if it accepts a
	 * privilege level setting at all, are a max of TSM_PRIVLEVEL_MAX (see
	 * SEV-SNP GHCB) and a minimum of a TSM selected floor value no less
	 * than 0.
	 */
	if (provider.ops->privlevel_floor > val || val > TSM_PRIVLEVEL_MAX)
		return -EINVAL;

	guard(rwsem_write)(&tsm_rwsem);
	rc = try_advance_write_generation(report);
	if (rc)
		return rc;
	report->desc.privlevel = val;

	return len;
}
CONFIGFS_ATTR_WO(tsm_report_, privlevel);

static ssize_t tsm_report_privlevel_floor_show(struct config_item *cfg,
					       char *buf)
{
	guard(rwsem_read)(&tsm_rwsem);
	return sysfs_emit(buf, "%u\n", provider.ops->privlevel_floor);
}
CONFIGFS_ATTR_RO(tsm_report_, privlevel_floor);

static ssize_t tsm_report_format_store(struct config_item *cfg, const char *buf,
				       size_t len)
{
	struct tsm_report *report = to_tsm_report(cfg);
	enum tsm_format format;
	int rc;

	if (sysfs_streq(buf, "default"))
		format = TSM_FORMAT_DEFAULT;
	else if (sysfs_streq(buf, "extended"))
		format = TSM_FORMAT_EXTENDED;
	else
		return -EINVAL;

	guard(rwsem_write)(&tsm_rwsem);
	rc = try_advance_write_generation(report);
	if (rc)
		return rc;
	report->desc.outblob_format = format;

	return len;
}
CONFIGFS_ATTR_WO(tsm_report_, format);

static ssize_t tsm_report_inblob_write(struct config_item *cfg,
				       const void *buf, size_t count)
{
	struct tsm_report *report = to_tsm_report(cfg);
	int rc;

	guard(rwsem_write)(&tsm_rwsem);
	rc = try_advance_write_generation(report);
	if (rc)
		return rc;

	report->desc.inblob_len = count;
	memcpy(report->desc.inblob, buf, count);
	return count;
}
CONFIGFS_BIN_ATTR_WO(tsm_report_, inblob, NULL, TSM_INBLOB_MAX);

static ssize_t tsm_report_generation_show(struct config_item *cfg, char *buf)
{
	struct tsm_report *report = to_tsm_report(cfg);

	guard(rwsem_read)(&tsm_rwsem);
	return sysfs_emit(buf, "%lu\n", report->write_generation);
}
CONFIGFS_ATTR_RO(tsm_report_, generation);

static ssize_t tsm_report_provider_show(struct config_item *cfg, char *buf)
{
	guard(rwsem_read)(&tsm_rwsem);
	return sysfs_emit(buf, "%s\n", provider.ops->name);
}
CONFIGFS_ATTR_RO(tsm_report_, provider);

static ssize_t read_cached_report(struct tsm_report *report, void *buf, size_t count)
{
	loff_t offset = 0;

	guard(rwsem_read)(&tsm_rwsem);
	if (!report->desc.inblob_len)
		return -EINVAL;

	if (!report->outblob ||
	    report->read_generation != report->write_generation)
		return -EWOULDBLOCK;

	if (!buf)
		return report->outblob_len;
	return memory_read_from_buffer(buf, count, &offset, report->outblob,
				       report->outblob_len);
}

static ssize_t tsm_report_outblob_read(struct config_item *cfg, void *buf,
				       size_t count)
{
	struct tsm_report *report = to_tsm_report(cfg);
	const struct tsm_ops *ops;
	size_t outblob_len;
	loff_t offset = 0;
	u8 *outblob;
	ssize_t rc;

	/* try to read from the existing report if present and valid... */
	rc = read_cached_report(report, buf, count);
	if (rc >= 0 || rc != -EWOULDBLOCK)
		return rc;

	/* slow path, report may need to be regenerated... */
	guard(rwsem_write)(&tsm_rwsem);
	ops = provider.ops;
	if (!report->desc.inblob_len)
		return -EINVAL;

	/* did another thread already generate this report? */
	if (report->outblob &&
	    report->read_generation == report->write_generation)
		goto out;

	kvfree(report->outblob);
	report->outblob = NULL;
	outblob = ops->report_new(&report->desc, provider.data, &outblob_len);
	if (IS_ERR(outblob))
		return PTR_ERR(outblob);
	report->outblob_len = outblob_len;
	report->outblob = outblob;
	report->read_generation = report->write_generation;

out:
	if (!buf)
		return report->outblob_len;
	return memory_read_from_buffer(buf, count, &offset, report->outblob,
				       report->outblob_len);
}
CONFIGFS_BIN_ATTR_RO(tsm_report_, outblob, NULL, TSM_OUTBLOB_MAX);

#define TSM_DEFAULT_ATTRS() \
	&tsm_report_attr_generation, \
	&tsm_report_attr_provider

static struct configfs_attribute *tsm_report_attrs[] = {
	TSM_DEFAULT_ATTRS(),
	NULL,
};

static struct configfs_bin_attribute *tsm_report_bin_attrs[] = {
	&tsm_report_attr_inblob,
	&tsm_report_attr_outblob,
	NULL,
};

static struct configfs_attribute *tsm_report_extra_attrs[] = {
	TSM_DEFAULT_ATTRS(),
	&tsm_report_attr_format,
	&tsm_report_attr_privlevel,
	&tsm_report_attr_privlevel_floor,
	NULL,
};

static void tsm_report_item_release(struct config_item *cfg)
{
	struct tsm_report *report = to_tsm_report(cfg);

	kvfree(report->outblob);
	kfree(report);
}

static struct configfs_item_operations tsm_report_item_ops = {
	.release = tsm_report_item_release,
};

const struct config_item_type tsm_report_default_type = {
	.ct_owner = THIS_MODULE,
	.ct_bin_attrs = tsm_report_bin_attrs,
	.ct_attrs = tsm_report_attrs,
	.ct_item_ops = &tsm_report_item_ops,
};
EXPORT_SYMBOL_GPL(tsm_report_default_type);

const struct config_item_type tsm_report_ext_type = {
	.ct_owner = THIS_MODULE,
	.ct_bin_attrs = tsm_report_bin_attrs,
	.ct_attrs = tsm_report_extra_attrs,
	.ct_item_ops = &tsm_report_item_ops,
};
EXPORT_SYMBOL_GPL(tsm_report_ext_type);

static struct config_item *tsm_report_make_item(struct config_group *group,
						const char *name)
{
	struct tsm_report *report;

	guard(rwsem_read)(&tsm_rwsem);
	if (!provider.ops)
		return ERR_PTR(-ENXIO);

	report = kzalloc(sizeof(*report), GFP_KERNEL);
	if (!report)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&report->cfg, name, provider.type);
	return &report->cfg;
}

static struct configfs_group_operations tsm_report_group_ops = {
	.make_item = tsm_report_make_item,
};

static const struct config_item_type tsm_reports_type = {
	.ct_owner = THIS_MODULE,
	.ct_group_ops = &tsm_report_group_ops,
};

static const struct config_item_type tsm_root_group_type = {
	.ct_owner = THIS_MODULE,
};

static struct configfs_subsystem tsm_configfs = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "tsm",
			.ci_type = &tsm_root_group_type,
		},
	},
	.su_mutex = __MUTEX_INITIALIZER(tsm_configfs.su_mutex),
};

static struct config_group *tsm_report_group;

int register_tsm(const struct tsm_ops *ops, void *priv,
		 const struct config_item_type *type)
{
	const struct tsm_ops *conflict;

	if (!type)
		type = &tsm_report_default_type;
	if (!(type == &tsm_report_default_type || type == &tsm_report_ext_type))
		return -EINVAL;

	guard(rwsem_write)(&tsm_rwsem);
	conflict = provider.ops;
	if (conflict) {
		pr_err("\"%s\" ops already registered\n", conflict->name);
		return -EBUSY;
	}

	provider.ops = ops;
	provider.data = priv;
	provider.type = type;
	return 0;
}
EXPORT_SYMBOL_GPL(register_tsm);

int unregister_tsm(const struct tsm_ops *ops)
{
	guard(rwsem_write)(&tsm_rwsem);
	if (ops != provider.ops)
		return -EBUSY;
	provider.ops = NULL;
	provider.data = NULL;
	provider.type = NULL;
	return 0;
}
EXPORT_SYMBOL_GPL(unregister_tsm);

static int __init tsm_init(void)
{
	struct config_group *root = &tsm_configfs.su_group;
	struct config_group *tsm;
	int rc;

	config_group_init(root);
	rc = configfs_register_subsystem(&tsm_configfs);
	if (rc)
		return rc;

	tsm = configfs_register_default_group(root, "report",
					      &tsm_reports_type);
	if (IS_ERR(tsm)) {
		configfs_unregister_subsystem(&tsm_configfs);
		return PTR_ERR(tsm);
	}
	tsm_report_group = tsm;

	return 0;
}
module_init(tsm_init);

static void __exit tsm_exit(void)
{
	configfs_unregister_default_group(tsm_report_group);
	configfs_unregister_subsystem(&tsm_configfs);
}
module_exit(tsm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Provide Trusted Security Module attestation reports via configfs");
