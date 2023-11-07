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
#include <linux/ctype.h>

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
 * invoked infrequently, however configfs allows for multiple agents to
 * own their own report generation instances to generate reports as
 * often as needed.
 *
 * The attestation report format is TSM provider specific, when / if a standard
 * materializes that can be published instead of the vendor layout. Until then
 * the 'provider' attribute indicates the format of 'outblob', and optionally
 * 'auxblob'.
 */

struct tsm_report_state {
	struct tsm_report report;
	unsigned long write_generation;
	unsigned long read_generation;
	struct config_item cfg;
};

struct tsm_rtmr_state {
	struct tsm_rtmr rtmr;
	unsigned long write_generation;
	unsigned long read_generation;
	struct config_item cfg;
};

enum tsm_data_select {
	TSM_REPORT,
	TSM_CERTS,
};

static struct tsm_rtmr *to_tsm_rtmr(struct config_item *cfg)
{
	struct tsm_rtmr_state *state =
		container_of(cfg, struct tsm_rtmr_state, cfg);

	return &state->rtmr;
}

static struct tsm_rtmr_state *to_rtmr_state(struct tsm_rtmr *rtmr)
{
	return container_of(rtmr, struct tsm_rtmr_state, rtmr);
}

static int try_rtmr_advance_write_generation(struct tsm_rtmr *rtmr)
{
	struct tsm_rtmr_state *state = to_rtmr_state(rtmr);

	lockdep_assert_held_write(&tsm_rwsem);

	/* Handle wrap of write_generation due to malicious user writes without any read */
	if (state->write_generation == state->read_generation - 1)
		return -EBUSY;

	state->write_generation++;

	return 0;
}

static ssize_t tsm_rtmr_index_store(struct config_item *cfg, const char *buf, size_t len)
{
	struct tsm_rtmr *rtmr = to_tsm_rtmr(cfg);
	unsigned int val;
	int rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc)
		return rc;

	if (val < provider.ops->min_rtmr_index || val >  provider.ops->max_rtmr_index)
		return -EINVAL;

	guard(rwsem_write)(&tsm_rwsem);

	rc = try_rtmr_advance_write_generation(rtmr);
	if (rc)
		return rc;

	rtmr->index = val;

	return len;
}
CONFIGFS_ATTR_WO(tsm_rtmr_, index);

static ssize_t tsm_rtmr_allowed_index_show(struct config_item *cfg, char *buf)
{
	guard(rwsem_read)(&tsm_rwsem);

	return sysfs_emit(buf, "%u-%u\n", provider.ops->min_rtmr_index,
			  provider.ops->max_rtmr_index);
}
CONFIGFS_ATTR_RO(tsm_rtmr_, allowed_index);

static ssize_t tsm_rtmr_data_write(struct config_item *cfg, const void *buf, size_t count)
{
	struct tsm_rtmr *rtmr = to_tsm_rtmr(cfg);
	int rc;

	guard(rwsem_write)(&tsm_rwsem);

	rc = try_rtmr_advance_write_generation(rtmr);
	if (rc)
		return rc;

	rtmr->data_len = count;

	memcpy(rtmr->data, buf, count);

	return count;
}
CONFIGFS_BIN_ATTR_WO(tsm_rtmr_, data, NULL, TSM_RTMR_DATA_MAX);

static ssize_t tsm_rtmr_status_show(struct config_item *cfg, char *buf)
{
	struct tsm_rtmr *rtmr = to_tsm_rtmr(cfg);
	struct tsm_rtmr_state *state = to_rtmr_state(rtmr);
	const struct tsm_ops *ops;
	size_t rc;

	guard(rwsem_read)(&tsm_rwsem);

	ops = provider.ops;

	if (!rtmr->data_len)
		return -EINVAL;

	if (state->write_generation > 0 && state->read_generation == state->write_generation)
		goto out;

	rc = ops->update_rtmr(rtmr, provider.data);
	if (rc < 0)
		return rc;

	state->read_generation = state->write_generation;
	rtmr->status = rc;
out:
	return sysfs_emit(buf, "%d\n", rtmr->status);
}
CONFIGFS_ATTR_RO(tsm_rtmr_, status);

static ssize_t tsm_rtmr_generation_show(struct config_item *cfg, char *buf)
{
	struct tsm_rtmr *rtmr = to_tsm_rtmr(cfg);
	struct tsm_rtmr_state *state = to_rtmr_state(rtmr);

	guard(rwsem_read)(&tsm_rwsem);

	return sysfs_emit(buf, "%lu\n", state->write_generation);
}
CONFIGFS_ATTR_RO(tsm_rtmr_, generation);

static struct configfs_bin_attribute *tsm_rtmr_bin_attrs[] = {
	&tsm_rtmr_attr_data,
	NULL,
};

static struct configfs_attribute *tsm_rtmr_attrs[] = {
	&tsm_rtmr_attr_generation,
	&tsm_rtmr_attr_index,
	&tsm_rtmr_attr_status,
	&tsm_rtmr_attr_allowed_index,
	NULL,
};

static void tsm_rtmr_item_release(struct config_item *cfg)
{
	struct tsm_rtmr *rtmr = to_tsm_rtmr(cfg);
	struct tsm_rtmr_state *state = to_rtmr_state(rtmr);

	kfree(state);
}

static struct configfs_item_operations tsm_rtmr_item_ops = {
	.release = tsm_rtmr_item_release,
};

const struct config_item_type tsm_rtmr_default_type = {
	.ct_owner = THIS_MODULE,
	.ct_bin_attrs = tsm_rtmr_bin_attrs,
	.ct_attrs = tsm_rtmr_attrs,
	.ct_item_ops = &tsm_rtmr_item_ops,
};
EXPORT_SYMBOL_GPL(tsm_rtmr_default_type);

static struct config_item *tsm_rtmr_make_item(struct config_group *group,
						     const char *name)
{
	struct tsm_rtmr_state *state;

	guard(rwsem_read)(&tsm_rwsem);

	if (!provider.ops)
		return ERR_PTR(-ENXIO);

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&state->cfg, name, &tsm_rtmr_default_type);

	return &state->cfg;
}

static struct configfs_group_operations tsm_rtmr_group_ops = {
	.make_item = tsm_rtmr_make_item,
};

static const struct config_item_type tsm_rtmr_type = {
	.ct_owner = THIS_MODULE,
	.ct_group_ops = &tsm_rtmr_group_ops,
};

static struct tsm_report *to_tsm_report(struct config_item *cfg)
{
	struct tsm_report_state *state =
		container_of(cfg, struct tsm_report_state, cfg);

	return &state->report;
}

static struct tsm_report_state *to_state(struct tsm_report *report)
{
	return container_of(report, struct tsm_report_state, report);
}

static int try_advance_write_generation(struct tsm_report *report)
{
	struct tsm_report_state *state = to_state(report);

	lockdep_assert_held_write(&tsm_rwsem);

	/*
	 * Malicious or broken userspace has written enough times for
	 * read_generation == write_generation by modular arithmetic without an
	 * interim read. Stop accepting updates until the current report
	 * configuration is read.
	 */
	if (state->write_generation == state->read_generation - 1)
		return -EBUSY;
	state->write_generation++;
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
	struct tsm_report_state *state = to_state(report);

	guard(rwsem_read)(&tsm_rwsem);
	return sysfs_emit(buf, "%lu\n", state->write_generation);
}
CONFIGFS_ATTR_RO(tsm_report_, generation);

static ssize_t tsm_report_provider_show(struct config_item *cfg, char *buf)
{
	guard(rwsem_read)(&tsm_rwsem);
	return sysfs_emit(buf, "%s\n", provider.ops->name);
}
CONFIGFS_ATTR_RO(tsm_report_, provider);

static ssize_t tsm_report_remote_guid_show(struct config_item *cfg, char *buf)
{
	struct tsm_report *report = to_tsm_report(cfg);

	guard(rwsem_read)(&tsm_rwsem);

	return sysfs_emit(buf, "%pUb\n", &report->desc.remote_guid);
}

int str_to_guid(const char *buf, u8 *guid, size_t len)
{
	const char *p = buf;
	int i;

	for (i = 0; i < UUID_SIZE; i++) {
		if (p + 2 > buf + len)
			return -EINVAL;

		if (!isxdigit(p[0]) || !isxdigit(p[1]))
			return -EINVAL;

		guid[i] = (hex_to_bin(p[0]) << 4) | hex_to_bin(p[1]);
		p += 2;

		if (*p == '-' || *p == ':')
			p++;
	}

	return 0;
}

static ssize_t tsm_report_remote_guid_store(struct config_item *cfg,
					    const char *buf, size_t len)
{
	struct tsm_report *report = to_tsm_report(cfg);
	u8 guid[UUID_SIZE];
	int rc;

	guard(rwsem_write)(&tsm_rwsem);

	rc = try_advance_write_generation(report);
	if (rc)
		return rc;

	rc = str_to_guid(buf, guid, len);
	if (rc)
		return rc;

	memcpy(&report->desc.remote_guid, guid, sizeof(guid));

	return len;
}
CONFIGFS_ATTR(tsm_report_, remote_guid);

static ssize_t __read_report(struct tsm_report *report, void *buf, size_t count,
			     enum tsm_data_select select)
{
	loff_t offset = 0;
	ssize_t len;
	u8 *out;

	if (select == TSM_REPORT) {
		out = report->outblob;
		len = report->outblob_len;
	} else {
		out = report->auxblob;
		len = report->auxblob_len;
	}

	/*
	 * Recall that a NULL @buf is configfs requesting the size of
	 * the buffer.
	 */
	if (!buf)
		return len;
	return memory_read_from_buffer(buf, count, &offset, out, len);
}

static ssize_t read_cached_report(struct tsm_report *report, void *buf,
				  size_t count, enum tsm_data_select select)
{
	struct tsm_report_state *state = to_state(report);

	guard(rwsem_read)(&tsm_rwsem);
	if (!report->desc.inblob_len)
		return -EINVAL;

	/*
	 * A given TSM backend always fills in ->outblob regardless of
	 * whether the report includes an auxblob or not.
	 */
	if (!report->outblob ||
	    state->read_generation != state->write_generation)
		return -EWOULDBLOCK;

	return __read_report(report, buf, count, select);
}

static ssize_t tsm_report_read(struct tsm_report *report, void *buf,
			       size_t count, enum tsm_data_select select)
{
	struct tsm_report_state *state = to_state(report);
	const struct tsm_ops *ops;
	ssize_t rc;

	/* try to read from the existing report if present and valid... */
	rc = read_cached_report(report, buf, count, select);
	if (rc >= 0 || rc != -EWOULDBLOCK)
		return rc;

	/* slow path, report may need to be regenerated... */
	guard(rwsem_write)(&tsm_rwsem);
	ops = provider.ops;
	if (!ops)
		return -ENOTTY;
	if (!report->desc.inblob_len)
		return -EINVAL;

	/* did another thread already generate this report? */
	if (report->outblob &&
	    state->read_generation == state->write_generation)
		goto out;

	kvfree(report->outblob);
	kvfree(report->auxblob);
	report->outblob = NULL;
	report->auxblob = NULL;
	rc = ops->report_new(report, provider.data);
	if (rc < 0)
		return rc;
	state->read_generation = state->write_generation;
out:
	return __read_report(report, buf, count, select);
}

static ssize_t tsm_report_outblob_read(struct config_item *cfg, void *buf,
				       size_t count)
{
	struct tsm_report *report = to_tsm_report(cfg);

	return tsm_report_read(report, buf, count, TSM_REPORT);
}
CONFIGFS_BIN_ATTR_RO(tsm_report_, outblob, NULL, TSM_OUTBLOB_MAX);

static ssize_t tsm_report_auxblob_read(struct config_item *cfg, void *buf,
				       size_t count)
{
	struct tsm_report *report = to_tsm_report(cfg);

	return tsm_report_read(report, buf, count, TSM_CERTS);
}
CONFIGFS_BIN_ATTR_RO(tsm_report_, auxblob, NULL, TSM_OUTBLOB_MAX);

#define TSM_DEFAULT_ATTRS() \
	&tsm_report_attr_generation, \
	&tsm_report_attr_provider, \
	&tsm_report_attr_remote_guid

static struct configfs_attribute *tsm_report_attrs[] = {
	TSM_DEFAULT_ATTRS(),
	NULL,
};

static struct configfs_attribute *tsm_report_extra_attrs[] = {
	TSM_DEFAULT_ATTRS(),
	&tsm_report_attr_privlevel,
	&tsm_report_attr_privlevel_floor,
	NULL,
};

#define TSM_DEFAULT_BIN_ATTRS() \
	&tsm_report_attr_inblob, \
	&tsm_report_attr_outblob

static struct configfs_bin_attribute *tsm_report_bin_attrs[] = {
	TSM_DEFAULT_BIN_ATTRS(),
	NULL,
};

static struct configfs_bin_attribute *tsm_report_bin_extra_attrs[] = {
	TSM_DEFAULT_BIN_ATTRS(),
	&tsm_report_attr_auxblob,
	NULL,
};

static void tsm_report_item_release(struct config_item *cfg)
{
	struct tsm_report *report = to_tsm_report(cfg);
	struct tsm_report_state *state = to_state(report);

	kvfree(report->auxblob);
	kvfree(report->outblob);
	kfree(state);
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

const struct config_item_type tsm_report_extra_type = {
	.ct_owner = THIS_MODULE,
	.ct_bin_attrs = tsm_report_bin_extra_attrs,
	.ct_attrs = tsm_report_extra_attrs,
	.ct_item_ops = &tsm_report_item_ops,
};
EXPORT_SYMBOL_GPL(tsm_report_extra_type);

static struct config_item *tsm_report_make_item(struct config_group *group,
						const char *name)
{
	struct tsm_report_state *state;

	guard(rwsem_read)(&tsm_rwsem);
	if (!provider.ops)
		return ERR_PTR(-ENXIO);

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&state->cfg, name, provider.type);
	return &state->cfg;
}

static struct configfs_group_operations tsm_report_group_ops = {
	.make_item = tsm_report_make_item,
};

static const struct config_item_type tsm_root_group_type = {
	.ct_owner = THIS_MODULE,
};

static const struct config_item_type tsm_reports_type = {
	.ct_owner = THIS_MODULE,
	.ct_group_ops = &tsm_report_group_ops,
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

int tsm_register(const struct tsm_ops *ops, void *priv,
		 const struct config_item_type *type)
{
	const struct tsm_ops *conflict;

	if (!type)
		type = &tsm_report_default_type;
	if (!(type == &tsm_report_default_type || type == &tsm_report_extra_type))
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
EXPORT_SYMBOL_GPL(tsm_register);

int tsm_unregister(const struct tsm_ops *ops)
{
	guard(rwsem_write)(&tsm_rwsem);
	if (ops != provider.ops)
		return -EBUSY;
	provider.ops = NULL;
	provider.data = NULL;
	provider.type = NULL;
	return 0;
}
EXPORT_SYMBOL_GPL(tsm_unregister);

static struct config_group *tsm_report_group;
static struct config_group *tsm_rtmr_group;

static int __init tsm_init(void)
{
	struct config_group *root = &tsm_configfs.su_group;
	struct config_group *tsm, *tsm_rtmr;
	int rc;

	config_group_init(root);
	rc = configfs_register_subsystem(&tsm_configfs);
	if (rc)
		return rc;

	tsm = configfs_register_default_group(root, "report",
					      &tsm_reports_type);
	if (IS_ERR(tsm)) {
		rc = PTR_ERR(tsm);
		goto free_subsys;
	}

	tsm_rtmr = configfs_register_default_group(root, "rtmr",
					      &tsm_rtmr_type);
	if (IS_ERR(tsm_rtmr)) {
		rc = PTR_ERR(tsm_rtmr);
		goto free_report;
	}

	tsm_report_group = tsm;
	tsm_rtmr_group = tsm_rtmr;

	return 0;

free_report:
	configfs_unregister_default_group(tsm);
free_subsys:
	configfs_unregister_subsystem(&tsm_configfs);

	return rc;
}
module_init(tsm_init);

static void __exit tsm_exit(void)
{
	configfs_unregister_default_group(tsm_rtmr_group);
	configfs_unregister_default_group(tsm_report_group);
	configfs_unregister_subsystem(&tsm_configfs);
}
module_exit(tsm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Provide Trusted Security Module attestation reports via configfs");
