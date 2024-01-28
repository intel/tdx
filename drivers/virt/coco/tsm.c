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
#include <linux/tpm.h>

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

enum tsm_data_select {
	TSM_REPORT,
	TSM_CERTS,
};

/**
 * DOC: Trusted Security Module (TSM) Runtime Measurement Register (RTMR) Interface
 *
 * The TSM RTMR interface is a common ABI for allowing TVMs to extend
 * and read measurement registers at runtime, i.e. after the TVM initial
 * measurement is finalized. TSMs that support such capability will typically
 * include all runtime measurement registers values into their signed
 * attestation report, providing the TVM post-boot measurements to e.g. remote
 * attestation services.
 *
 * A TVM uses the TSM RTMR configfs ABI to create all runtime measurement
 * registers (RTMR) that it needs. Each created RTMR must be configured first
 * before being readable and extensible. TVM configures an RTMR by setting its
 * index and optionally by mapping it to one or more TCG PCR indexes.
 *
 * A TSM backend statically declares the number of RTMRs it supports and which
 * hash algorithm must be used when extending them. This declaration is done
 * through the tsm_capabilities structure, at TSM registration time (see
 * tsm_register()).
 */

/**
 * struct tsm_rtmr_state - tracks the state of a TSM RTMR.
 * @index: The RTMR hardware index.
 * @alg: The hash algorithm used for this RTMR.
 * @digest: The RTMR cached digest value.
 * @cached_digest: Is the RTMR cached digest valid or not.
 * @cfg: The configfs item for this RTMR.
 */
struct tsm_rtmr_state {
	u32 index;
	enum hash_algo alg;
	u8 digest[TSM_DIGEST_MAX];
	bool cached_digest;
	struct config_item cfg;
};

static bool is_rtmr_configured(struct tsm_rtmr_state *rtmr_state)
{
	return rtmr_state->index != U32_MAX;
}

/**
 * struct tsm_rtmrs_state - tracks the state of all RTMRs for a TSM.
 * @rtmrs: The array of all created RTMRs.
 * @tcg_map: A mapping between TCG PCR and RTMRs, indexed by PCR indexes.
 * Entry `i` on this map points to an RTMR that covers TCG PCR[i] for the TSM
 * hash algorithm.
 * @group: The configfs group for a TSM RTMRs.
 */
static struct tsm_rtmrs_state {
	struct tsm_rtmr_state **rtmrs;
	const struct tsm_rtmr_state *tcg_map[TPM2_PLATFORM_PCR];
	struct config_group *group;
} *tsm_rtmrs;

static int tsm_rtmr_read(struct tsm_provider *tsm, u32 idx,
			 u8 *digest, size_t digest_size)
{
	if (tsm->ops && tsm->ops->rtmr_read)
		return tsm->ops->rtmr_read(idx, digest, digest_size);

	return -ENXIO;
}

static int tsm_rtmr_extend(struct tsm_provider *tsm, u32 idx,
			   const u8 *digest, size_t digest_size)
{
	if (tsm->ops && tsm->ops->rtmr_extend)
		return tsm->ops->rtmr_extend(idx, digest, digest_size);

	return -ENXIO;
}

static struct tsm_rtmr_state *to_tsm_rtmr_state(struct config_item *cfg)
{
	return container_of(cfg, struct tsm_rtmr_state, cfg);
}

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
	&tsm_report_attr_provider

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
