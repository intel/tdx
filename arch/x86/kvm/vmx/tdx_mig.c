// SPDX-License-Identifier: GPL-2.0
#include <linux/anon_inodes.h>
#include <linux/kvm_host.h>

struct tdx_mig_mbmd_data {
	__u16 size;
	__u16 mig_version;
	__u16 migs_index;
	__u8  mb_type;
	__u8  rsvd0;
	__u32 mb_counter;
	__u32 mig_epoch;
	__u64 iv_counter;
	__u8  type_specific_info[];
} __packed;

struct tdx_mig_mbmd {
	struct tdx_mig_mbmd_data *data;
	uint64_t addr_and_size;
};

struct tdx_mig_stream {
	uint16_t idx;
	uint32_t buf_list_pages;
	struct tdx_mig_mbmd mbmd;
};

struct tdx_mig_state {
	/* Number of streams created */
	atomic_t streams_created;
	/*
	 * Array to store physical addresses of the migration stream context
	 * pages that have been added to the TDX module. The pages can be
	 * reclaimed from TDX when TD is torn down.
	 */
	hpa_t *migsc_paddrs;
};

struct tdx_mig_capabilities {
	uint32_t max_migs;
	uint32_t nonmem_state_pages;
};

static struct tdx_mig_capabilities tdx_mig_caps;

static void tdx_reclaim_td_page(unsigned long td_page_pa);

static int tdx_mig_capabilities_setup(void)
{
	struct tdx_module_args out;
	uint32_t immutable_state_pages, td_state_pages, vp_state_pages;
	uint64_t err;

	err = tdh_sys_rd(TDX_MD_FID_MAX_MIGS, &out);
	if (err)
		return -EIO;
	tdx_mig_caps.max_migs = out.r8;
	/*
	 * At least two migration streams (forward stream + backward stream)
	 * are required to be created.
	 */
	if (unlikely(tdx_mig_caps.max_migs < 2))
		return -EOPNOTSUPP;

	err = tdh_sys_rd(TDX_MD_FID_IMMUTABLE_STATE_PAGES, &out);
	if (err)
		return -EIO;
	immutable_state_pages = out.r8;

	err = tdh_sys_rd(TDX_MD_FID_TD_STATE_PAGES, &out);
	if (err)
		return -EIO;
	td_state_pages = out.r8;

	err = tdh_sys_rd(TDX_MD_FID_VP_STATE_PAGES, &out);
	if (err)
		return -EIO;
	vp_state_pages = out.r8;

	/*
	 * The minimal number of pages required. It hould be large enough to
	 * store all the non-memory states.
	 */
	tdx_mig_caps.nonmem_state_pages = max3(immutable_state_pages,
					       td_state_pages, vp_state_pages);

	return 0;
}

static void tdx_mig_stream_get_tdx_mig_attr(struct tdx_mig_stream *stream,
					    struct kvm_dev_tdx_mig_attr *attr)
{
	attr->version = KVM_DEV_TDX_MIG_ATTR_VERSION;
	attr->max_migs = tdx_mig_caps.max_migs;
	attr->buf_list_pages = stream->buf_list_pages;
}

static int tdx_mig_stream_get_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	struct tdx_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;

	switch (attr->group) {
	case KVM_DEV_TDX_MIG_ATTR: {
		struct kvm_dev_tdx_mig_attr tdx_mig_attr;

		if (attr->attr != sizeof(struct kvm_dev_tdx_mig_attr)) {
			pr_err("Incompatible kvm_dev_get_tdx_mig_attr\n");
			return -EINVAL;
		}

		tdx_mig_stream_get_tdx_mig_attr(stream, &tdx_mig_attr);
		if (copy_to_user(uaddr, &tdx_mig_attr, sizeof(tdx_mig_attr)))
			return -EFAULT;
		break;
	}
	default:
		return -EINVAL;
	}

	return 0;
}

static int tdx_mig_stream_set_tdx_mig_attr(struct tdx_mig_stream *stream,
					   struct kvm_dev_tdx_mig_attr *attr)
{
	uint32_t req_pages = attr->buf_list_pages;
	uint32_t min_pages = tdx_mig_caps.nonmem_state_pages;

	if (req_pages > TDX_MIG_BUF_LIST_PAGES_MAX) {
		stream->buf_list_pages = TDX_MIG_BUF_LIST_PAGES_MAX;
		pr_warn("Cut the buf_list_npages to the max supported num\n");
	} else if (req_pages < min_pages) {
		stream->buf_list_pages = min_pages;
	} else {
		stream->buf_list_pages = req_pages;
	}

	return 0;
}

static int tdx_mig_stream_mbmd_setup(struct tdx_mig_mbmd *mbmd)
{
	struct page *page;
	unsigned long mbmd_size = PAGE_SIZE;
	int order = get_order(mbmd_size);

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, order);
	if (!page)
		return -ENOMEM;

	mbmd->data = page_address(page);
	/*
	 * MBMD address and size format defined in TDX module ABI spec:
	 * Bits 63:52 - size of the MBMD buffer
	 * Bits 51:0  - host physical page frame number of the MBMD buffer
	 */
	mbmd->addr_and_size = page_to_phys(page) | (mbmd_size - 1) << 52;

	return 0;
}

static int tdx_mig_stream_setup(struct tdx_mig_stream *stream)
{
	return tdx_mig_stream_mbmd_setup(&stream->mbmd);
}

static int tdx_mig_stream_set_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	struct tdx_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;
	int ret;

	switch (attr->group) {
	case KVM_DEV_TDX_MIG_ATTR: {
		struct kvm_dev_tdx_mig_attr tdx_mig_attr;

		if (copy_from_user(&tdx_mig_attr, uaddr, sizeof(tdx_mig_attr)))
			return -EFAULT;

		if (tdx_mig_attr.version != KVM_DEV_TDX_MIG_ATTR_VERSION)
			return -EINVAL;

		ret = tdx_mig_stream_set_tdx_mig_attr(stream, &tdx_mig_attr);
		if (ret)
			break;

		ret = tdx_mig_stream_setup(stream);
		break;
	}
	default:
		return -EINVAL;
	}

	return ret;
}

static int tdx_mig_stream_mmap(struct kvm_device *dev,
				   struct vm_area_struct *vma)
{
	return -ENXIO;
}

static long tdx_mig_stream_ioctl(struct kvm_device *dev, unsigned int ioctl,
				 unsigned long arg)
{
	return -ENXIO;
}

static int tdx_mig_do_stream_create(struct kvm_tdx *kvm_tdx,
				    struct tdx_mig_stream *stream,
				    hpa_t *migsc_addr)
{
	struct tdx_module_args out;
	hpa_t migsc_va, migsc_pa;
	uint64_t err;

	/*
	 * This migration stream has been created, e.g. the previous migration
	 * session is aborted and the migration stream is retained during the
	 * TD guest lifecycle (required by the TDX migration architecture for
	 * later re-migration). No need to proceed to the creation in this
	 * case.
	 */
	if (*migsc_addr)
		return 0;

	migsc_va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!migsc_va)
		return -ENOMEM;
	migsc_pa = __pa(migsc_va);

	err = tdh_mig_stream_create(kvm_tdx->tdr_pa, migsc_pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MIG_STREAM_CREATE, err, &out);
		free_page(migsc_va);
		return -EIO;
	}

	*migsc_addr = migsc_pa;
	return 0;
}

static int tdx_mig_stream_create(struct kvm_device *dev, u32 type)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	struct tdx_mig_stream *stream;
	int ret;

	stream = kzalloc(sizeof(struct tdx_mig_stream), GFP_KERNEL_ACCOUNT);
	if (!stream)
		return -ENOMEM;

	dev->private = stream;
	stream->idx = atomic_inc_return(&mig_state->streams_created) - 1;

	ret = tdx_mig_do_stream_create(kvm_tdx, stream,
				       &mig_state->migsc_paddrs[stream->idx]);
	if (ret) {
		atomic_dec(&mig_state->streams_created);
		kfree(stream);
		return ret;
	}

	return 0;
}

static void tdx_mig_stream_release(struct kvm_device *dev)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	struct tdx_mig_stream *stream = dev->private;

	atomic_dec(&mig_state->streams_created);
	free_page((unsigned long)stream->mbmd.data);
	kfree(stream);
}

static int tdx_mig_state_create(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	hpa_t *migsc_paddrs;

	mig_state = kzalloc(sizeof(struct tdx_mig_state), GFP_KERNEL_ACCOUNT);
	if (!mig_state)
		return -ENOMEM;

	migsc_paddrs = kcalloc(tdx_mig_caps.max_migs, sizeof(hpa_t),
			       GFP_KERNEL_ACCOUNT);
	if (!migsc_paddrs) {
		kfree(mig_state);
		return -ENOMEM;
	}

	mig_state->migsc_paddrs = migsc_paddrs;
	kvm_tdx->mig_state = mig_state;
	return 0;
}

static void tdx_mig_state_destroy(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	uint32_t i;

	if (!mig_state)
		return;

	/* All the streams should have been destroyed */
	WARN_ON_ONCE(atomic_read(&mig_state->streams_created));
	for (i = 0; i < tdx_mig_caps.max_migs; i++) {
		if (!mig_state->migsc_paddrs[i])
			break;

		tdx_reclaim_td_page(mig_state->migsc_paddrs[i]);
	}

	kfree(mig_state);
	kvm_tdx->mig_state = NULL;
}

static struct kvm_device_ops kvm_tdx_mig_stream_ops = {
	.name = "kvm-tdx-mig",
	.get_attr = tdx_mig_stream_get_attr,
	.set_attr = tdx_mig_stream_set_attr,
	.mmap = tdx_mig_stream_mmap,
	.ioctl = tdx_mig_stream_ioctl,
	.create = tdx_mig_stream_create,
	.release = tdx_mig_stream_release,
};

static int kvm_tdx_mig_stream_ops_init(void)
{
	return kvm_register_device_ops(&kvm_tdx_mig_stream_ops,
				       KVM_DEV_TYPE_TDX_MIG_STREAM);
}

static void kvm_tdx_mig_stream_ops_exit(void)
{
	kvm_unregister_device_ops(KVM_DEV_TYPE_TDX_MIG_STREAM);
}
