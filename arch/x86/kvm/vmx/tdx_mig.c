// SPDX-License-Identifier: GPL-2.0
#include <linux/anon_inodes.h>
#include <linux/kvm_host.h>

struct tdx_mig_state {
};

struct tdx_mig_capabilities {
	uint32_t max_migs;
	uint32_t nonmem_state_pages;
};

static struct tdx_mig_capabilities tdx_mig_caps;

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

static int tdx_mig_stream_get_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	return -ENXIO;
}

static int tdx_mig_stream_set_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	return -ENXIO;
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

static int tdx_mig_stream_create(struct kvm_device *dev, u32 type)
{
	return -ENXIO;
}

static void tdx_mig_stream_release(struct kvm_device *dev)
{
}

static int tdx_mig_state_create(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;

	mig_state = kzalloc(sizeof(struct tdx_mig_state), GFP_KERNEL_ACCOUNT);
	if (!mig_state)
		return -ENOMEM;

	kvm_tdx->mig_state = mig_state;
	return 0;
}

static void tdx_mig_state_destroy(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;

	if (!mig_state)
		return;

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
