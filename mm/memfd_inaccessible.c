// SPDX-License-Identifier: GPL-2.0
#include "linux/sbitmap.h"
#include <linux/memfd.h>
#include <linux/pagemap.h>
#include <linux/pseudo_fs.h>
#include <linux/shmem_fs.h>
#include <uapi/linux/falloc.h>
#include <uapi/linux/magic.h>

struct inaccessible_data {
	struct mutex lock;
	struct file *memfd;
	struct list_head notifiers;
};

static void inaccessible_notifier_invalidate(struct inaccessible_data *data,
				 pgoff_t start, pgoff_t end)
{
	struct inaccessible_notifier *notifier;

	mutex_lock(&data->lock);
	list_for_each_entry(notifier, &data->notifiers, list) {
		notifier->ops->invalidate(notifier, start, end);
	}
	mutex_unlock(&data->lock);
}

static int inaccessible_release(struct inode *inode, struct file *file)
{
	struct inaccessible_data *data = inode->i_mapping->private_data;

	fput(data->memfd);
	kfree(data);
	return 0;
}

static long inaccessible_fallocate(struct file *file, int mode,
				   loff_t offset, loff_t len)
{
	struct inaccessible_data *data = file->f_mapping->private_data;
	struct file *memfd = data->memfd;
	int ret;

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		if (!PAGE_ALIGNED(offset) || !PAGE_ALIGNED(len))
			return -EINVAL;
	}

	ret = memfd->f_op->fallocate(memfd, mode, offset, len);
	inaccessible_notifier_invalidate(data, offset, offset + len);
	return ret;
}

static const struct file_operations inaccessible_fops = {
	.release = inaccessible_release,
	.fallocate = inaccessible_fallocate,
};

static int inaccessible_getattr(struct user_namespace *mnt_userns,
				const struct path *path, struct kstat *stat,
				u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct inaccessible_data *data = inode->i_mapping->private_data;
	struct file *memfd = data->memfd;

	return memfd->f_inode->i_op->getattr(mnt_userns, path, stat,
					     request_mask, query_flags);
}

static int inaccessible_setattr(struct user_namespace *mnt_userns,
				struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct inaccessible_data *data = inode->i_mapping->private_data;
	struct file *memfd = data->memfd;
	int ret;

	if (attr->ia_valid & ATTR_SIZE) {
		if (memfd->f_inode->i_size)
			return -EPERM;

		if (!PAGE_ALIGNED(attr->ia_size))
			return -EINVAL;
	}

	ret = memfd->f_inode->i_op->setattr(mnt_userns,
					    file_dentry(memfd), attr);
	return ret;
}

static const struct inode_operations inaccessible_iops = {
	.getattr = inaccessible_getattr,
	.setattr = inaccessible_setattr,
};

static int inaccessible_init_fs_context(struct fs_context *fc)
{
	if (!init_pseudo(fc, INACCESSIBLE_MAGIC))
		return -ENOMEM;

	fc->s_iflags |= SB_I_NOEXEC;
	return 0;
}

static struct file_system_type inaccessible_fs = {
	.owner		= THIS_MODULE,
	.name		= "[inaccessible]",
	.init_fs_context = inaccessible_init_fs_context,
	.kill_sb	= kill_anon_super,
};

static struct vfsmount *inaccessible_mnt;

static __init int inaccessible_init(void)
{
	inaccessible_mnt = kern_mount(&inaccessible_fs);
	if (IS_ERR(inaccessible_mnt))
		return PTR_ERR(inaccessible_mnt);
	return 0;
}
fs_initcall(inaccessible_init);

struct file *memfd_mkinaccessible(struct file *memfd)
{
	struct inaccessible_data *data;
	struct address_space *mapping;
	struct inode *inode;
	struct file *file;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	data->memfd = memfd;
	mutex_init(&data->lock);
	INIT_LIST_HEAD(&data->notifiers);

	inode = alloc_anon_inode(inaccessible_mnt->mnt_sb);
	if (IS_ERR(inode)) {
		kfree(data);
		return ERR_CAST(inode);
	}

	inode->i_mode |= S_IFREG;
	inode->i_op = &inaccessible_iops;
	inode->i_mapping->private_data = data;

	file = alloc_file_pseudo(inode, inaccessible_mnt,
				 "[memfd:inaccessible]", O_RDWR,
				 &inaccessible_fops);
	if (IS_ERR(file)) {
		iput(inode);
		kfree(data);
	}

	file->f_flags |= O_LARGEFILE;

	mapping = memfd->f_mapping;
	mapping_set_unevictable(mapping);
	mapping_set_gfp_mask(mapping,
			     mapping_gfp_mask(mapping) & ~__GFP_MOVABLE);

	return file;
}

void inaccessible_register_notifier(struct file *file,
				    struct inaccessible_notifier *notifier)
{
	struct inaccessible_data *data = file->f_mapping->private_data;

	mutex_lock(&data->lock);
	list_add(&notifier->list, &data->notifiers);
	mutex_unlock(&data->lock);
}
EXPORT_SYMBOL_GPL(inaccessible_register_notifier);

void inaccessible_unregister_notifier(struct file *file,
				      struct inaccessible_notifier *notifier)
{
	struct inaccessible_data *data = file->f_mapping->private_data;

	mutex_lock(&data->lock);
	list_del(&notifier->list);
	mutex_unlock(&data->lock);
}
EXPORT_SYMBOL_GPL(inaccessible_unregister_notifier);

int inaccessible_get_pfn(struct file *file, pgoff_t offset, pfn_t *pfn,
			 int *order)
{
	struct inaccessible_data *data = file->f_mapping->private_data;
	struct file *memfd = data->memfd;
	struct page *page;
	int ret;

	ret = shmem_getpage(file_inode(memfd), offset, &page, SGP_WRITE);
	if (ret)
		return ret;

	*pfn = page_to_pfn_t(page);
	*order = thp_order(compound_head(page));
	SetPageUptodate(page);
	unlock_page(page);

	return 0;
}
EXPORT_SYMBOL_GPL(inaccessible_get_pfn);

void inaccessible_put_pfn(struct file *file, pfn_t pfn)
{
	struct page *page = pfn_t_to_page(pfn);

	if (WARN_ON_ONCE(!page))
		return;

	put_page(page);
}
EXPORT_SYMBOL_GPL(inaccessible_put_pfn);
