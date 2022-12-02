// SPDX-License-Identifier: GPL-2.0
#include "linux/sbitmap.h"
#include <linux/pagemap.h>
#include <linux/pseudo_fs.h>
#include <linux/shmem_fs.h>
#include <linux/syscalls.h>
#include <uapi/linux/falloc.h>
#include <uapi/linux/magic.h>
#include <linux/restrictedmem.h>

struct restrictedmem_data {
	struct mutex lock;
	struct file *memfd;
	struct list_head notifiers;
};

static void restrictedmem_invalidate_start(struct restrictedmem_data *data,
					   pgoff_t start, pgoff_t end)
{
	struct restrictedmem_notifier *notifier;

	mutex_lock(&data->lock);
	list_for_each_entry(notifier, &data->notifiers, list) {
		notifier->ops->invalidate_start(notifier, start, end);
	}
	mutex_unlock(&data->lock);
}

static void restrictedmem_invalidate_end(struct restrictedmem_data *data,
					 pgoff_t start, pgoff_t end)
{
	struct restrictedmem_notifier *notifier;

	mutex_lock(&data->lock);
	list_for_each_entry(notifier, &data->notifiers, list) {
		notifier->ops->invalidate_end(notifier, start, end);
	}
	mutex_unlock(&data->lock);
}

static void restrictedmem_notifier_error(struct restrictedmem_data *data,
					 pgoff_t start, pgoff_t end)
{
	struct restrictedmem_notifier *notifier;

	mutex_lock(&data->lock);
	list_for_each_entry(notifier, &data->notifiers, list) {
		notifier->ops->error(notifier, start, end);
	}
	mutex_unlock(&data->lock);
}

static int restrictedmem_release(struct inode *inode, struct file *file)
{
	struct restrictedmem_data *data = inode->i_mapping->private_data;

	fput(data->memfd);
	kfree(data);
	return 0;
}

static long restrictedmem_punch_hole(struct restrictedmem_data *data, int mode,
				     loff_t offset, loff_t len)
{
	int ret;
	pgoff_t start, end;
	struct file *memfd = data->memfd;

	if (!PAGE_ALIGNED(offset) || !PAGE_ALIGNED(len))
		return -EINVAL;

	start = offset >> PAGE_SHIFT;
	end = (offset + len) >> PAGE_SHIFT;

	restrictedmem_invalidate_start(data, start, end);
	ret = memfd->f_op->fallocate(memfd, mode, offset, len);
	restrictedmem_invalidate_end(data, start, end);

	return ret;
}

static long restrictedmem_fallocate(struct file *file, int mode,
				    loff_t offset, loff_t len)
{
	struct restrictedmem_data *data = file->f_mapping->private_data;
	struct file *memfd = data->memfd;

	if (mode & FALLOC_FL_PUNCH_HOLE)
		return restrictedmem_punch_hole(data, mode, offset, len);

	return memfd->f_op->fallocate(memfd, mode, offset, len);
}

static const struct file_operations restrictedmem_fops = {
	.release = restrictedmem_release,
	.fallocate = restrictedmem_fallocate,
};

static int restrictedmem_getattr(struct user_namespace *mnt_userns,
				 const struct path *path, struct kstat *stat,
				 u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct restrictedmem_data *data = inode->i_mapping->private_data;
	struct file *memfd = data->memfd;

	return memfd->f_inode->i_op->getattr(mnt_userns, path, stat,
					     request_mask, query_flags);
}

static int restrictedmem_setattr(struct user_namespace *mnt_userns,
				 struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct restrictedmem_data *data = inode->i_mapping->private_data;
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

static const struct inode_operations restrictedmem_iops = {
	.getattr = restrictedmem_getattr,
	.setattr = restrictedmem_setattr,
};

static int restrictedmem_init_fs_context(struct fs_context *fc)
{
	if (!init_pseudo(fc, RESTRICTEDMEM_MAGIC))
		return -ENOMEM;

	fc->s_iflags |= SB_I_NOEXEC;
	return 0;
}

static struct file_system_type restrictedmem_fs = {
	.owner		= THIS_MODULE,
	.name		= "memfd:restrictedmem",
	.init_fs_context = restrictedmem_init_fs_context,
	.kill_sb	= kill_anon_super,
};

static struct vfsmount *restrictedmem_mnt;

static __init int restrictedmem_init(void)
{
	restrictedmem_mnt = kern_mount(&restrictedmem_fs);
	if (IS_ERR(restrictedmem_mnt))
		return PTR_ERR(restrictedmem_mnt);
	return 0;
}
fs_initcall(restrictedmem_init);

static struct file *restrictedmem_file_create(struct file *memfd)
{
	struct restrictedmem_data *data;
	struct address_space *mapping;
	struct inode *inode;
	struct file *file;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	data->memfd = memfd;
	mutex_init(&data->lock);
	INIT_LIST_HEAD(&data->notifiers);

	inode = alloc_anon_inode(restrictedmem_mnt->mnt_sb);
	if (IS_ERR(inode)) {
		kfree(data);
		return ERR_CAST(inode);
	}

	inode->i_mode |= S_IFREG;
	inode->i_op = &restrictedmem_iops;
	inode->i_mapping->private_data = data;

	file = alloc_file_pseudo(inode, restrictedmem_mnt,
				 "restrictedmem", O_RDWR,
				 &restrictedmem_fops);
	if (IS_ERR(file)) {
		iput(inode);
		kfree(data);
		return ERR_CAST(file);
	}

	file->f_flags |= O_LARGEFILE;

	/*
	 * These pages are currently unmovable so don't place them into movable
	 * pageblocks (e.g. CMA and ZONE_MOVABLE).
	 */
	mapping = memfd->f_mapping;
	mapping_set_unevictable(mapping);
	mapping_set_gfp_mask(mapping,
			     mapping_gfp_mask(mapping) & ~__GFP_MOVABLE);

	return file;
}

SYSCALL_DEFINE1(memfd_restricted, unsigned int, flags)
{
	struct file *file, *restricted_file;
	int fd, err;

	if (flags)
		return -EINVAL;

	fd = get_unused_fd_flags(0);
	if (fd < 0)
		return fd;

	file = shmem_file_setup("memfd:restrictedmem", 0, VM_NORESERVE);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_fd;
	}
	file->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
	file->f_flags |= O_LARGEFILE;

	restricted_file = restrictedmem_file_create(file);
	if (IS_ERR(restricted_file)) {
		err = PTR_ERR(restricted_file);
		fput(file);
		goto err_fd;
	}

	fd_install(fd, restricted_file);
	return fd;
err_fd:
	put_unused_fd(fd);
	return err;
}

void restrictedmem_register_notifier(struct file *file,
				     struct restrictedmem_notifier *notifier)
{
	struct restrictedmem_data *data = file->f_mapping->private_data;

	mutex_lock(&data->lock);
	list_add(&notifier->list, &data->notifiers);
	mutex_unlock(&data->lock);
}
EXPORT_SYMBOL_GPL(restrictedmem_register_notifier);

void restrictedmem_unregister_notifier(struct file *file,
				       struct restrictedmem_notifier *notifier)
{
	struct restrictedmem_data *data = file->f_mapping->private_data;

	mutex_lock(&data->lock);
	list_del(&notifier->list);
	mutex_unlock(&data->lock);
}
EXPORT_SYMBOL_GPL(restrictedmem_unregister_notifier);

int restrictedmem_get_page(struct file *file, pgoff_t offset,
			   struct page **pagep, int *order)
{
	struct restrictedmem_data *data = file->f_mapping->private_data;
	struct file *memfd = data->memfd;
	struct folio *folio;
	struct page *page;
	int ret;

	ret = shmem_get_folio(file_inode(memfd), offset, &folio, SGP_WRITE);
	if (ret)
		return ret;

	page = folio_file_page(folio, offset);
	*pagep = page;
	if (order)
		*order = thp_order(compound_head(page));

	SetPageUptodate(page);
	unlock_page(page);

	return 0;
}
EXPORT_SYMBOL_GPL(restrictedmem_get_page);

void restrictedmem_error_page(struct page *page, struct address_space *mapping)
{
	struct super_block *sb = restrictedmem_mnt->mnt_sb;
	struct inode *inode, *next;

	if (!shmem_mapping(mapping))
		return;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry_safe(inode, next, &sb->s_inodes, i_sb_list) {
		struct restrictedmem_data *data = inode->i_mapping->private_data;
		struct file *memfd = data->memfd;

		if (memfd->f_mapping == mapping) {
			pgoff_t start, end;

			spin_unlock(&sb->s_inode_list_lock);

			start = page->index;
			end = start + thp_nr_pages(page);
			restrictedmem_notifier_error(data, start, end);
			return;
		}
	}
	spin_unlock(&sb->s_inode_list_lock);
}
