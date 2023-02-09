// SPDX-License-Identifier: GPL-2.0
#include "linux/sbitmap.h"
#include <linux/pagemap.h>
#include <linux/pseudo_fs.h>
#include <linux/shmem_fs.h>
#include <linux/syscalls.h>
#include <uapi/linux/falloc.h>
#include <uapi/linux/magic.h>
#include <linux/restrictedmem.h>

struct restrictedmem {
	struct rw_semaphore lock;
	struct file *memfd;
	struct xarray bindings;
	bool exclusive;
};

static int restrictedmem_release(struct inode *inode, struct file *file)
{
	struct restrictedmem *rm = inode->i_mapping->private_data;

	xa_destroy(&rm->bindings);
	fput(rm->memfd);
	kfree(rm);
	return 0;
}

static long restrictedmem_punch_hole(struct restrictedmem *rm, int mode,
				     loff_t offset, loff_t len)
{
	struct restrictedmem_notifier *notifier;
	struct file *memfd = rm->memfd;
	unsigned long index;
	pgoff_t start, end;
	int ret;

	if (!PAGE_ALIGNED(offset) || !PAGE_ALIGNED(len))
		return -EINVAL;

	start = offset >> PAGE_SHIFT;
	end = (offset + len) >> PAGE_SHIFT;

	/*
	 * Bindings must stable across invalidation to ensure the start+end
	 * are balanced.
	 */
	down_read(&rm->lock);

	xa_for_each_range(&rm->bindings, index, notifier, start, end)
		notifier->ops->invalidate_start(notifier, start, end);

	ret = memfd->f_op->fallocate(memfd, mode, offset, len);

	xa_for_each_range(&rm->bindings, index, notifier, start, end)
		notifier->ops->invalidate_end(notifier, start, end);

	up_read(&rm->lock);

	return ret;
}

static long restrictedmem_fallocate(struct file *file, int mode,
				    loff_t offset, loff_t len)
{
	struct restrictedmem *rm = file->f_mapping->private_data;
	struct file *memfd = rm->memfd;

	if (mode & FALLOC_FL_PUNCH_HOLE)
		return restrictedmem_punch_hole(rm, mode, offset, len);

	return memfd->f_op->fallocate(memfd, mode, offset, len);
}

static const struct file_operations restrictedmem_fops = {
	.release = restrictedmem_release,
	.fallocate = restrictedmem_fallocate,
};

static int restrictedmem_getattr(struct mnt_idmap *idmap,
				 const struct path *path, struct kstat *stat,
				 u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct restrictedmem *rm = inode->i_mapping->private_data;
	struct file *memfd = rm->memfd;

	return memfd->f_inode->i_op->getattr(idmap, path, stat,
					     request_mask, query_flags);
}

static int restrictedmem_setattr(struct mnt_idmap *idmap,
				 struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct restrictedmem *rm = inode->i_mapping->private_data;
	struct file *memfd = rm->memfd;
	int ret;

	if (attr->ia_valid & ATTR_SIZE) {
		if (memfd->f_inode->i_size)
			return -EPERM;

		if (!PAGE_ALIGNED(attr->ia_size))
			return -EINVAL;
	}

	ret = memfd->f_inode->i_op->setattr(idmap,
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
	struct restrictedmem *rm;
	struct address_space *mapping;
	struct inode *inode;
	struct file *file;

	rm = kzalloc(sizeof(*rm), GFP_KERNEL);
	if (!rm)
		return ERR_PTR(-ENOMEM);

	rm->memfd = memfd;
	init_rwsem(&rm->lock);
	xa_init(&rm->bindings);

	inode = alloc_anon_inode(restrictedmem_mnt->mnt_sb);
	if (IS_ERR(inode)) {
		kfree(rm);
		return ERR_CAST(inode);
	}

	inode->i_mode |= S_IFREG;
	inode->i_op = &restrictedmem_iops;
	inode->i_mapping->private_data = rm;

	file = alloc_file_pseudo(inode, restrictedmem_mnt,
				 "restrictedmem", O_RDWR,
				 &restrictedmem_fops);
	if (IS_ERR(file)) {
		iput(inode);
		kfree(rm);
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

static int restricted_error_remove_page(struct address_space *mapping,
					struct page *page)
{
	struct super_block *sb = restrictedmem_mnt->mnt_sb;
	struct inode *inode, *next;
	pgoff_t start, end;

	start = page->index;
	end = start + thp_nr_pages(page);

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry_safe(inode, next, &sb->s_inodes, i_sb_list) {
		struct restrictedmem_notifier *notifier;
		struct restrictedmem *rm;
		unsigned long index;
		struct file *memfd;

		if (atomic_read(&inode->i_count))
			continue;

		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_NEW | I_FREEING | I_WILL_FREE)) {
			spin_unlock(&inode->i_lock);
			continue;
		}

		rm = inode->i_mapping->private_data;
		memfd = rm->memfd;

		if (memfd->f_mapping != mapping) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		spin_unlock(&inode->i_lock);

		xa_for_each_range(&rm->bindings, index, notifier, start, end)
			notifier->ops->error(notifier, start, end);
		break;
	}
	spin_unlock(&sb->s_inode_list_lock);

	return 0;
}

#ifdef CONFIG_MIGRATION
static int restricted_folio(struct address_space *mapping, struct folio *dst,
			    struct folio *src, enum migrate_mode mode)
{
	return -EBUSY;
}
#endif

static struct address_space_operations restricted_aops = {
	.dirty_folio	= noop_dirty_folio,
	.error_remove_page = restricted_error_remove_page,
#ifdef CONFIG_MIGRATION
	.migrate_folio	= restricted_folio,
#endif
};

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

	file->f_mapping->a_ops = &restricted_aops;

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

int restrictedmem_bind(struct file *file, pgoff_t start, pgoff_t end,
		       struct restrictedmem_notifier *notifier, bool exclusive)
{
	struct restrictedmem *rm = file->f_mapping->private_data;
	int ret = -EINVAL;

	down_write(&rm->lock);

	/* Non-exclusive mappings are not yet implemented. */
	if (!exclusive)
		goto out_unlock;

	if (!xa_empty(&rm->bindings)) {
		if (exclusive != rm->exclusive)
			goto out_unlock;

		if (exclusive && xa_find(&rm->bindings, &start, end, XA_PRESENT))
			goto out_unlock;
	}

	xa_store_range(&rm->bindings, start, end, notifier, GFP_KERNEL);
	rm->exclusive = exclusive;
	ret = 0;
out_unlock:
	up_write(&rm->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(restrictedmem_bind);

void restrictedmem_unbind(struct file *file, pgoff_t start, pgoff_t end,
			  struct restrictedmem_notifier *notifier)
{
	struct restrictedmem *rm = file->f_mapping->private_data;

	down_write(&rm->lock);
	xa_store_range(&rm->bindings, start, end, NULL, GFP_KERNEL);
	synchronize_rcu();
	up_write(&rm->lock);
}
EXPORT_SYMBOL_GPL(restrictedmem_unbind);

int restrictedmem_get_page(struct file *file, pgoff_t offset,
			   struct page **pagep, int *order)
{
	struct restrictedmem *rm = file->f_mapping->private_data;
	struct file *memfd = rm->memfd;
	struct folio *folio;
	struct page *page;
	int ret;

	/* Sanity check that _someone_ bound the target offset. */
	if (WARN_ON_ONCE(!xa_load(&rm->bindings, offset)))
		return -EINVAL;

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
