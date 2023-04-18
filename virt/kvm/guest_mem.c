// SPDX-License-Identifier: GPL-2.0
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/kvm_host.h>
#include <linux/pagemap.h>
#include <linux/sbitmap.h>


#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/swap.h>
#include <linux/mount.h>
#include <linux/memfd.h>
#include <linux/bitops.h>
#include <linux/printk.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/pseudo_fs.h>
#include <linux/secretmem.h>
#include <linux/set_memory.h>
#include <linux/sched/signal.h>

#include <uapi/linux/magic.h>

#include "kvm_mm.h"

static struct vfsmount *kvm_gmem_mnt;

struct kvm_gmem {
	struct kvm *kvm;
	struct xarray bindings;
};

static loff_t kvm_gmem_get_size(struct file *file)
{
	return i_size_read(file_inode(file));
}

static struct folio *kvm_gmem_get_folio(struct file *file, pgoff_t index)
{
	struct folio *folio;

	/* TODO: Support huge pages. */
	folio = filemap_grab_folio(file->f_mapping, index);
	if (!folio)
		return NULL;

	/*
	 * TODO: Confirm this won't zero in-use pages, and skip clearing pages
	 * when trusted firmware will do it when assigning memory to the guest.
	 */
	if (!folio_test_uptodate(folio)) {
		unsigned long nr_pages = folio_nr_pages(folio);
		unsigned long i;

		for (i = 0; i < nr_pages; i++)
			clear_highpage(folio_page(folio, i));
	}

	folio_mark_accessed(folio);
	folio_mark_dirty(folio);
	folio_mark_uptodate(folio);

	return folio;
}

static void kvm_gmem_invalidate_begin(struct kvm *kvm, struct kvm_gmem *gmem,
				      pgoff_t start, pgoff_t end)
{
	struct kvm_memory_slot *slot;
	unsigned long index;
	bool flush = false;

	KVM_MMU_LOCK(kvm);

	kvm_mmu_invalidate_begin(kvm);

	xa_for_each_range(&gmem->bindings, index, slot, start, end - 1) {
		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + start - slot->gmem.index,
			.end = slot->base_gfn + min(end - slot->gmem.index, slot->npages),
			.slot = slot,
			.pte = __pte(0),
			.may_block = true,
		};

		if (WARN_ON_ONCE(start < slot->gmem.index ||
				 end > slot->gmem.index + slot->npages))
			continue;

		kvm_mmu_invalidate_range_add(kvm, gfn_range.start, gfn_range.end);

		flush |= kvm_unmap_gfn_range(kvm, &gfn_range);
	}

	if (flush)
		kvm_flush_remote_tlbs(kvm);

	KVM_MMU_UNLOCK(kvm);
}

static void kvm_gmem_invalidate_end(struct kvm *kvm, struct kvm_gmem *gmem,
				    pgoff_t start, pgoff_t end)
{
	KVM_MMU_LOCK(kvm);
	if (xa_find(&gmem->bindings, &start, end - 1, XA_PRESENT))
		kvm_mmu_invalidate_end(kvm);
	KVM_MMU_UNLOCK(kvm);
}

static long kvm_gmem_punch_hole(struct file *file, loff_t offset, loff_t len)
{
	struct kvm_gmem *gmem = file->private_data;
	pgoff_t start = offset >> PAGE_SHIFT;
	pgoff_t end = (offset + len) >> PAGE_SHIFT;
	struct kvm *kvm = gmem->kvm;

	/*
	 * Bindings must stable across invalidation to ensure the start+end
	 * are balanced.
	 */
	filemap_invalidate_lock(file->f_mapping);

	kvm_gmem_invalidate_begin(kvm, gmem, start, end);

	truncate_inode_pages_range(file->f_mapping, offset, offset + len - 1);

	kvm_gmem_invalidate_end(kvm, gmem, start, end);

	filemap_invalidate_unlock(file->f_mapping);

	return 0;
}

static long kvm_gmem_allocate(struct file *file, loff_t offset, loff_t len)
{
	struct address_space *mapping = file->f_mapping;
	pgoff_t start, index, end;
	int r;

	/* Dedicated guest is immutable by default. */
	if (offset + len > kvm_gmem_get_size(file))
		return -EINVAL;

	filemap_invalidate_lock_shared(mapping);

	start = offset >> PAGE_SHIFT;
	end = (offset + len) >> PAGE_SHIFT;

	r = 0;
	for (index = start; index < end; ) {
		struct folio *folio;

		if (signal_pending(current)) {
			r = -EINTR;
			break;
		}

		folio = kvm_gmem_get_folio(file, index);
		if (!folio) {
			r = -ENOMEM;
			break;
		}

		index = folio_next_index(folio);

		folio_unlock(folio);
		folio_put(folio);

		/* 64-bit only, wrapping the index should be impossible. */
		if (WARN_ON_ONCE(!index))
			break;

		cond_resched();
	}

	filemap_invalidate_unlock_shared(mapping);

	file_modified(file);
	return r;
}

static long kvm_gmem_fallocate(struct file *file, int mode, loff_t offset,
			       loff_t len)
{
	int ret;

	if (!(mode & FALLOC_FL_KEEP_SIZE))
		return -EOPNOTSUPP;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	if (!PAGE_ALIGNED(offset) || !PAGE_ALIGNED(len))
		return -EINVAL;

	if (mode & FALLOC_FL_PUNCH_HOLE)
		ret = kvm_gmem_punch_hole(file, offset, len);
	else
		ret = kvm_gmem_allocate(file, offset, len);

	return ret;
}

static int kvm_gmem_release(struct inode *inode, struct file *file)
{
	struct kvm_gmem *gmem = inode->i_mapping->private_data;
	struct kvm_memory_slot *slot;
	struct kvm *kvm = gmem->kvm;
	unsigned long index;

	/*
	 * Prevent concurrent attempts to *unbind* a memslot.  This is the last
	 * reference to the file and thus no new bindings can be created, but
	 * deferencing the slot for existing bindings needs to be protected
	 * against memslot updates, specifically so that unbind doesn't race
	 * and free the memslot (kvm_gmem_get_file() will return NULL).
	 */
	mutex_lock(&kvm->slots_lock);

	xa_for_each(&gmem->bindings, index, slot)
		rcu_assign_pointer(slot->gmem.file, NULL);

	synchronize_rcu();

	/*
	 * All in-flight operations are gone and new bindings can be created.
	 * Free the backing memory, and more importantly, zap all SPTEs that
	 * pointed at this file.
	 */
	kvm_gmem_invalidate_begin(kvm, gmem, 0, -1ul);
	truncate_inode_pages_final(file->f_mapping);
	kvm_gmem_invalidate_end(kvm, gmem, 0, -1ul);

	mutex_unlock(&kvm->slots_lock);

	WARN_ON_ONCE(!(mapping_empty(file->f_mapping)));

	xa_destroy(&gmem->bindings);
	kfree(gmem);

	kvm_put_kvm(kvm);

	return 0;
}

static struct file *kvm_gmem_get_file(struct kvm_memory_slot *slot)
{
	struct file *file;

	rcu_read_lock();

	file = rcu_dereference(slot->gmem.file);
	if (file && !get_file_rcu(file))
		file = NULL;
	rcu_read_unlock();

	return file;
}

static const struct file_operations kvm_gmem_fops = {
	.open		= generic_file_open,
	.release	= kvm_gmem_release,
	.fallocate	= kvm_gmem_fallocate,
};

static int kvm_gmem_migrate_folio(struct address_space *mapping,
				  struct folio *dst, struct folio *src,
				  enum migrate_mode mode)
{
	WARN_ON_ONCE(1);
	return -EINVAL;
}

static int kvm_gmem_error_page(struct address_space *mapping, struct page *page)
{
	struct kvm_gmem *gmem = mapping->private_data;
	struct kvm_memory_slot *slot;
	unsigned long index;
	pgoff_t start, end;
	gfn_t gfn;

	filemap_invalidate_lock_shared(mapping);

	start = page->index;
	end = start + thp_nr_pages(page);

	xa_for_each_range(&gmem->bindings, index, slot, start, end - 1) {
		for (gfn = start; gfn < end; gfn++) {
			if (WARN_ON_ONCE(gfn < slot->base_gfn ||
					 gfn >= slot->base_gfn + slot->npages))
				continue;

			send_sig_mceerr(BUS_MCEERR_AR,
					(void __user *)gfn_to_hva_memslot(slot, gfn),
					PAGE_SHIFT, current);
		}
	}

	filemap_invalidate_unlock_shared(mapping);

	return 0;
}

static const struct address_space_operations kvm_gmem_aops = {
	.dirty_folio = noop_dirty_folio,
#ifdef CONFIG_MIGRATION
	.migrate_folio	= kvm_gmem_migrate_folio,
#endif
	.error_remove_page = kvm_gmem_error_page,
};

static int  kvm_gmem_getattr(struct mnt_idmap *idmap,
			     const struct path *path, struct kstat *stat,
			     u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = path->dentry->d_inode;

	/* TODO */
	generic_fillattr(idmap, inode, stat);
	return 0;
}

static int kvm_gmem_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			    struct iattr *attr)
{
	/* TODO */
	return -EINVAL;
}
static const struct inode_operations kvm_gmem_iops = {
	.getattr	= kvm_gmem_getattr,
	.setattr	= kvm_gmem_setattr,
};

static int __kvm_gmem_create(struct kvm *kvm, loff_t size, struct vfsmount *mnt)
{
	const char *anon_name = "[kvm-gmem]";
	const struct qstr qname = QSTR_INIT(anon_name, strlen(anon_name));
	struct kvm_gmem *gmem;
	struct inode *inode;
	struct file *file;
	int fd, err;

	fd = get_unused_fd_flags(0);
	if (fd < 0)
		return fd;

	inode = alloc_anon_inode(mnt->mnt_sb);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto err_fd;
	}

	err = security_inode_init_security_anon(inode, &qname, NULL);
	if (err)
		goto err_inode;

	file = alloc_file_pseudo(inode, mnt, "kvm-gmem", O_RDWR, &kvm_gmem_fops);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_inode;
	}

	gmem = kzalloc(sizeof(*gmem), GFP_KERNEL);
	if (!gmem) {
		err = -ENOMEM;
		goto err_file;
	}

	xa_init(&gmem->bindings);

	kvm_get_kvm(kvm);
	gmem->kvm = kvm;

	inode->i_op = &kvm_gmem_iops;
	inode->i_mapping->a_ops = &kvm_gmem_aops;
	inode->i_mapping->private_data = gmem;
	inode->i_mode |= S_IFREG;
	inode->i_size = size;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_unevictable(inode->i_mapping);

	file->f_flags |= O_LARGEFILE;
	file->f_mapping = inode->i_mapping;
	file->private_data = gmem;

	fd_install(fd, file);
	return fd;

err_file:
	fput(file);
err_inode:
	iput(inode);
err_fd:
	put_unused_fd(fd);
	return err;
}

int kvm_gmem_create(struct kvm *kvm, struct kvm_create_guest_memfd *gmem)
{
	loff_t size = gmem->size;

	if (size < 0 || !PAGE_ALIGNED(size))
		return -EINVAL;

	if (gmem->flags)
		return -EINVAL;

	return __kvm_gmem_create(kvm, size, kvm_gmem_mnt);
}

int kvm_gmem_bind(struct kvm *kvm, struct kvm_memory_slot *slot,
		  unsigned int fd, loff_t offset)
{
	unsigned long start, end;
	struct kvm_gmem *gmem;
	struct file *file;

	BUILD_BUG_ON(sizeof(gfn_t) != sizeof(slot->gmem.index));

	if (offset < 0)
		return -EINVAL;

	file = fget(fd);
	if (!file)
		return -EINVAL;

	if (file->f_op != &kvm_gmem_fops)
		goto err;

	gmem = file->private_data;
	if (gmem->kvm != kvm)
		goto err;

	if (offset + (slot->npages << PAGE_SHIFT) > kvm_gmem_get_size(file))
		goto err;

	filemap_invalidate_lock(file->f_mapping);

	start = offset >> PAGE_SHIFT;
	end = start + slot->npages;

	if (!xa_empty(&gmem->bindings) &&
	    xa_find(&gmem->bindings, &start, end - 1, XA_PRESENT)) {
		filemap_invalidate_unlock(file->f_mapping);
		goto err;
	}

	/*
	 * No synchronize_rcu() needed, any in-flight readers are guaranteed to
	 * be see either a NULL file or this new file, no need for them to go
	 * away.
	 */
	rcu_assign_pointer(slot->gmem.file, file);
	slot->gmem.index = start;

	xa_store_range(&gmem->bindings, start, end - 1, slot, GFP_KERNEL);
	filemap_invalidate_unlock(file->f_mapping);

	/*
	 * Drop the reference to the file, even on success.  The file pins KVM,
	 * not the other way 'round.  Active bindings are invalidated if the
	 * file is closed before memslots are destroyed.
	 */
	fput(file);
	return 0;

err:
	fput(file);
	return -EINVAL;
}

void kvm_gmem_unbind(struct kvm_memory_slot *slot)
{
	unsigned long start = slot->gmem.index;
	unsigned long end = start + slot->npages;
	struct kvm_gmem *gmem;
	struct file *file;

	/* Nothing to do if the underlying file was already closed (or is being
	 * close right now), kvm_gmem_release() invalidates all bindings.
	 */
	file = kvm_gmem_get_file(slot);
	if (!file)
		return;

	gmem = file->private_data;

	filemap_invalidate_lock(file->f_mapping);
	xa_store_range(&gmem->bindings, start, end - 1, NULL, GFP_KERNEL);
	rcu_assign_pointer(slot->gmem.file, NULL);
	synchronize_rcu();
	filemap_invalidate_unlock(file->f_mapping);

	fput(file);
}

int kvm_gmem_get_pfn(struct kvm *kvm, struct kvm_memory_slot *slot,
		     gfn_t gfn, kvm_pfn_t *pfn, int *order)
{
	pgoff_t index = gfn - slot->base_gfn + slot->gmem.index;
	struct kvm_gmem *gmem;
	struct folio *folio;
	struct page *page;
	struct file *file;

	file = kvm_gmem_get_file(slot);
	if (!file)
		return -EFAULT;

	gmem = file->private_data;

	if (WARN_ON_ONCE(xa_load(&gmem->bindings, index) != slot)) {
		fput(file);
		return -EIO;
	}

	folio = kvm_gmem_get_folio(file, index);
	if (!folio) {
		fput(file);
		return -ENOMEM;
	}

	page = folio_file_page(folio, index);

	*pfn = page_to_pfn(page);
	*order = thp_order(compound_head(page));

	folio_unlock(folio);
	fput(file);

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_gmem_get_pfn);

static int kvm_gmem_init_fs_context(struct fs_context *fc)
{
	if (!init_pseudo(fc, GUEST_MEMORY_MAGIC))
		return -ENOMEM;

	return 0;
}

static struct file_system_type kvm_gmem_fs = {
	.name		 = "kvm_guest_memory",
	.init_fs_context = kvm_gmem_init_fs_context,
	.kill_sb	 = kill_anon_super,
};

int kvm_gmem_init(void)
{
	kvm_gmem_mnt = kern_mount(&kvm_gmem_fs);
	if (IS_ERR(kvm_gmem_mnt))
		return PTR_ERR(kvm_gmem_mnt);

	/* For giggles.  Userspace can never map this anyways. */
	kvm_gmem_mnt->mnt_flags |= MNT_NOEXEC;

	return 0;
}

void kvm_gmem_exit(void)
{
	kern_unmount(kvm_gmem_mnt);
	kvm_gmem_mnt = NULL;
}
