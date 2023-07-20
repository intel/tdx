// SPDX-License-Identifier: GPL-2.0
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/kvm_host.h>
#include <linux/pagemap.h>
#include <linux/pseudo_fs.h>

#include <uapi/linux/magic.h>

#include "kvm_mm.h"

static struct vfsmount *kvm_gmem_mnt;

struct kvm_gmem {
	struct kvm *kvm;
	struct xarray bindings;
	struct list_head entry;
};

static struct folio *kvm_gmem_get_huge_folio(struct inode *inode, pgoff_t index)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	unsigned long huge_index = round_down(index, HPAGE_PMD_NR);
	unsigned long flags = (unsigned long)inode->i_private;
	struct address_space *mapping  = inode->i_mapping;
	gfp_t gfp = mapping_gfp_mask(mapping);
	struct folio *folio;

	if (!(flags & KVM_GUEST_MEMFD_ALLOW_HUGEPAGE))
		return NULL;

	if (filemap_range_has_page(mapping, huge_index << PAGE_SHIFT,
				   (huge_index + HPAGE_PMD_NR - 1) << PAGE_SHIFT))
		return NULL;

	folio = filemap_alloc_folio(gfp, HPAGE_PMD_ORDER);
	if (!folio)
		return NULL;

	if (filemap_add_folio(mapping, folio, huge_index, gfp)) {
		folio_put(folio);
		return NULL;
	}

	return folio;
#else
	return NULL;
#endif
}

static struct folio *kvm_gmem_get_folio(struct inode *inode, pgoff_t index)
{
	struct folio *folio;

	folio = kvm_gmem_get_huge_folio(inode, index);
	if (!folio) {
		folio = filemap_grab_folio(inode->i_mapping, index);
		if (!folio)
			return NULL;
	}

	/*
	 * Use the up-to-date flag to track whether or not the memory has been
	 * zeroed before being handed off to the guest.  There is no backing
	 * storage for the memory, so the folio will remain up-to-date until
	 * it's removed.
	 *
	 * TODO: Skip clearing pages when trusted firmware will do it when
	 * assigning memory to the guest.
	 */
	if (!folio_test_uptodate(folio)) {
		unsigned long nr_pages = folio_nr_pages(folio);
		unsigned long i;

		for (i = 0; i < nr_pages; i++)
			clear_highpage(folio_page(folio, i));

		folio_mark_uptodate(folio);
	}

	/*
	 * Ignore accessed, referenced, and dirty flags.  The memory is
	 * unevictable and there is no storage to write back to.
	 */
	return folio;
}

static void kvm_gmem_invalidate_begin(struct kvm_gmem *gmem, pgoff_t start,
				      pgoff_t end)
{
	struct kvm_memory_slot *slot;
	struct kvm *kvm = gmem->kvm;
	unsigned long index;
	bool flush = false;

	KVM_MMU_LOCK(kvm);

	kvm_mmu_invalidate_begin(kvm);

	xa_for_each_range(&gmem->bindings, index, slot, start, end - 1) {
		pgoff_t pgoff = slot->gmem.pgoff;

		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + max(pgoff, start) - pgoff,
			.end = slot->base_gfn + min(pgoff + slot->npages, end) - pgoff,
			.slot = slot,
			.may_block = true,
			.only_private = true,
			.only_shared = false,
		};

		flush |= kvm_mmu_unmap_gfn_range(kvm, &gfn_range);
	}

	if (flush)
		kvm_flush_remote_tlbs(kvm);

	KVM_MMU_UNLOCK(kvm);
}

static void kvm_gmem_invalidate_end(struct kvm_gmem *gmem, pgoff_t start,
				    pgoff_t end)
{
	struct kvm *kvm = gmem->kvm;

	KVM_MMU_LOCK(kvm);
	if (xa_find(&gmem->bindings, &start, end - 1, XA_PRESENT))
		kvm_mmu_invalidate_end(kvm);
	KVM_MMU_UNLOCK(kvm);
}

void __weak kvm_arch_gmem_invalidate(struct kvm *kvm, kvm_pfn_t start, kvm_pfn_t end)
{
}

/* Handle arch-specific hooks needed before releasing guarded pages. */
static void kvm_gmem_issue_arch_invalidate(struct kvm *kvm, struct inode *inode,
					   pgoff_t start, pgoff_t end)
{
	pgoff_t file_end = i_size_read(inode) >> PAGE_SHIFT;
	pgoff_t index = start;

	end = min(end, file_end);

	while (index < end) {
		struct folio *folio;
		unsigned int order;
		struct page *page;
		kvm_pfn_t pfn;

		folio = __filemap_get_folio(inode->i_mapping, index,
					    FGP_LOCK, 0);
		if (IS_ERR(folio) || !folio) {
			index++;
			continue;
		}

		page = folio_file_page(folio, index);
		pfn = page_to_pfn(page);
		order = folio_order(folio);

		kvm_arch_gmem_invalidate(kvm, pfn, pfn + min((1ul << order), end - index));

		index = folio_next_index(folio);
		folio_unlock(folio);
		folio_put(folio);

		cond_resched();
	}
}

static long kvm_gmem_punch_hole(struct inode *inode, loff_t offset, loff_t len)
{
	struct list_head *gmem_list = &inode->i_mapping->private_list;
	pgoff_t start = offset >> PAGE_SHIFT;
	pgoff_t end = (offset + len) >> PAGE_SHIFT;
	struct kvm_gmem *gmem;

	/*
	 * Bindings must stable across invalidation to ensure the start+end
	 * are balanced.
	 */
	filemap_invalidate_lock(inode->i_mapping);

	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_begin(gmem, start, end);

	kvm_gmem_issue_arch_invalidate(gmem->kvm, inode, start, end);
	truncate_inode_pages_range(inode->i_mapping, offset, offset + len - 1);

	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_end(gmem, start, end);

	filemap_invalidate_unlock(inode->i_mapping);

	return 0;
}

static long kvm_gmem_allocate(struct inode *inode, loff_t offset, loff_t len)
{
	struct address_space *mapping = inode->i_mapping;
	pgoff_t start, index, end;
	int r;

	/* Dedicated guest is immutable by default. */
	if (offset + len > i_size_read(inode))
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

		folio = kvm_gmem_get_folio(inode, index);
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
		ret = kvm_gmem_punch_hole(file_inode(file), offset, len);
	else
		ret = kvm_gmem_allocate(file_inode(file), offset, len);

	if (!ret)
		file_modified(file);
	return ret;
}

static int kvm_gmem_release(struct inode *inode, struct file *file)
{
	struct kvm_gmem *gmem = file->private_data;
	struct kvm_memory_slot *slot;
	struct kvm *kvm = gmem->kvm;
	unsigned long index;

	/*
	 * Prevent concurrent attempts to *unbind* a memslot.  This is the last
	 * reference to the file and thus no new bindings can be created, but
	 * dereferencing the slot for existing bindings needs to be protected
	 * against memslot updates, specifically so that unbind doesn't race
	 * and free the memslot (kvm_gmem_get_file() will return NULL).
	 */
	mutex_lock(&kvm->slots_lock);

	filemap_invalidate_lock(inode->i_mapping);

	xa_for_each(&gmem->bindings, index, slot)
		rcu_assign_pointer(slot->gmem.file, NULL);

	synchronize_rcu();

	/*
	 * All in-flight operations are gone and new bindings can be created.
	 * Zap all SPTEs pointed at by this file.  Do not free the backing
	 * memory, as its lifetime is associated with the inode, not the file.
	 */
	kvm_gmem_invalidate_begin(gmem, 0, -1ul);
	kvm_gmem_issue_arch_invalidate(gmem->kvm, file_inode(file), 0, -1ul);
	kvm_gmem_invalidate_end(gmem, 0, -1ul);

	list_del(&gmem->entry);

	filemap_invalidate_unlock(inode->i_mapping);

	mutex_unlock(&kvm->slots_lock);

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
	struct list_head *gmem_list = &mapping->private_list;
	struct kvm_memory_slot *slot;
	struct kvm_gmem *gmem;
	unsigned long index;
	pgoff_t start, end;
	gfn_t gfn;

	filemap_invalidate_lock_shared(mapping);

	start = page->index;
	end = start + thp_nr_pages(page);

	list_for_each_entry(gmem, gmem_list, entry) {
		xa_for_each_range(&gmem->bindings, index, slot, start, end - 1) {
			for (gfn = start; gfn < end; gfn++) {
				if (WARN_ON_ONCE(gfn < slot->base_gfn ||
						gfn >= slot->base_gfn + slot->npages))
					continue;

				/*
				 * FIXME: Tell userspace that the *private*
				 * memory encountered an error.
				 */
				send_sig_mceerr(BUS_MCEERR_AR,
						(void __user *)gfn_to_hva_memslot(slot, gfn),
						PAGE_SHIFT, current);
			}
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

static int __kvm_gmem_create(struct kvm *kvm, loff_t size, u64 flags,
			     struct vfsmount *mnt)
{
	const char *anon_name = "[kvm-gmem]";
	const struct qstr qname = QSTR_INIT(anon_name, strlen(anon_name));
	struct kvm_gmem *gmem;
	struct inode *inode;
	struct file *file;
	int fd, err;

	inode = alloc_anon_inode(mnt->mnt_sb);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	err = security_inode_init_security_anon(inode, &qname, NULL);
	if (err)
		goto err_inode;

	inode->i_private = (void *)(unsigned long)flags;
	inode->i_op = &kvm_gmem_iops;
	inode->i_mapping->a_ops = &kvm_gmem_aops;
	inode->i_mode |= S_IFREG;
	inode->i_size = size;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_large_folios(inode->i_mapping);
	mapping_set_unevictable(inode->i_mapping);
	mapping_set_unmovable(inode->i_mapping);

	fd = get_unused_fd_flags(0);
	if (fd < 0) {
		err = fd;
		goto err_inode;
	}

	file = alloc_file_pseudo(inode, mnt, "kvm-gmem", O_RDWR, &kvm_gmem_fops);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_fd;
	}

	file->f_flags |= O_LARGEFILE;
	file->f_mapping = inode->i_mapping;

	gmem = kzalloc(sizeof(*gmem), GFP_KERNEL);
	if (!gmem) {
		err = -ENOMEM;
		goto err_file;
	}

	kvm_get_kvm(kvm);
	gmem->kvm = kvm;
	xa_init(&gmem->bindings);

	file->private_data = gmem;

	list_add(&gmem->entry, &inode->i_mapping->private_list);

	fd_install(fd, file);
	return fd;

err_file:
	fput(file);
err_fd:
	put_unused_fd(fd);
err_inode:
	iput(inode);
	return err;
}

static bool kvm_gmem_is_valid_size(loff_t size, u64 flags)
{
	if (size < 0 || !PAGE_ALIGNED(size))
		return false;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if ((flags & KVM_GUEST_MEMFD_ALLOW_HUGEPAGE) &&
	    !IS_ALIGNED(size, HPAGE_PMD_SIZE))
		return false;
#endif

	return true;
}

int kvm_gmem_create(struct kvm *kvm, struct kvm_create_guest_memfd *args)
{
	loff_t size = args->size;
	u64 flags = args->flags;
	u64 valid_flags = 0;

	if (IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		valid_flags |= KVM_GUEST_MEMFD_ALLOW_HUGEPAGE;

	if (flags & ~valid_flags)
		return -EINVAL;

	if (!kvm_gmem_is_valid_size(size, flags))
		return -EINVAL;

	return __kvm_gmem_create(kvm, size, flags, kvm_gmem_mnt);
}

int kvm_gmem_bind(struct kvm *kvm, struct kvm_memory_slot *slot,
		  unsigned int fd, loff_t offset)
{
	loff_t size = slot->npages << PAGE_SHIFT;
	unsigned long start, end, flags;
	struct kvm_gmem *gmem;
	struct inode *inode;
	struct file *file;

	BUILD_BUG_ON(sizeof(gfn_t) != sizeof(slot->gmem.pgoff));

	file = fget(fd);
	if (!file)
		return -EINVAL;

	if (file->f_op != &kvm_gmem_fops)
		goto err;

	gmem = file->private_data;
	if (gmem->kvm != kvm)
		goto err;

	inode = file_inode(file);
	flags = (unsigned long)inode->i_private;

	/*
	 * For simplicity, require the offset into the file and the size of the
	 * memslot to be aligned to the largest possible page size used to back
	 * the file (same as the size of the file itself).
	 */
	if (!kvm_gmem_is_valid_size(offset, flags) ||
	    !kvm_gmem_is_valid_size(size, flags))
		goto err;

	if (offset + size > i_size_read(inode))
		goto err;

	filemap_invalidate_lock(inode->i_mapping);

	start = offset >> PAGE_SHIFT;
	end = start + slot->npages;

	if (!xa_empty(&gmem->bindings) &&
	    xa_find(&gmem->bindings, &start, end - 1, XA_PRESENT)) {
		filemap_invalidate_unlock(inode->i_mapping);
		goto err;
	}

	/*
	 * No synchronize_rcu() needed, any in-flight readers are guaranteed to
	 * be see either a NULL file or this new file, no need for them to go
	 * away.
	 */
	rcu_assign_pointer(slot->gmem.file, file);
	slot->gmem.pgoff = start;

	xa_store_range(&gmem->bindings, start, end - 1, slot, GFP_KERNEL);
	filemap_invalidate_unlock(inode->i_mapping);

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
	unsigned long start = slot->gmem.pgoff;
	unsigned long end = start + slot->npages;
	struct kvm_gmem *gmem;
	struct file *file;

	/*
	 * Nothing to do if the underlying file was already closed (or is being
	 * closed right now), kvm_gmem_release() invalidates all bindings.
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
		     gfn_t gfn, kvm_pfn_t *pfn, int *max_order)
{
	pgoff_t index = gfn - slot->base_gfn + slot->gmem.pgoff;
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

	folio = kvm_gmem_get_folio(file_inode(file), index);
	if (!folio) {
		fput(file);
		return -ENOMEM;
	}

	page = folio_file_page(folio, index);

	*pfn = page_to_pfn(page);
	*max_order = compound_order(compound_head(page));

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
