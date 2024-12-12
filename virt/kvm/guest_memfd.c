// SPDX-License-Identifier: GPL-2.0
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/kvm_host.h>
#include <linux/pagemap.h>
#include <linux/anon_inodes.h>
#include <linux/pseudo_fs.h>

#include "kvm_mm.h"

/* Do all the filesystem crap just for evict_inode... */

static struct vfsmount *kvm_gmem_mnt __read_mostly;

static void gmem_evict_inode(struct inode *inode)
{
	kvfree(inode->i_private);
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
}

static const struct super_operations gmem_super_operations = {
	.drop_inode	= generic_delete_inode,
	.evict_inode    = gmem_evict_inode,
	.statfs         = simple_statfs,
};

static int gmem_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, KVM_GUEST_MEM_MAGIC);
	if (!ctx)
		return -ENOMEM;

	ctx->ops = &gmem_super_operations;
	return 0;
}

static struct file_system_type kvm_gmem_fs_type = {
	.name           = "kvm_gmemfs",
	.init_fs_context = gmem_init_fs_context,
	.kill_sb        = kill_anon_super,
};

static struct file *kvm_gmem_create_file(const char *name, const struct file_operations *fops)
{
	struct inode *inode;
	struct file *file;

	if (fops->owner && !try_module_get(fops->owner))
		return ERR_PTR(-ENOENT);

	inode = alloc_anon_inode(kvm_gmem_mnt->mnt_sb);
	if (IS_ERR(inode)) {
		file = ERR_CAST(inode);
		goto err;
	}
	file = alloc_file_pseudo(inode, kvm_gmem_mnt, name, O_RDWR, fops);
	if (IS_ERR(file))
		goto err_iput;

	return file;

err_iput:
	iput(inode);
err:
	module_put(fops->owner);
	return file;
}


#define KVM_GMEM_INODE_SIZE(size)			\
	struct_size_t(struct kvm_gmem_inode, prepared,	\
		      DIV_ROUND_UP(size, PAGE_SIZE * BITS_PER_LONG))

struct kvm_gmem_inode {
	unsigned long flags;
	unsigned long prepared[];
};

struct kvm_gmem {
	struct kvm *kvm;
	struct xarray bindings;
	struct list_head entry;
};

/**
 * folio_file_pfn - like folio_file_page, but return a pfn.
 * @folio: The folio which contains this index.
 * @index: The index we want to look up.
 *
 * Return: The pfn for this index.
 */
static inline kvm_pfn_t folio_file_pfn(struct folio *folio, pgoff_t index)
{
	return folio_pfn(folio) + (index & (folio_nr_pages(folio) - 1));
}

static int __kvm_gmem_prepare_folio(struct kvm *kvm, struct kvm_memory_slot *slot,
				    pgoff_t index, struct folio *folio, int max_order)
{
#ifdef CONFIG_HAVE_KVM_ARCH_GMEM_PREPARE
	kvm_pfn_t pfn = folio_file_pfn(folio, index);
	gfn_t gfn = slot->base_gfn + index - slot->gmem.pgoff;
	int rc = kvm_arch_gmem_prepare(kvm, gfn, pfn, max_order);
	if (rc) {
		pr_warn_ratelimited("gmem: Failed to prepare folio for index %lx GFN %llx PFN %llx max_order %d error %d.\n",
				    index, gfn, pfn, max_order, rc);
		return rc;
	}
#endif

	return 0;
}

/*
 * The bitmap of prepared pages has to be accessed atomically, because
 * preparation is not protected by any guest.  This unfortunately means
 * that we cannot use regular bitmap operations.
 *
 * The logic becomes a bit simpler for set and test, which operate a
 * folio at a time and therefore can assume that the range is naturally
 * aligned (meaning that either it is smaller than a word, or it is does
 * not include fractions of a word).  For punch-hole operations however
 * there is all the complexity.
 */

static void bitmap_set_atomic_word(unsigned long *p, unsigned long start, unsigned long len)
{
	unsigned long mask_to_set =
		BITMAP_FIRST_WORD_MASK(start) & BITMAP_LAST_WORD_MASK(start + len);

	atomic_long_or(mask_to_set, (atomic_long_t *)p);
}

static void bitmap_clear_atomic_word(unsigned long *p, unsigned long start, unsigned long len)
{
	unsigned long mask_to_set =
		BITMAP_FIRST_WORD_MASK(start) & BITMAP_LAST_WORD_MASK(start + len);

	atomic_long_andnot(mask_to_set, (atomic_long_t *)p);
}

static bool bitmap_test_allset_word(unsigned long *p, unsigned long start, unsigned long len)
{
	unsigned long mask_to_set =
		BITMAP_FIRST_WORD_MASK(start) & BITMAP_LAST_WORD_MASK(start + len);

	return (*p & mask_to_set) == mask_to_set;
}

static void kvm_gmem_mark_prepared(struct file *file, pgoff_t index, int order)
{
	struct kvm_gmem_inode *i_gmem = (struct kvm_gmem_inode *)file->f_inode->i_private;
	unsigned long npages = (1ul << order);
	unsigned long *p;

	rwsem_assert_held(&file->f_mapping->invalidate_lock);

	/* The index isn't necessarily aligned to the requested order. */
	index &= ~(npages - 1);
	p = i_gmem->prepared + BIT_WORD(index);

	/* Clear page before updating bitmap.  */
	smp_wmb();

	if (npages < BITS_PER_LONG) {
		bitmap_set_atomic_word(p, index, npages);
	} else {
		BUILD_BUG_ON(BITS_PER_LONG != 64);
		memset64((u64 *)p, ~0, BITS_TO_LONGS(npages));
	}
}

static void kvm_gmem_mark_range_unprepared(struct inode *inode, pgoff_t index, pgoff_t npages)
{
	struct kvm_gmem_inode *i_gmem = (struct kvm_gmem_inode *)inode->i_private;
	unsigned long *p = i_gmem->prepared + BIT_WORD(index);

	rwsem_assert_held(&inode->i_mapping->invalidate_lock);

	index &= BITS_PER_LONG - 1;
	if (index) {
		int first_word_count = min(npages, BITS_PER_LONG - index);
		bitmap_clear_atomic_word(p, index, first_word_count);
		npages -= first_word_count;
		p++;
	}

	if (npages > BITS_PER_LONG) {
		BUILD_BUG_ON(BITS_PER_LONG != 64);
		memset64((u64 *)p, 0, BIT_WORD(npages));
		p += BIT_WORD(npages);
		npages &= BITS_PER_LONG - 1;
	}

	if (npages)
		bitmap_clear_atomic_word(p++, 0, npages);
}

static bool kvm_gmem_is_prepared(struct file *file, pgoff_t index, int order)
{
	struct kvm_gmem_inode *i_gmem = (struct kvm_gmem_inode *)file->f_inode->i_private;
	unsigned long npages = (1ul << order);
	unsigned long *p;
	bool ret;

	rwsem_assert_held(&file->f_mapping->invalidate_lock);

	/* The index isn't necessarily aligned to the requested order. */
	index &= ~(npages - 1);
	p = i_gmem->prepared + BIT_WORD(index);

	if (npages < BITS_PER_LONG) {
		ret = bitmap_test_allset_word(p, index, npages);
	} else {
		for (; npages > 0; npages -= BITS_PER_LONG)
			if (*p++ != ~0)
				break;
		ret = (npages == 0);
	}

	/* Synchronize with kvm_gmem_mark_prepared().  */
	smp_rmb();
	return ret;
}

/*
 * Process @folio, which contains @gfn, so that the guest can use it.
 * The folio must be locked and the gfn must be contained in @slot.
 * On successful return the guest sees a zero page so as to avoid
 * leaking host data and the up-to-date flag is set.
 */
static int kvm_gmem_prepare_folio(struct kvm *kvm, struct file *file,
				  struct kvm_memory_slot *slot,
				  gfn_t gfn, struct folio *folio, int max_order)
{
	unsigned long nr_pages, i;
	pgoff_t index, aligned_index;
	int r;

	rwsem_assert_held(&file->f_mapping->invalidate_lock);

	index = gfn - slot->base_gfn + slot->gmem.pgoff;
	nr_pages = (1ull << max_order);
	WARN_ON(nr_pages > folio_nr_pages(folio));
	aligned_index = ALIGN_DOWN(index, nr_pages);

	for (i = 0; i < nr_pages; i++)
		if (!kvm_gmem_is_prepared(file, aligned_index + i, 0))
			clear_highpage(folio_page(folio, aligned_index - folio_index(folio) + i));

	/*
	 * In cases where only a sub-range of a folio is prepared, e.g. via
	 * calling kvm_gmem_populate() for a non-aligned GPA range, or when
	 * there's a mix of private/shared attributes for the GPA range that
	 * the folio backs, it's possible that later on the same folio might
	 * be accessed with a larger order when it becomes possible to map
	 * the full GPA range into the guest using a larger order. In such
	 * cases, some sub-ranges might already have been prepared.
	 *
	 * Because of this, the arch-specific callbacks should be expected
	 * to handle dealing with cases where some sub-ranges are already
	 * in a prepared state, since the alternative would involve needing
	 * to issue multiple prepare callbacks with finer granularity, and
	 * potentially obfuscating cases where arch-specific callbacks can
	 * be notified of larger-order mappings and potentially optimize
	 * preparation based on that knowledge.
	 */
	r = __kvm_gmem_prepare_folio(kvm, slot, index, folio, max_order);
	if (!r)
		kvm_gmem_mark_prepared(file, index, max_order);

	return r;
}

static struct folio *kvm_gmem_get_huge_folio(struct inode *inode, pgoff_t index,
					     unsigned int order)
{
	pgoff_t npages = 1UL << order;
	pgoff_t huge_index = round_down(index, npages);
	struct address_space *mapping  = inode->i_mapping;
	gfp_t gfp = mapping_gfp_mask(mapping) | __GFP_NOWARN;
	loff_t size = i_size_read(inode);
	struct folio *folio;

	/* Make sure hugepages would be fully-contained by inode */
	if ((huge_index + npages) * PAGE_SIZE > size)
		return NULL;

	if (filemap_range_has_page(mapping, (loff_t)huge_index << PAGE_SHIFT,
				   (loff_t)(huge_index + npages - 1) << PAGE_SHIFT))
		return NULL;

	folio = filemap_alloc_folio(gfp, order);
	if (!folio)
		return NULL;

	if (filemap_add_folio(mapping, folio, huge_index, gfp)) {
		folio_put(folio);
		return NULL;
	}

	return folio;
}

/*
 * Returns a locked folio on success.  The caller is responsible for
 * setting the up-to-date flag before the memory is mapped into the guest.
 * There is no backing storage for the memory, so the folio will remain
 * up-to-date until it's removed.
 *
 * Ignore accessed, referenced, and dirty flags.  The memory is
 * unevictable and there is no storage to write back to.
 */
static struct folio *kvm_gmem_get_folio(struct inode *inode, pgoff_t index)
{
	struct folio *folio = NULL;

	if (gmem_2m_enabled)
		folio = kvm_gmem_get_huge_folio(inode, index, PMD_ORDER);

	if (!folio)
		folio = filemap_grab_folio(inode->i_mapping, index);

	return folio;
}

static void kvm_gmem_invalidate_begin(struct kvm_gmem *gmem, pgoff_t start,
				      pgoff_t end)
{
	bool flush = false, found_memslot = false;
	struct kvm_memory_slot *slot;
	struct kvm *kvm = gmem->kvm;
	unsigned long index;

	xa_for_each_range(&gmem->bindings, index, slot, start, end - 1) {
		pgoff_t pgoff = slot->gmem.pgoff;

		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + max(pgoff, start) - pgoff,
			.end = slot->base_gfn + min(pgoff + slot->npages, end) - pgoff,
			.slot = slot,
			.may_block = true,
			/* guest memfd is relevant to only private mappings. */
			.attr_filter = KVM_FILTER_PRIVATE,
		};

		if (!found_memslot) {
			found_memslot = true;

			KVM_MMU_LOCK(kvm);
			kvm_mmu_invalidate_begin(kvm);
		}

		flush |= kvm_mmu_unmap_gfn_range(kvm, &gfn_range);
	}

	if (flush)
		kvm_flush_remote_tlbs(kvm);

	if (found_memslot)
		KVM_MMU_UNLOCK(kvm);
}

static void kvm_gmem_invalidate_end(struct kvm_gmem *gmem, pgoff_t start,
				    pgoff_t end)
{
	struct kvm *kvm = gmem->kvm;

	if (xa_find(&gmem->bindings, &start, end - 1, XA_PRESENT)) {
		KVM_MMU_LOCK(kvm);
		kvm_mmu_invalidate_end(kvm);
		KVM_MMU_UNLOCK(kvm);
	}
}

static long kvm_gmem_punch_hole(struct inode *inode, loff_t offset, loff_t len)
{
	struct list_head *gmem_list = &inode->i_mapping->i_private_list;
	loff_t size = i_size_read(inode);
	pgoff_t start, end;
	struct kvm_gmem *gmem;

	if (offset > size)
		return 0;

	len = min(size - offset, len);
	start = offset >> PAGE_SHIFT;
	end = (offset + len) >> PAGE_SHIFT;

	/*
	 * Bindings must be stable across invalidation to ensure the start+end
	 * are balanced.
	 */
	filemap_invalidate_lock(inode->i_mapping);

	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_begin(gmem, start, end);

	truncate_inode_pages_range(inode->i_mapping, offset, offset + len - 1);
	kvm_gmem_mark_range_unprepared(inode, start, end - start);

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
		if (IS_ERR(folio)) {
			r = PTR_ERR(folio);
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
	 *
	 * Since .release is called only when the reference count is zero,
	 * after which file_ref_get() and get_file_active() fail,
	 * kvm_gmem_get_pfn() cannot be using the file concurrently.
	 * file_ref_put() provides a full barrier, and get_file_active() the
	 * matching acquire barrier.
	 */
	mutex_lock(&kvm->slots_lock);

	filemap_invalidate_lock(inode->i_mapping);

	xa_for_each(&gmem->bindings, index, slot)
		WRITE_ONCE(slot->gmem.file, NULL);

	/*
	 * All in-flight operations are gone and new bindings can be created.
	 * Zap all SPTEs pointed at by this file.  Do not free the backing
	 * memory, as its lifetime is associated with the inode, not the file.
	 */
	kvm_gmem_invalidate_begin(gmem, 0, -1ul);
	kvm_gmem_invalidate_end(gmem, 0, -1ul);

	list_del(&gmem->entry);

	filemap_invalidate_unlock(inode->i_mapping);

	mutex_unlock(&kvm->slots_lock);

	xa_destroy(&gmem->bindings);
	kfree(gmem);

	kvm_put_kvm(kvm);

	return 0;
}

static inline struct file *kvm_gmem_get_file(struct kvm_memory_slot *slot)
{
	/*
	 * Do not return slot->gmem.file if it has already been closed;
	 * there might be some time between the last fput() and when
	 * kvm_gmem_release() clears slot->gmem.file.
	 */
	return get_file_active(&slot->gmem.file);
}

static pgoff_t kvm_gmem_get_index(struct kvm_memory_slot *slot, gfn_t gfn)
{
	return gfn - slot->base_gfn + slot->gmem.pgoff;
}

static struct file_operations kvm_gmem_fops = {
	.open		= generic_file_open,
	.release	= kvm_gmem_release,
	.fallocate	= kvm_gmem_fallocate,
};

int kvm_gmem_init(struct module *module)
{
	int ret;

	ret = register_filesystem(&kvm_gmem_fs_type);
	if (ret) {
		pr_err("kvm-gmem: cannot register file system (%d)\n", ret);
		return ret;
	}

	kvm_gmem_mnt = kern_mount(&kvm_gmem_fs_type);
	if (IS_ERR(kvm_gmem_mnt)) {
		pr_err("kvm-gmem: kernel mount failed (%ld)\n", PTR_ERR(kvm_gmem_mnt));
		return PTR_ERR(kvm_gmem_mnt);
	}

	kvm_gmem_fops.owner = module;

	return 0;
}

void kvm_gmem_exit(void)
{
	kern_unmount(kvm_gmem_mnt);
	unregister_filesystem(&kvm_gmem_fs_type);
}

static int kvm_gmem_migrate_folio(struct address_space *mapping,
				  struct folio *dst, struct folio *src,
				  enum migrate_mode mode)
{
	WARN_ON_ONCE(1);
	return -EINVAL;
}

static int kvm_gmem_error_folio(struct address_space *mapping, struct folio *folio)
{
	struct list_head *gmem_list = &mapping->i_private_list;
	struct kvm_gmem *gmem;
	pgoff_t start, end;

	filemap_invalidate_lock_shared(mapping);

	start = folio->index;
	end = start + folio_nr_pages(folio);

	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_begin(gmem, start, end);

	/*
	 * Do not truncate the range, what action is taken in response to the
	 * error is userspace's decision (assuming the architecture supports
	 * gracefully handling memory errors).  If/when the guest attempts to
	 * access a poisoned page, kvm_gmem_get_pfn() will return -EHWPOISON,
	 * at which point KVM can either terminate the VM or propagate the
	 * error to userspace.
	 */

	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_end(gmem, start, end);

	filemap_invalidate_unlock_shared(mapping);

	return MF_DELAYED;
}

#ifdef CONFIG_HAVE_KVM_ARCH_GMEM_INVALIDATE
static void kvm_gmem_free_folio(struct folio *folio)
{
	struct page *page = folio_page(folio, 0);
	kvm_pfn_t pfn = page_to_pfn(page);
	int order = folio_order(folio);

	kvm_arch_gmem_invalidate(pfn, pfn + (1ul << order));
}
#endif

static const struct address_space_operations kvm_gmem_aops = {
	.dirty_folio = noop_dirty_folio,
	.migrate_folio	= kvm_gmem_migrate_folio,
	.error_remove_folio = kvm_gmem_error_folio,
#ifdef CONFIG_HAVE_KVM_ARCH_GMEM_INVALIDATE
	.free_folio = kvm_gmem_free_folio,
#endif
};

static int kvm_gmem_getattr(struct mnt_idmap *idmap, const struct path *path,
			    struct kstat *stat, u32 request_mask,
			    unsigned int query_flags)
{
	struct inode *inode = path->dentry->d_inode;

	generic_fillattr(idmap, request_mask, inode, stat);
	return 0;
}

static int kvm_gmem_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			    struct iattr *attr)
{
	return -EINVAL;
}
static const struct inode_operations kvm_gmem_iops = {
	.getattr	= kvm_gmem_getattr,
	.setattr	= kvm_gmem_setattr,
};

static int __kvm_gmem_create(struct kvm *kvm, loff_t size, u64 flags)
{
	const char *gmem_name = "[kvm-gmem]";
	struct kvm_gmem_inode *i_gmem;
	struct kvm_gmem *gmem;
	struct inode *inode;
	struct file *file;
	int fd, err;

	i_gmem = kvzalloc(KVM_GMEM_INODE_SIZE(size), GFP_KERNEL);
	if (!i_gmem)
		return -ENOMEM;
	i_gmem->flags = flags;

	fd = get_unused_fd_flags(0);
	if (fd < 0) {
		err = fd;
		goto err_i_gmem;
	}

	gmem = kzalloc(sizeof(*gmem), GFP_KERNEL);
	if (!gmem) {
		err = -ENOMEM;
		goto err_fd;
	}

	file = kvm_gmem_create_file(gmem_name, &kvm_gmem_fops);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_gmem;
	}

	inode = file->f_inode;

	file->f_mapping = inode->i_mapping;
	file->private_data = gmem;
	file->f_flags |= O_LARGEFILE;

	inode->i_private = i_gmem;
	inode->i_op = &kvm_gmem_iops;
	inode->i_mapping->a_ops = &kvm_gmem_aops;
	inode->i_mode |= S_IFREG;
	inode->i_size = size;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_inaccessible(inode->i_mapping);
	mapping_set_large_folios(inode->i_mapping);
	/* Unmovable mappings are supposed to be marked unevictable as well. */
	WARN_ON_ONCE(!mapping_unevictable(inode->i_mapping));

	kvm_get_kvm(kvm);
	gmem->kvm = kvm;
	xa_init(&gmem->bindings);
	list_add(&gmem->entry, &inode->i_mapping->i_private_list);

	fd_install(fd, file);
	return fd;

err_gmem:
	kfree(gmem);
err_fd:
	put_unused_fd(fd);
err_i_gmem:
	kvfree(i_gmem);
	return err;
}

int kvm_gmem_create(struct kvm *kvm, struct kvm_create_guest_memfd *args)
{
	loff_t size = args->size;
	u64 flags = args->flags;
	u64 valid_flags = 0;

	if (flags & ~valid_flags)
		return -EINVAL;

	if (size <= 0 || !PAGE_ALIGNED(size))
		return -EINVAL;

	return __kvm_gmem_create(kvm, size, flags);
}

int kvm_gmem_bind(struct kvm *kvm, struct kvm_memory_slot *slot,
		  unsigned int fd, loff_t offset)
{
	loff_t size = slot->npages << PAGE_SHIFT;
	unsigned long start, end;
	struct kvm_gmem *gmem;
	struct inode *inode;
	struct file *file;
	int r = -EINVAL;

	BUILD_BUG_ON(sizeof(gfn_t) != sizeof(slot->gmem.pgoff));

	file = fget(fd);
	if (!file)
		return -EBADF;

	if (file->f_op != &kvm_gmem_fops)
		goto err;

	gmem = file->private_data;
	if (gmem->kvm != kvm)
		goto err;

	inode = file_inode(file);

	if (offset < 0 || !PAGE_ALIGNED(offset) ||
	    offset + size > i_size_read(inode))
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
	 * memslots of flag KVM_MEM_GUEST_MEMFD are immutable to change, so
	 * kvm_gmem_bind() must occur on a new memslot.  Because the memslot
	 * is not visible yet, kvm_gmem_get_pfn() is guaranteed to see the file.
	 */
	WRITE_ONCE(slot->gmem.file, file);
	slot->gmem.pgoff = start;

	xa_store_range(&gmem->bindings, start, end - 1, slot, GFP_KERNEL);
	filemap_invalidate_unlock(inode->i_mapping);

	/*
	 * Drop the reference to the file, even on success.  The file pins KVM,
	 * not the other way 'round.  Active bindings are invalidated if the
	 * file is closed before memslots are destroyed.
	 */
	r = 0;
err:
	fput(file);
	return r;
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

	/*
	 * synchronize_srcu(&kvm->srcu) ensured that kvm_gmem_get_pfn()
	 * cannot see this memslot.
	 */
	WRITE_ONCE(slot->gmem.file, NULL);
	filemap_invalidate_unlock(file->f_mapping);

	fput(file);
}

/* Returns a locked folio on success.  */
static struct folio *__kvm_gmem_get_pfn(struct file *file,
					struct kvm_memory_slot *slot,
					pgoff_t index, kvm_pfn_t *pfn,
					int *max_order)
{
	struct file *gmem_file = READ_ONCE(slot->gmem.file);
	struct kvm_gmem *gmem = file->private_data;
	struct folio *folio;
	pgoff_t huge_index;

	if (file != gmem_file) {
		WARN_ON_ONCE(gmem_file);
		return ERR_PTR(-EFAULT);
	}

	gmem = file->private_data;
	if (xa_load(&gmem->bindings, index) != slot) {
		WARN_ON_ONCE(xa_load(&gmem->bindings, index));
		return ERR_PTR(-EIO);
	}

	/*
	 * The folio can be mapped with a hugepage if and only if the folio is
	 * fully contained by the range the memslot is bound to.  Note, the
	 * caller is responsible for handling gfn alignment, this only deals
	 * with the file binding.
	 */
	huge_index = ALIGN_DOWN(index, 1ull << *max_order);
	if (huge_index < slot->gmem.pgoff ||
	    huge_index + (1ull << *max_order) > slot->gmem.pgoff + slot->npages)
		*max_order = 0;

	folio = kvm_gmem_get_folio(file_inode(file), index);
	if (IS_ERR(folio))
		return folio;

	if (folio_test_hwpoison(folio)) {
		folio_unlock(folio);
		folio_put(folio);
		return ERR_PTR(-EHWPOISON);
	}

	*pfn = folio_file_pfn(folio, index);
	*max_order = min_t(int, *max_order, folio_order(folio));

	return folio;
}

int kvm_gmem_get_pfn(struct kvm *kvm, struct kvm_memory_slot *slot,
		     gfn_t gfn, kvm_pfn_t *pfn, struct page **page,
		     int *max_order)
{
	pgoff_t index = kvm_gmem_get_index(slot, gfn);
	struct file *file = kvm_gmem_get_file(slot);
	int max_order_local;
	struct address_space *mapping;
	struct folio *folio;
	int r = 0;

	if (!file)
		return -EFAULT;

	mapping = file->f_inode->i_mapping;
	filemap_invalidate_lock_shared(mapping);

	/*
	 * The caller might pass a NULL 'max_order', but internally this
	 * function needs to be aware of any order limitations set by
	 * __kvm_gmem_get_pfn() so the scope of preparation operations can
	 * be limited to the corresponding range. The initial order can be
	 * arbitrarily large, but gmem doesn't currently support anything
	 * greater than PMD_ORDER so use that for now.
	 */
	max_order_local = PMD_ORDER;

	folio = __kvm_gmem_get_pfn(file, slot, index, pfn, &max_order_local);
	if (IS_ERR(folio)) {
		r = PTR_ERR(folio);
		filemap_invalidate_unlock_shared(mapping);
		goto out;
	}

	if (!kvm_gmem_is_prepared(file, index, max_order_local))
		r = kvm_gmem_prepare_folio(kvm, file, slot, gfn, folio, max_order_local);

	folio_unlock(folio);
	filemap_invalidate_unlock_shared(mapping);

	if (!r)
		*page = folio_file_page(folio, index);
	else
		folio_put(folio);

out:
	if (max_order)
		*max_order = max_order_local;
	fput(file);
	return r;
}
EXPORT_SYMBOL_GPL(kvm_gmem_get_pfn);

#ifdef CONFIG_KVM_GENERIC_PRIVATE_MEM
long kvm_gmem_populate(struct kvm *kvm, gfn_t start_gfn, void __user *src, long npages,
		       kvm_gmem_populate_cb post_populate, void *opaque)
{
	struct file *file;
	struct kvm_memory_slot *slot;
	void __user *p;

	int ret = 0, max_order;
	long i;

	lockdep_assert_held(&kvm->slots_lock);
	if (npages < 0)
		return -EINVAL;

	slot = gfn_to_memslot(kvm, start_gfn);
	if (!kvm_slot_can_be_private(slot))
		return -EINVAL;

	file = kvm_gmem_get_file(slot);
	if (!file)
		return -EFAULT;

	filemap_invalidate_lock(file->f_mapping);

	npages = min_t(ulong, slot->npages - (start_gfn - slot->base_gfn), npages);
	for (i = 0; i < npages; i += (1 << max_order)) {
		struct folio *folio;
		gfn_t gfn = start_gfn + i;
		pgoff_t index = kvm_gmem_get_index(slot, gfn);
		kvm_pfn_t pfn;

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		folio = __kvm_gmem_get_pfn(file, slot, index, &pfn, &max_order);
		if (IS_ERR(folio)) {
			ret = PTR_ERR(folio);
			break;
		}

		if (kvm_gmem_is_prepared(file, index, max_order)) {
			folio_unlock(folio);
			folio_put(folio);
			ret = -EEXIST;
			break;
		}

		folio_unlock(folio);
		WARN_ON(!IS_ALIGNED(gfn, 1 << max_order) ||
			(npages - i) < (1 << max_order));

		ret = -EINVAL;
		while (!kvm_range_has_memory_attributes(kvm, gfn, gfn + (1 << max_order),
							KVM_MEMORY_ATTRIBUTE_PRIVATE,
							KVM_MEMORY_ATTRIBUTE_PRIVATE)) {
			if (!max_order)
				goto put_folio_and_exit;
			max_order--;
		}

		p = src ? src + i * PAGE_SIZE : NULL;
		ret = post_populate(kvm, gfn, pfn, p, max_order, opaque);
		if (!ret) {
			pgoff_t index = gfn - slot->base_gfn + slot->gmem.pgoff;
			kvm_gmem_mark_prepared(file, index, max_order);
		}

put_folio_and_exit:
		folio_put(folio);
		if (ret)
			break;
	}

	filemap_invalidate_unlock(file->f_mapping);

	fput(file);
	return ret && !i ? ret : i;
}
EXPORT_SYMBOL_GPL(kvm_gmem_populate);
#endif
