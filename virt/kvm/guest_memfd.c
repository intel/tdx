// SPDX-License-Identifier: GPL-2.0
#include <linux/anon_inodes.h>
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/guestmem.h>
#include <linux/kvm_host.h>
#include <linux/maple_tree.h>
#include <linux/mman.h>
#include <linux/pseudo_fs.h>
#include <linux/pagemap.h>

#include <uapi/linux/guestmem.h>

#include "kvm_mm.h"

static struct vfsmount *kvm_gmem_mnt;

struct kvm_gmem {
	struct kvm *kvm;
	struct xarray bindings;
	struct list_head entry;
};

struct kvm_gmem_inode_private {
#ifdef CONFIG_KVM_GMEM_SHARED_MEM
	struct maple_tree shareability;
#endif
#ifdef CONFIG_KVM_GMEM_HUGETLB
	const struct guestmem_allocator_operations *allocator_ops;
	void *allocator_private;
#endif
};

enum shareability {
	SHAREABILITY_GUEST = 1,	/* Only the guest can map (fault) folios in this range. */
	SHAREABILITY_ALL = 2,	/* Both guest and host can fault folios in this range. */
};

static struct folio *kvm_gmem_get_folio(struct inode *inode, pgoff_t index);
static int __kvm_gmem_filemap_add_folio(struct address_space *mapping,
					struct folio *folio, pgoff_t index);

static struct kvm_gmem_inode_private *kvm_gmem_private(struct inode *inode)
{
	return inode->i_mapping->i_private_data;
}

#ifdef CONFIG_KVM_GMEM_HUGETLB

static const struct guestmem_allocator_operations *
kvm_gmem_allocator_ops(struct inode *inode)
{
	return kvm_gmem_private(inode)->allocator_ops;
}

static void *kvm_gmem_allocator_private(struct inode *inode)
{
	return kvm_gmem_private(inode)->allocator_private;
}

static bool kvm_gmem_has_custom_allocator(struct inode *inode)
{
	return kvm_gmem_private(inode) && kvm_gmem_allocator_ops(inode) != NULL;
}

static unsigned long
kvm_gmem_get_unmapped_area(struct file *file, unsigned long addr,
			   unsigned long len, unsigned long pgoff,
			   unsigned long flags)
{
	struct inode *inode;
	size_t page_size;
	size_t nr_pages;
	void *priv;

	inode = file_inode(file);
	if (!kvm_gmem_has_custom_allocator(inode))
		goto out;

	priv = kvm_gmem_allocator_private(inode);
	nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);
	page_size = nr_pages << PAGE_SHIFT;

	if (!IS_ALIGNED(len, page_size))
		return -EINVAL;
	if (flags & MAP_FIXED && !IS_ALIGNED(addr, page_size))
		return -EINVAL;

	addr = ALIGN(addr, page_size);

out:
	return mm_get_unmapped_area(current->mm, file, addr, len, pgoff, flags);
}

static unsigned long kvm_gmem_get_align_mask(struct file *file,
					     unsigned long flags)
{
	struct inode *inode;
	size_t page_size;
	size_t nr_pages;
	void *priv;

	inode = file_inode(file);
	if (!kvm_gmem_has_custom_allocator(inode))
		return arch_get_align_mask(file, flags);

	priv = kvm_gmem_allocator_private(inode);
	nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);
	page_size = nr_pages << PAGE_SHIFT;

	return PAGE_MASK & (page_size - 1);
}

#else

static const struct guestmem_allocator_operations *
kvm_gmem_allocator_ops(struct inode *inode)
{
	return NULL;
}

static void *kvm_gmem_allocator_private(struct inode *inode)
{
	return NULL;
}

static bool kvm_gmem_has_custom_allocator(struct inode *inode)
{
	return false;
}

#define kvm_gmem_get_unmapped_area NULL
#define kvm_gmem_get_align_mask NULL

#endif

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

#ifdef CONFIG_KVM_GMEM_SHARED_MEM

static int kvm_gmem_shareability_setup(struct kvm_gmem_inode_private *private,
				      loff_t size, u64 flags)
{
	enum shareability m;
	pgoff_t last;

	last = (size >> PAGE_SHIFT) - 1;
	m = flags & GUEST_MEMFD_FLAG_INIT_PRIVATE ? SHAREABILITY_GUEST :
						    SHAREABILITY_ALL;
	return mtree_store_range(&private->shareability, 0, last, xa_mk_value(m),
				 GFP_KERNEL);
}

static enum shareability kvm_gmem_shareability_get(struct inode *inode,
						 pgoff_t index)
{
	struct maple_tree *mt;
	void *entry;

	mt = &kvm_gmem_private(inode)->shareability;
	entry = mtree_load(mt, index);
	WARN(!entry,
	     "Shareability should always be defined for all indices in inode.");

	return xa_to_value(entry);
}

static bool kvm_gmem_shareability_in_range(struct inode *inode, pgoff_t start,
					    size_t nr_pages, enum shareability m)
{
	struct maple_tree *mt;
	pgoff_t last;
	void *entry;

	mt = &kvm_gmem_private(inode)->shareability;

	last = start + nr_pages - 1;
	mt_for_each(mt, entry, start, last) {
		if (xa_to_value(entry) == m)
			return true;
	}

	return false;
}

static inline bool kvm_gmem_has_some_shared(struct inode *inode, pgoff_t start,
					    size_t nr_pages)
{
	return kvm_gmem_shareability_in_range(inode, start, nr_pages,
					     SHAREABILITY_ALL);
}

static struct folio *kvm_gmem_get_shared_folio(struct inode *inode, pgoff_t index)
{
	if (kvm_gmem_shareability_get(inode, index) != SHAREABILITY_ALL)
		return ERR_PTR(-EACCES);

	return kvm_gmem_get_folio(inode, index);
}

/**
 * kvm_gmem_shareability_store() - Sets shareability to @value for range.
 *
 * @mt: the shareability maple tree.
 * @index: the range begins at this index in the inode.
 * @nr_pages: number of PAGE_SIZE pages in this range.
 * @value: the shareability value to set for this range.
 *
 * Unlike mtree_store_range(), this function also merges adjacent ranges that
 * have the same values as an optimization. Assumes that all stores to @mt go
 * through this function, such that adjacent ranges are always merged.
 *
 * Return: 0 on success and negative error otherwise.
 */
static int kvm_gmem_shareability_store(struct maple_tree *mt, pgoff_t index,
				       size_t nr_pages, enum shareability value)
{
	MA_STATE(mas, mt, 0, 0);
	unsigned long start;
	unsigned long last;
	void *entry;
	int ret;

	start = index;
	last = start + nr_pages - 1;

	mas_lock(&mas);

	/* Try extending range. entry is NULL on overflow/wrap-around. */
	mas_set_range(&mas, last + 1, last + 1);
	entry = mas_find(&mas, last + 1);
	if (entry && xa_to_value(entry) == value)
		last = mas.last;

	mas_set_range(&mas, start - 1, start - 1);
	entry = mas_find(&mas, start - 1);
	if (entry && xa_to_value(entry) == value)
		start = mas.index;

	mas_set_range(&mas, start, last);
	ret = mas_store_gfp(&mas, xa_mk_value(value), GFP_KERNEL);

	mas_unlock(&mas);

	return ret;
}

struct conversion_work {
	struct list_head list;
	pgoff_t start;
	size_t nr_pages;
};

static int add_to_work_list(struct list_head *list, pgoff_t start, pgoff_t last)
{
	struct conversion_work *work;

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	work->start = start;
	work->nr_pages = last + 1 - start;

	list_add_tail(&work->list, list);

	return 0;
}

static bool kvm_gmem_has_safe_refcount(struct address_space *mapping, pgoff_t start,
				       size_t nr_pages, pgoff_t *error_index)
{
	const int filemap_get_folios_refcount = 1;
	struct folio_batch fbatch;
	bool refcount_safe;
	pgoff_t last;
	int i;

	last = start + nr_pages - 1;
	refcount_safe = true;

	folio_batch_init(&fbatch);
	while (refcount_safe &&
	       filemap_get_folios(mapping, &start, last, &fbatch)) {

		for (i = 0; i < folio_batch_count(&fbatch); ++i) {
			int filemap_refcount;
			int safe_refcount;
			struct folio *f;

			f = fbatch.folios[i];
			filemap_refcount = folio_nr_pages(f);

			safe_refcount = filemap_refcount + filemap_get_folios_refcount;
			if (folio_ref_count(f) != safe_refcount) {
				refcount_safe = false;
				*error_index = f->index;
				break;
			}
		}

		folio_batch_release(&fbatch);
	}

	return refcount_safe;
}

static void kvm_gmem_unmap_private(struct kvm_gmem *gmem, pgoff_t start,
				   pgoff_t end)
{
	struct kvm_memory_slot *slot;
	struct kvm *kvm = gmem->kvm;
	unsigned long index;
	bool locked = false;
	bool flush = false;

	xa_for_each_range(&gmem->bindings, index, slot, start, end - 1) {
		pgoff_t pgoff = slot->gmem.pgoff;

		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + max(pgoff, start) - pgoff,
			.end = slot->base_gfn + min(pgoff + slot->npages, end) - pgoff,
			.slot = slot,
			.may_block = true,
			/* This function is only concerned with private mappings. */
			.attr_filter = KVM_FILTER_PRIVATE,
		};

		if (!locked) {
			KVM_MMU_LOCK(kvm);
			locked = true;
		}

		flush |= kvm_mmu_unmap_gfn_range(kvm, &gfn_range);
	}

	if (flush)
		kvm_flush_remote_tlbs(kvm);

	if (locked)
		KVM_MMU_UNLOCK(kvm);
}

static void kvm_gmem_invalidate_begin(struct kvm_gmem *gmem, pgoff_t start,
				      pgoff_t end)
{
	struct kvm_memory_slot *slot;
	struct kvm *kvm = gmem->kvm;
	unsigned long index;
	bool found_memslot;

	found_memslot = false;
	xa_for_each_range(&gmem->bindings, index, slot, start, end - 1) {
		gfn_t gfn_start;
		gfn_t gfn_end;
		pgoff_t pgoff;

		pgoff = slot->gmem.pgoff;

		gfn_start = slot->base_gfn + max(pgoff, start) - pgoff;
		gfn_end = slot->base_gfn + min(pgoff + slot->npages, end) - pgoff;

		if (!found_memslot) {
			found_memslot = true;

			KVM_MMU_LOCK(kvm);
			kvm_mmu_invalidate_begin(kvm);
		}

		kvm_mmu_invalidate_range_add(kvm, gfn_start, gfn_end);
	}

	if (found_memslot)
		KVM_MMU_UNLOCK(kvm);
}

static pgoff_t kvm_gmem_compute_invalidate_bound(struct inode *inode,
						 pgoff_t bound, bool start)
{
	size_t nr_pages;
	void *priv;

	if (!kvm_gmem_has_custom_allocator(inode))
		return bound;

	priv = kvm_gmem_allocator_private(inode);
	nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);

	if (start)
		return round_down(bound, nr_pages);
	else
		return round_up(bound, nr_pages);
}

static pgoff_t kvm_gmem_compute_invalidate_start(struct inode *inode,
						 pgoff_t bound)
{
	return kvm_gmem_compute_invalidate_bound(inode, bound, true);
}

static pgoff_t kvm_gmem_compute_invalidate_end(struct inode *inode,
					       pgoff_t bound)
{
	return kvm_gmem_compute_invalidate_bound(inode, bound, false);
}

static int kvm_gmem_shareability_apply(struct inode *inode,
				       struct conversion_work *work,
				       enum shareability m)
{
	struct maple_tree *mt;

	mt = &kvm_gmem_private(inode)->shareability;
	return kvm_gmem_shareability_store(mt, work->start, work->nr_pages, m);
}

static int kvm_gmem_convert_compute_work(struct inode *inode, pgoff_t start,
					 size_t nr_pages, enum shareability m,
					 struct list_head *work_list)
{
	struct maple_tree *mt;
	struct ma_state mas;
	pgoff_t last;
	void *entry;
	int ret;

	last = start + nr_pages - 1;

	mt = &kvm_gmem_private(inode)->shareability;
	ret = 0;

	mas_init(&mas, mt, start);

	rcu_read_lock();
	mas_for_each(&mas, entry, last) {
		enum shareability current_m;
		pgoff_t m_range_index;
		pgoff_t m_range_last;
		int ret;

		m_range_index = max(mas.index, start);
		m_range_last = min(mas.last, last);

		current_m = xa_to_value(entry);
		if (m == current_m)
			continue;

		mas_pause(&mas);
		rcu_read_unlock();
		/* Caller will clean this up on error. */
		ret = add_to_work_list(work_list, m_range_index, m_range_last);
		rcu_read_lock();
		if (ret)
			break;
	}
	rcu_read_unlock();

	return ret;
}

static void kvm_gmem_convert_invalidate_begin(struct inode *inode,
					      struct conversion_work *work)
{
	struct list_head *gmem_list;
	pgoff_t invalidate_start;
	pgoff_t invalidate_end;
	struct kvm_gmem *gmem;
	pgoff_t work_end;

	work_end = work->start + work->nr_pages;
	invalidate_start = kvm_gmem_compute_invalidate_start(inode, work->start);
	invalidate_end = kvm_gmem_compute_invalidate_end(inode, work_end);

	gmem_list = &inode->i_mapping->i_private_list;
	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_begin(gmem, invalidate_start, invalidate_end);
}

static void kvm_gmem_invalidate_end(struct kvm_gmem *gmem, pgoff_t start,
				    pgoff_t end);

static void kvm_gmem_convert_invalidate_end(struct inode *inode,
					    struct conversion_work *work)
{
	struct list_head *gmem_list;
	pgoff_t invalidate_start;
	pgoff_t invalidate_end;
	struct kvm_gmem *gmem;
	pgoff_t work_end;

	work_end = work->start + work->nr_pages;
	invalidate_start = kvm_gmem_compute_invalidate_start(inode, work->start);
	invalidate_end = kvm_gmem_compute_invalidate_end(inode, work_end);

	gmem_list = &inode->i_mapping->i_private_list;
	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_end(gmem, invalidate_start, invalidate_end);
}

static int kvm_gmem_convert_should_proceed(struct inode *inode,
					   struct conversion_work *work,
					   bool to_shared, pgoff_t *error_index)
{
	if (to_shared) {
		struct list_head *gmem_list;
		struct kvm_gmem *gmem;
		pgoff_t work_end;

		work_end = work->start + work->nr_pages;

		gmem_list = &inode->i_mapping->i_private_list;
		list_for_each_entry(gmem, gmem_list, entry)
			kvm_gmem_unmap_private(gmem, work->start, work_end);
	} else {
		unmap_mapping_pages(inode->i_mapping, work->start,
				    work->nr_pages, false);

		if (!kvm_gmem_has_safe_refcount(inode->i_mapping, work->start,
						work->nr_pages, error_index)) {
			return -EAGAIN;
		}
	}

	return 0;
}

static int kvm_gmem_restructure_folios_in_range(struct inode *inode,
						pgoff_t start, size_t nr_pages,
						bool is_split_operation);

static int kvm_gmem_convert_execute_work(struct inode *inode,
					 struct conversion_work *work,
					 bool to_shared)
{
	enum shareability m;
	int ret;

	m = to_shared ? SHAREABILITY_ALL : SHAREABILITY_GUEST;
	ret = kvm_gmem_shareability_apply(inode, work, m);
	if (ret)
		return ret;
	/*
	 * Apply shareability first so split/merge can operate on new
	 * shareability state.
	 */
	ret = kvm_gmem_restructure_folios_in_range(
		inode, work->start, work->nr_pages, to_shared);

	return ret;
}

static int kvm_gmem_convert_range(struct file *file, pgoff_t start,
				  size_t nr_pages, bool shared,
				  pgoff_t *error_index)
{
	struct conversion_work *work, *tmp, *rollback_stop_item;
	LIST_HEAD(work_list);
	struct inode *inode;
	enum shareability m;
	int ret;

	inode = file_inode(file);

	filemap_invalidate_lock(inode->i_mapping);

	m = shared ? SHAREABILITY_ALL : SHAREABILITY_GUEST;
	ret = kvm_gmem_convert_compute_work(inode, start, nr_pages, m, &work_list);
	if (ret || list_empty(&work_list))
		goto out;

	list_for_each_entry(work, &work_list, list)
		kvm_gmem_convert_invalidate_begin(inode, work);

	list_for_each_entry(work, &work_list, list) {
		ret = kvm_gmem_convert_should_proceed(inode, work, shared,
						      error_index);
		if (ret)
			goto invalidate_end;
	}

	list_for_each_entry(work, &work_list, list) {
		rollback_stop_item = work;

		ret = kvm_gmem_convert_execute_work(inode, work, shared);
		if (ret)
			break;
	}

	if (ret) {
		list_for_each_entry(work, &work_list, list) {
			int r;

			r = kvm_gmem_convert_execute_work(inode, work, !shared);
			WARN_ON(r);

			if (work == rollback_stop_item)
				break;
		}
	}

invalidate_end:
	list_for_each_entry(work, &work_list, list)
		kvm_gmem_convert_invalidate_end(inode, work);
out:
	filemap_invalidate_unlock(inode->i_mapping);

	list_for_each_entry_safe(work, tmp, &work_list, list) {
		list_del(&work->list);
		kfree(work);
	}

	return ret;
}

static int kvm_gmem_ioctl_convert_range(struct file *file,
					struct kvm_gmem_convert *param,
					bool shared)
{
	pgoff_t error_index;
	size_t nr_pages;
	pgoff_t start;
	int ret;

	if (param->error_offset)
		return -EINVAL;

	if (param->size == 0)
		return 0;

	if (param->offset + param->size < param->offset ||
	    param->offset > file_inode(file)->i_size ||
	    param->offset + param->size > file_inode(file)->i_size)
		return -EINVAL;

	if (!IS_ALIGNED(param->offset, PAGE_SIZE) ||
	    !IS_ALIGNED(param->size, PAGE_SIZE))
		return -EINVAL;

	start = param->offset >> PAGE_SHIFT;
	nr_pages = param->size >> PAGE_SHIFT;

	ret = kvm_gmem_convert_range(file, start, nr_pages, shared, &error_index);
	if (ret)
		param->error_offset = error_index << PAGE_SHIFT;

	return ret;
}

#ifdef CONFIG_KVM_GMEM_HUGETLB

static inline void __filemap_remove_folio_for_restructuring(struct folio *folio)
{
	struct address_space *mapping = folio->mapping;

	spin_lock(&mapping->host->i_lock);
	xa_lock_irq(&mapping->i_pages);

	__filemap_remove_folio(folio, NULL);

	xa_unlock_irq(&mapping->i_pages);
	spin_unlock(&mapping->host->i_lock);
}

/**
 * filemap_remove_folio_for_restructuring() - Remove @folio from filemap for
 * split/merge.
 *
 * @folio: the folio to be removed.
 *
 * Similar to filemap_remove_folio(), but skips LRU-related calls (meaningless
 * for guest_memfd), and skips call to ->free_folio() to maintain folio flags.
 *
 * Context: Expects only the filemap's refcounts to be left on the folio. Will
 *          freeze these refcounts away so that no other users will interfere
 *          with restructuring.
 */
static inline void filemap_remove_folio_for_restructuring(struct folio *folio)
{
	int filemap_refcount;

	filemap_refcount = folio_nr_pages(folio);
	while (!folio_ref_freeze(folio, filemap_refcount)) {
		/*
		 * At this point only filemap refcounts are expected, hence okay
		 * to spin until speculative refcounts go away.
		 */
		WARN_ONCE(1, "Spinning on folio=%p refcount=%d", folio, folio_ref_count(folio));
	}

	folio_lock(folio);
	__filemap_remove_folio_for_restructuring(folio);
	folio_unlock(folio);
}

/**
 * kvm_gmem_split_folio_in_filemap() - Split @folio within filemap in @inode.
 *
 * @inode: inode containing the folio.
 * @folio: folio to be split.
 *
 * Split a folio into folios of size PAGE_SIZE. Will clean up folio from filemap
 * and add back the split folios.
 *
 * Context: Expects that before this call, folio's refcount is just the
 *          filemap's refcounts. After this function returns, the split folios'
 *          refcounts will also be filemap's refcounts.
 * Return: 0 on success or negative error otherwise.
 */
static int kvm_gmem_split_folio_in_filemap(struct inode *inode, struct folio *folio)
{
	size_t orig_nr_pages;
	pgoff_t orig_index;
	size_t i, j;
	int ret;

	orig_nr_pages = folio_nr_pages(folio);
	if (orig_nr_pages == 1)
		return 0;

	orig_index = folio->index;

	filemap_remove_folio_for_restructuring(folio);

	ret = kvm_gmem_allocator_ops(inode)->split_folio(folio);
	if (ret)
		goto err;

	for (i = 0; i < orig_nr_pages; ++i) {
		struct folio *f = page_folio(folio_page(folio, i));

		ret = __kvm_gmem_filemap_add_folio(inode->i_mapping, f,
						   orig_index + i);
		if (ret)
			goto rollback;
	}

	return ret;

rollback:
	for (j = 0; j < i; ++j) {
		struct folio *f = page_folio(folio_page(folio, j));

		filemap_remove_folio_for_restructuring(f);
	}

	kvm_gmem_allocator_ops(inode)->merge_folio(folio);
err:
	WARN_ON(__kvm_gmem_filemap_add_folio(inode->i_mapping, folio, orig_index));

	return ret;
}

static inline bool kvm_gmem_should_split_at_index(struct inode *inode,
						  pgoff_t index)
{
	pgoff_t index_floor;
	size_t nr_pages;
	void *priv;

	priv = kvm_gmem_allocator_private(inode);
	nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);
	index_floor = round_down(index, nr_pages);

	return kvm_gmem_has_some_shared(inode, index_floor, nr_pages);
}

static inline int kvm_gmem_try_split_folio_in_filemap(struct inode *inode,
						      struct folio *folio)
{
	if (!kvm_gmem_has_custom_allocator(inode))
		return 0;

	if (kvm_gmem_should_split_at_index(inode, folio->index))
		return kvm_gmem_split_folio_in_filemap(inode, folio);

	return 0;
}

/**
 * kvm_gmem_merge_folio_in_filemap() - Merge @first_folio within filemap in
 * @inode.
 *
 * @inode: inode containing the folio.
 * @first_folio: first folio among folios to be merged.
 *
 * Will clean up subfolios from filemap and add back the merged folio.
 *
 * Context: Expects that before this call, all subfolios only have filemap
 *          refcounts. After this function returns, the merged folio will only
 *          have filemap refcounts.
 * Return: 0 on success or negative error otherwise.
 */
static int kvm_gmem_merge_folio_in_filemap(struct inode *inode,
					   struct folio *first_folio)
{
	size_t to_nr_pages;
	pgoff_t index;
	void *priv;
	size_t i;
	int ret;

	index = first_folio->index;

	priv = kvm_gmem_allocator_private(inode);
	to_nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);
	if (folio_nr_pages(first_folio) == to_nr_pages)
		return 0;

	for (i = 0; i < to_nr_pages; ++i) {
		struct folio *f = page_folio(folio_page(first_folio, i));

		filemap_remove_folio_for_restructuring(f);
	}

	kvm_gmem_allocator_ops(inode)->merge_folio(first_folio);

	ret = __kvm_gmem_filemap_add_folio(inode->i_mapping, first_folio, index);
	if (ret)
		goto err_split;

	return ret;

err_split:
	WARN_ON(kvm_gmem_allocator_ops(inode)->split_folio(first_folio));
	for (i = 0; i < to_nr_pages; ++i) {
		struct folio *f = page_folio(folio_page(first_folio, i));

		WARN_ON(__kvm_gmem_filemap_add_folio(inode->i_mapping, f, index + i));
	}

	return ret;
}

static inline int kvm_gmem_try_merge_folio_in_filemap(struct inode *inode,
						      struct folio *first_folio)
{
	size_t to_nr_pages;
	void *priv;

	priv = kvm_gmem_allocator_private(inode);
	to_nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);

	if (kvm_gmem_has_some_shared(inode, first_folio->index, to_nr_pages))
		return 0;

	return kvm_gmem_merge_folio_in_filemap(inode, first_folio);
}

static int kvm_gmem_restructure_folios_in_range(struct inode *inode,
						pgoff_t start, size_t nr_pages,
						bool is_split_operation)
{
	size_t to_nr_pages;
	pgoff_t index;
	pgoff_t end;
	void *priv;
	int ret;

	if (!kvm_gmem_has_custom_allocator(inode))
		return 0;

	end = start + nr_pages;

	/* Round to allocator page size, to check all (huge) pages in range. */
	priv = kvm_gmem_allocator_private(inode);
	to_nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);

	start = round_down(start, to_nr_pages);
	end = round_up(end, to_nr_pages);

	for (index = start; index < end; index += to_nr_pages) {
		struct folio *f;

		f = filemap_get_folio(inode->i_mapping, index);
		if (IS_ERR(f))
			continue;

		/* Leave just filemap's refcounts on the folio. */
		folio_put(f);

		if (is_split_operation)
			ret = kvm_gmem_split_folio_in_filemap(inode, f);
		else
			ret = kvm_gmem_try_merge_folio_in_filemap(inode, f);

		if (ret)
			goto rollback;
	}
	return ret;

rollback:
	for (index -= to_nr_pages; index >= start; index -= to_nr_pages) {
		struct folio *f;

		f = filemap_get_folio(inode->i_mapping, index);
		if (IS_ERR(f))
			continue;

		/* Leave just filemap's refcounts on the folio. */
		folio_put(f);

		if (is_split_operation)
			WARN_ON(kvm_gmem_merge_folio_in_filemap(inode, f));
		else
			WARN_ON(kvm_gmem_split_folio_in_filemap(inode, f));
	}

	return ret;
}

static long kvm_gmem_merge_truncate_indices(struct inode *inode, pgoff_t index,
					   size_t nr_pages)
{
	struct folio *f;
	pgoff_t unused;
	long num_freed;

	unmap_mapping_pages(inode->i_mapping, index, nr_pages, false);

	if (!kvm_gmem_has_safe_refcount(inode->i_mapping, index, nr_pages, &unused))
		return -EAGAIN;

	f = filemap_get_folio(inode->i_mapping, index);
	if (IS_ERR(f))
		return 0;

	/* Leave just filemap's refcounts on the folio. */
	folio_put(f);

	WARN_ON(kvm_gmem_merge_folio_in_filemap(inode, f));

	num_freed = folio_nr_pages(f);
	folio_lock(f);
	truncate_inode_folio(inode->i_mapping, f);
	folio_unlock(f);

	return num_freed;
}

#else

static inline bool kvm_gmem_should_split_at_index(struct inode *inode,
						  pgoff_t index)
{
	return false;
}

static inline int kvm_gmem_try_split_folio_in_filemap(struct inode *inode,
						      struct folio *folio)
{
	return 0;
}

static long kvm_gmem_merge_truncate_indices(struct inode *inode, pgoff_t index,
					   size_t nr_pages)
{
	return 0;
}

#endif

#else

static inline struct folio *kvm_gmem_get_shared_folio(struct inode *inode, pgoff_t index)
{
	WARN_ONCE(1, "Unexpected call to get shared folio.");
	return NULL;
}

static inline int kvm_gmem_try_split_folio_in_filemap(struct inode *inode,
						      struct folio *folio)
{
	return 0;
}

static inline bool kvm_gmem_should_split_at_index(struct inode *inode,
						  pgoff_t index)
{
	return false;
}

static inline bool kvm_gmem_has_some_shared(struct inode *inode, pgoff_t start,
					    size_t nr_pages)
{
	return false;
}

static long kvm_gmem_merge_truncate_indices(struct inode *inode, pgoff_t index,
					   size_t nr_pages)
{
	return 0;
}

#endif /* CONFIG_KVM_GMEM_SHARED_MEM */

static int __kvm_gmem_prepare_folio(struct kvm *kvm, struct kvm_memory_slot *slot,
				    pgoff_t index, struct folio *folio)
{
#ifdef CONFIG_HAVE_KVM_ARCH_GMEM_PREPARE
	kvm_pfn_t pfn = folio_file_pfn(folio, index);
	gfn_t gfn = slot->base_gfn + index - slot->gmem.pgoff;
	int rc = kvm_arch_gmem_prepare(kvm, gfn, pfn, folio_order(folio));
	if (rc) {
		pr_warn_ratelimited("gmem: Failed to prepare folio for index %lx GFN %llx PFN %llx error %d.\n",
				    index, gfn, pfn, rc);
		return rc;
	}
#endif

	return 0;
}

static inline void kvm_gmem_mark_prepared(struct folio *folio)
{
	folio_mark_uptodate(folio);
}

/*
 * Process @folio, which contains @gfn, so that the guest can use it.
 * The folio must be locked and the gfn must be contained in @slot.
 * On successful return the guest sees a zero page so as to avoid
 * leaking host data and the up-to-date flag is set.
 */
static int kvm_gmem_prepare_folio(struct kvm *kvm, struct kvm_memory_slot *slot,
				  gfn_t gfn, struct folio *folio,
				  unsigned long addr_hint)
{
	pgoff_t index;
	int r;

	folio_zero_user(folio, addr_hint);

	/*
	 * Preparing huge folios should always be safe, since it should
	 * be possible to split them later if needed.
	 *
	 * Right now the folio order is always going to be zero, but the
	 * code is ready for huge folios.  The only assumption is that
	 * the base pgoff of memslots is naturally aligned with the
	 * requested page order, ensuring that huge folios can also use
	 * huge page table entries for GPA->HPA mapping.
	 *
	 * The order will be passed when creating the guest_memfd, and
	 * checked when creating memslots.
	 */
	WARN_ON(!IS_ALIGNED(slot->gmem.pgoff, 1 << folio_order(folio)));
	index = gfn - slot->base_gfn + slot->gmem.pgoff;
	index = ALIGN_DOWN(index, 1 << folio_order(folio));
	r = __kvm_gmem_prepare_folio(kvm, slot, index, folio);
	if (!r)
		kvm_gmem_mark_prepared(folio);

	return r;
}

static int __kvm_gmem_filemap_add_folio(struct address_space *mapping,
					struct folio *folio, pgoff_t index)
{
	void *shadow = NULL;
	gfp_t gfp;
	int ret;

	gfp = mapping_gfp_mask(mapping);

	__folio_set_locked(folio);
	ret = __filemap_add_folio(mapping, folio, index, gfp, &shadow);
	__folio_clear_locked(folio);

	return ret;
}

/*
 * Adds a folio to the filemap for guest_memfd. Skips adding the folio to any
 * LRU list.
 */
static int kvm_gmem_filemap_add_folio(struct address_space *mapping,
					     struct folio *folio, pgoff_t index)
{
	int ret;

	ret = __kvm_gmem_filemap_add_folio(mapping, folio, index);
	if (!ret)
		folio_set_unevictable(folio);

	return ret;
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
	size_t allocated_size;
	struct folio *folio;
	pgoff_t index_floor;
	int ret;

repeat:
	folio = filemap_lock_folio(inode->i_mapping, index);
	if (!IS_ERR(folio))
		return folio;

	if (kvm_gmem_has_custom_allocator(inode)) {
		size_t nr_pages;
		void *p;

		p = kvm_gmem_allocator_private(inode);
		folio = kvm_gmem_allocator_ops(inode)->alloc_folio(p);
		if (IS_ERR(folio))
			return folio;

		nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(p);
		index_floor = round_down(index, nr_pages);
	} else {
		gfp_t gfp = mapping_gfp_mask(inode->i_mapping);

		folio = filemap_alloc_folio(gfp, 0);
		if (!folio)
			return ERR_PTR(-ENOMEM);

		ret = mem_cgroup_charge(folio, NULL, gfp);
		if (ret) {
			folio_put(folio);
			return ERR_PTR(ret);
		}

		index_floor = index;
	}
	allocated_size = folio_size(folio);

	ret = kvm_gmem_filemap_add_folio(inode->i_mapping, folio, index_floor);
	if (ret) {
		folio_put(folio);

		/*
		 * There was a race, two threads tried to get a folio indexing
		 * to the same location in the filemap. The losing thread should
		 * free the allocated folio, then lock the folio added to the
		 * filemap by the winning thread.
		 */
		if (ret == -EEXIST)
			goto repeat;

		return ERR_PTR(ret);
	}

	/* Leave just filemap's refcounts on folio. */
	folio_put(folio);

	ret = kvm_gmem_try_split_folio_in_filemap(inode, folio);
	if (ret)
		goto err;

	spin_lock(&inode->i_lock);
	inode->i_blocks += allocated_size / 512;
	spin_unlock(&inode->i_lock);

	/*
	 * folio is the one that is allocated, this gets the folio at the
	 * requested index.
	 */
	folio = filemap_lock_folio(inode->i_mapping, index);

	return folio;

err:
	filemap_remove_folio(folio);
	return ERR_PTR(ret);
}

static void kvm_gmem_invalidate_begin_and_zap(struct kvm_gmem *gmem,
					      pgoff_t start, pgoff_t end)
{
	bool flush = false, found_memslot = false;
	struct kvm_memory_slot *slot;
	struct kvm *kvm = gmem->kvm;
	unsigned long index;

	xa_for_each_range(&gmem->bindings, index, slot, start, end - 1) {
		enum kvm_gfn_range_filter filter;
		pgoff_t pgoff = slot->gmem.pgoff;

		filter = KVM_FILTER_PRIVATE;
		if (kvm_gmem_memslot_supports_shared(slot)) {
			/*
			 * Unmapping would also cause invalidation, but cannot
			 * rely on mmu_notifiers to do invalidation via
			 * unmapping, since memory may not be mapped to
			 * userspace.
			 */
			filter |= KVM_FILTER_SHARED;
		}

		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + max(pgoff, start) - pgoff,
			.end = slot->base_gfn + min(pgoff + slot->npages, end) - pgoff,
			.slot = slot,
			.may_block = true,
			.attr_filter = filter,
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

/**
 * kvm_gmem_truncate_indices() - Truncates all folios beginning @index for
 * @nr_pages.
 *
 * @mapping: filemap to truncate pages from.
 * @index: the index in the filemap to begin truncation.
 * @nr_pages: number of PAGE_SIZE pages to truncate.
 *
 * Return: the number of PAGE_SIZE pages that were actually truncated.
 */
static long kvm_gmem_truncate_indices(struct address_space *mapping,
				      pgoff_t index, size_t nr_pages)
{
	struct folio_batch fbatch;
	long truncated;
	pgoff_t last;

	last = index + nr_pages - 1;

	truncated = 0;
	folio_batch_init(&fbatch);
	while (filemap_get_folios(mapping, &index, last, &fbatch)) {
		unsigned int i;

		for (i = 0; i < folio_batch_count(&fbatch); ++i) {
			struct folio *f = fbatch.folios[i];

			truncated += folio_nr_pages(f);
			folio_lock(f);
			truncate_inode_folio(f->mapping, f);
			folio_unlock(f);
		}

		folio_batch_release(&fbatch);
		cond_resched();
	}

	return truncated;
}

/**
 * kvm_gmem_truncate_inode_aligned_pages() - Removes entire folios from filemap
 * in @inode.
 *
 * @inode: inode to remove folios from.
 * @index: start of range to be truncated. Must be hugepage aligned.
 * @nr_pages: number of PAGE_SIZE pages to be iterated over.
 *
 * Removes folios beginning @index for @nr_pages from filemap in @inode, updates
 * inode metadata.
 *
 * Return: 0 on success and negative error otherwise.
 */
static long kvm_gmem_truncate_inode_aligned_pages(struct inode *inode,
						  pgoff_t index,
						  size_t nr_pages)
{
	size_t nr_per_huge_page;
	long num_freed;
	pgoff_t idx;
	void *priv;
	long ret;

	priv = kvm_gmem_allocator_private(inode);
	nr_per_huge_page = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);

	ret = 0;
	num_freed = 0;
	for (idx = index; idx < index + nr_pages; idx += nr_per_huge_page) {
		if (mapping_exiting(inode->i_mapping) ||
		    !kvm_gmem_has_some_shared(inode, idx, nr_per_huge_page)) {
			num_freed += kvm_gmem_truncate_indices(
				inode->i_mapping, idx, nr_per_huge_page);
		} else {
			ret = kvm_gmem_merge_truncate_indices(inode, idx,
							      nr_per_huge_page);
			if (ret < 0)
				break;

			num_freed += ret;
			ret = 0;
		}
	}

	spin_lock(&inode->i_lock);
	inode->i_blocks -= (num_freed << PAGE_SHIFT) / 512;
	spin_unlock(&inode->i_lock);

	return ret;
}

/**
 * kvm_gmem_zero_range() - Zeroes all sub-pages in range [@start, @end).
 *
 * @mapping: the filemap to remove this range from.
 * @start: index in filemap for start of range (inclusive).
 * @end: index in filemap for end of range (exclusive).
 *
 * The pages in range may be split. truncate_inode_pages_range() isn't the right
 * function because it removes pages from the page cache; this function only
 * zeroes the pages.
 */
static void kvm_gmem_zero_range(struct address_space *mapping,
				pgoff_t start, pgoff_t end)
{
	struct folio_batch fbatch;

	folio_batch_init(&fbatch);
	while (filemap_get_folios(mapping, &start, end - 1, &fbatch)) {
		unsigned int i;

		for (i = 0; i < folio_batch_count(&fbatch); ++i) {
			struct folio *f;
			size_t nr_bytes;

			f = fbatch.folios[i];
			nr_bytes = offset_in_folio(f, end << PAGE_SHIFT);
			if (nr_bytes == 0)
				nr_bytes = folio_size(f);

			folio_zero_segment(f, 0, nr_bytes);
		}

		folio_batch_release(&fbatch);
		cond_resched();
	}
}

/**
 * kvm_gmem_truncate_inode_range() - Truncate pages in range [@lstart, @lend).
 *
 * @inode: inode to truncate from.
 * @lstart: offset in inode for start of range (inclusive).
 * @lend: offset in inode for end of range (exclusive).
 *
 * Removes full (huge)pages from the filemap and zeroing incomplete
 * (huge)pages. The pages in the range may be split.
 *
 * Return: 0 on success and negative error otherwise.
 */
static long kvm_gmem_truncate_inode_range(struct inode *inode, loff_t lstart,
					  loff_t lend)
{
	pgoff_t full_hpage_start;
	size_t nr_per_huge_page;
	pgoff_t full_hpage_end;
	size_t nr_pages;
	pgoff_t start;
	pgoff_t end;
	void *priv;
	long ret;

	priv = kvm_gmem_allocator_private(inode);
	nr_per_huge_page = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);

	start = lstart >> PAGE_SHIFT;
	end = min(lend, i_size_read(inode)) >> PAGE_SHIFT;

	full_hpage_start = round_up(start, nr_per_huge_page);
	full_hpage_end = round_down(end, nr_per_huge_page);

	if (start < full_hpage_start) {
		pgoff_t zero_end = min(full_hpage_start, end);

		kvm_gmem_zero_range(inode->i_mapping, start, zero_end);
	}

	ret = 0;
	if (full_hpage_end > full_hpage_start) {
		nr_pages = full_hpage_end - full_hpage_start;
		ret = kvm_gmem_truncate_inode_aligned_pages(
			inode, full_hpage_start, nr_pages);
	}

	if (end > full_hpage_end && end > full_hpage_start) {
		pgoff_t zero_start = max(full_hpage_end, start);

		kvm_gmem_zero_range(inode->i_mapping, zero_start, end);
	}

	return ret;
}

static long kvm_gmem_punch_hole(struct inode *inode, loff_t offset, loff_t len)
{
	struct list_head *gmem_list = &inode->i_mapping->i_private_list;
	pgoff_t start = offset >> PAGE_SHIFT;
	pgoff_t end = (offset + len) >> PAGE_SHIFT;
	struct kvm_gmem *gmem;
	long ret;

	/*
	 * Bindings must be stable across invalidation to ensure the start+end
	 * are balanced.
	 */
	filemap_invalidate_lock(inode->i_mapping);

	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_begin_and_zap(gmem, start, end);

	ret = 0;
	if (kvm_gmem_has_custom_allocator(inode)) {
		ret = kvm_gmem_truncate_inode_range(inode, offset, offset + len);
	} else {
		/* Page size is PAGE_SIZE, so use optimized truncation function. */
		truncate_inode_pages_range(inode->i_mapping, offset, offset + len - 1);
	}

	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_end(gmem, start, end);

	filemap_invalidate_unlock(inode->i_mapping);

	return ret;
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
	if (kvm_gmem_has_custom_allocator(inode)) {
		size_t nr_pages;
		void *p;

		p = kvm_gmem_allocator_private(inode);
		nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(p);

		start = round_down(start, nr_pages);
		end = round_down(end, nr_pages);
	}

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
	kvm_gmem_invalidate_begin_and_zap(gmem, 0, -1ul);
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

static pgoff_t kvm_gmem_get_index(const struct kvm_memory_slot *slot, gfn_t gfn)
{
	return gfn - slot->base_gfn + slot->gmem.pgoff;
}

#ifdef CONFIG_KVM_GMEM_SHARED_MEM

static bool kvm_gmem_supports_shared(struct inode *inode)
{
	uint64_t flags = (uint64_t)inode->i_private;

	return flags & GUEST_MEMFD_FLAG_SUPPORT_SHARED;
}

static vm_fault_t kvm_gmem_fault_shared(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct folio *folio;
	vm_fault_t ret = VM_FAULT_LOCKED;

	filemap_invalidate_lock_shared(inode->i_mapping);

	folio = kvm_gmem_get_shared_folio(inode, vmf->pgoff);
	if (IS_ERR(folio)) {
		int err = PTR_ERR(folio);

		if (err == -EAGAIN)
			ret = VM_FAULT_RETRY;
		else
			ret = vmf_error(err);

		goto out_filemap;
	}

	if (folio_test_hwpoison(folio)) {
		ret = VM_FAULT_HWPOISON;
		goto out_folio;
	}

	if (WARN_ON_ONCE(folio_test_large(folio))) {
		ret = VM_FAULT_SIGBUS;
		goto out_folio;
	}

	if (!folio_test_uptodate(folio)) {
		clear_highpage(folio_page(folio, 0));
		kvm_gmem_mark_prepared(folio);
	}

	vmf->page = folio_file_page(folio, vmf->pgoff);

out_folio:
	if (ret != VM_FAULT_LOCKED) {
		folio_unlock(folio);
		folio_put(folio);
	}

out_filemap:
	filemap_invalidate_unlock_shared(inode->i_mapping);

	return ret;
}

static const struct vm_operations_struct kvm_gmem_vm_ops = {
	.fault = kvm_gmem_fault_shared,
};

static int kvm_gmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	if (!kvm_gmem_supports_shared(file_inode(file)))
		return -ENODEV;

	if ((vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) !=
	    (VM_SHARED | VM_MAYSHARE)) {
		return -EINVAL;
	}

	vma->vm_ops = &kvm_gmem_vm_ops;

	return 0;
}

bool kvm_gmem_memslot_supports_shared(const struct kvm_memory_slot *slot)
{
	struct file *file;
	bool ret;

	file = kvm_gmem_get_file((struct kvm_memory_slot *)slot);
	if (!file)
		return false;

	ret = kvm_gmem_supports_shared(file_inode(file));

	fput(file);
	return ret;
}
EXPORT_SYMBOL_GPL(kvm_gmem_memslot_supports_shared);

/*
 * kvm_gmem_is_private() - Return true if this gfn is private to the guest.
 *
 * @slot: memslot where gfn belongs to.
 * @gfn: the gfn to query shareability for.
 *
 * Context: This function is racy, it reads shareability using a snapshot. The
 *          caller has to ensure that shareability being changed later will be
 *          handled.
 * Return: true if this gfn is private to the guest.
 */
bool kvm_gmem_is_private(struct kvm_memory_slot *slot, gfn_t gfn)
{
	struct inode *inode;
	struct file *file;
	pgoff_t index;
	bool ret;

	file = kvm_gmem_get_file(slot);
	if (!file)
		return false;

	index = kvm_gmem_get_index(slot, gfn);
	inode = file_inode(file);

	ret = kvm_gmem_shareability_get(inode, index) == SHAREABILITY_GUEST;

	fput(file);
	return ret;
}
EXPORT_SYMBOL_GPL(kvm_gmem_is_private);

#else

#define kvm_gmem_mmap NULL

static bool kvm_gmem_supports_shared(struct inode *inode)
{
	return false;
}

#endif /* CONFIG_KVM_GMEM_SHARED_MEM */

static long kvm_gmem_ioctl(struct file *file, unsigned int ioctl,
			   unsigned long arg)
{
	void __user *argp;
	int r;

	argp = (void __user *)arg;

	switch (ioctl) {
#ifdef CONFIG_KVM_GMEM_SHARED_MEM
	case KVM_GMEM_CONVERT_SHARED:
	case KVM_GMEM_CONVERT_PRIVATE: {
		struct kvm_gmem_convert param;
		bool to_shared;

		r = -EFAULT;
		if (copy_from_user(&param, argp, sizeof(param)))
			goto out;

		to_shared = ioctl == KVM_GMEM_CONVERT_SHARED;
		r = kvm_gmem_ioctl_convert_range(file, &param, to_shared);
		if (r) {
			if (copy_to_user(argp, &param, sizeof(param))) {
				r = -EFAULT;
				goto out;
			}
		}
		break;
	}
#endif
	default:
		r = -ENOTTY;
		goto out;
	}
out:
	return r;
}

static struct file_operations kvm_gmem_fops = {
	.mmap			= kvm_gmem_mmap,
	.open			= generic_file_open,
	.release		= kvm_gmem_release,
	.fallocate		= kvm_gmem_fallocate,
	.unlocked_ioctl 	= kvm_gmem_ioctl,
	.get_unmapped_area	= kvm_gmem_get_unmapped_area,
	.get_align_mask		= kvm_gmem_get_align_mask,
};

static void kvm_gmem_free_inode(struct inode *inode)
{
	struct kvm_gmem_inode_private *private = kvm_gmem_private(inode);

	/* private may be NULL if inode creation process had an error. */
	if (private && kvm_gmem_has_custom_allocator(inode)) {
		void *p = kvm_gmem_allocator_private(inode);

		kvm_gmem_allocator_ops(inode)->inode_teardown(p, inode->i_size);
	}

	kfree(private);

	free_inode_nonrcu(inode);
}

static void kvm_gmem_destroy_inode(struct inode *inode)
{
#ifdef CONFIG_KVM_GMEM_SHARED_MEM
	struct kvm_gmem_inode_private *private = kvm_gmem_private(inode);

	/*
	 * mtree_destroy() can't be used within rcu callback, hence can't be
	 * done in ->free_inode().
	 */
	if (private && kvm_gmem_supports_shared(inode))
		mtree_destroy(&private->shareability);
#endif
}

static void kvm_gmem_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final_prepare(inode->i_mapping);

	if (kvm_gmem_has_custom_allocator(inode)) {
		size_t nr_pages = inode->i_size >> PAGE_SHIFT;

		kvm_gmem_truncate_inode_aligned_pages(inode, 0, nr_pages);
	} else {
		truncate_inode_pages(inode->i_mapping, 0);
	}

	clear_inode(inode);
}

static const struct super_operations kvm_gmem_super_operations = {
	.statfs		= simple_statfs,
	.evict_inode	= kvm_gmem_evict_inode,
	.destroy_inode	= kvm_gmem_destroy_inode,
	.free_inode	= kvm_gmem_free_inode,
};

static int kvm_gmem_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx;

	if (!init_pseudo(fc, GUEST_MEMFD_MAGIC))
		return -ENOMEM;

	ctx = fc->fs_private;
	ctx->ops = &kvm_gmem_super_operations;

	return 0;
}

static struct file_system_type kvm_gmem_fs = {
	.name		 = "kvm_guest_memory",
	.init_fs_context = kvm_gmem_init_fs_context,
	.kill_sb	 = kill_anon_super,
};

static int kvm_gmem_init_mount(void)
{
	kvm_gmem_mnt = kern_mount(&kvm_gmem_fs);

	if (WARN_ON_ONCE(IS_ERR(kvm_gmem_mnt)))
		return PTR_ERR(kvm_gmem_mnt);

	kvm_gmem_mnt->mnt_flags |= MNT_NOEXEC;
	return 0;
}

int kvm_gmem_init(struct module *module)
{
	kvm_gmem_fops.owner = module;

	return kvm_gmem_init_mount();
}

void kvm_gmem_exit(void)
{
	kern_unmount(kvm_gmem_mnt);
	kvm_gmem_mnt = NULL;
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
		kvm_gmem_invalidate_begin_and_zap(gmem, start, end);

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
static void kvm_gmem_invalidate(struct folio *folio)
{
	kvm_pfn_t pfn = folio_pfn(folio);

	kvm_arch_gmem_invalidate(pfn, pfn + folio_nr_pages(folio));
}
#else
static inline void kvm_gmem_invalidate(struct folio *folio) {}
#endif

static void kvm_gmem_free_folio(struct address_space *mapping,
				struct folio *folio)
{
	folio_clear_unevictable(folio);

	/*
	 * No-op for 4K page since the PG_uptodate is cleared as part of
	 * freeing, but may be required for other allocators to reset page.
	 */
	folio_clear_uptodate(folio);

	if (kvm_gmem_has_custom_allocator(mapping->host))
		kvm_gmem_allocator_ops(mapping->host)->free_folio(folio);

	kvm_gmem_invalidate(folio);
}

static const struct address_space_operations kvm_gmem_aops = {
	.dirty_folio = noop_dirty_folio,
	.migrate_folio	= kvm_gmem_migrate_folio,
	.error_remove_folio = kvm_gmem_error_folio,
	.free_folio = kvm_gmem_free_folio,
};

static int kvm_gmem_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			    struct iattr *attr)
{
	return -EINVAL;
}
static const struct inode_operations kvm_gmem_iops = {
	.setattr	= kvm_gmem_setattr,
};

static struct inode *kvm_gmem_inode_make_secure_inode(const char *name,
						      loff_t size, u64 flags)
{
	struct kvm_gmem_inode_private *private;
	struct inode *inode;
	int err;

	inode = anon_inode_make_secure_inode(kvm_gmem_mnt->mnt_sb, name, NULL);
	if (IS_ERR(inode))
		return inode;

	err = -ENOMEM;
	private = kzalloc(sizeof(*private), GFP_KERNEL);
	if (!private)
		goto out;

	inode->i_mapping->i_private_data = private;

#ifdef CONFIG_KVM_GMEM_SHARED_MEM
	if (flags & GUEST_MEMFD_FLAG_SUPPORT_SHARED) {
		mt_init(&private->shareability);

		err = kvm_gmem_shareability_setup(private, size, flags);
		if (err)
			goto out;
	}
#endif

#ifdef CONFIG_KVM_GMEM_HUGETLB
	if (flags & GUEST_MEMFD_FLAG_HUGETLB) {
		void *allocator_priv;
		size_t nr_pages;

		allocator_priv = guestmem_hugetlb_ops.inode_setup(size, flags);
		if (IS_ERR(allocator_priv)) {
			err = PTR_ERR(allocator_priv);
			goto out;
		}

		private->allocator_ops = &guestmem_hugetlb_ops;
		private->allocator_private = allocator_priv;

		nr_pages = guestmem_hugetlb_ops.nr_pages_in_folio(allocator_priv);
		inode->i_blkbits = ilog2(nr_pages << PAGE_SHIFT);
	}
#endif

	inode->i_private = (void *)(unsigned long)flags;
	inode->i_op = &kvm_gmem_iops;
	inode->i_mapping->a_ops = &kvm_gmem_aops;
	inode->i_mode |= S_IFREG;
	inode->i_size = size;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_inaccessible(inode->i_mapping);
	/* Unmovable mappings are supposed to be marked unevictable as well. */
	WARN_ON_ONCE(!mapping_unevictable(inode->i_mapping));

	return inode;

out:
	iput(inode);

	return ERR_PTR(err);
}

static struct file *kvm_gmem_inode_create_getfile(void *priv, loff_t size,
						  u64 flags)
{
	static const char *name = "[kvm-gmem]";
	struct inode *inode;
	struct file *file;
	int err;

	err = -ENOENT;
	if (!try_module_get(kvm_gmem_fops.owner))
		goto err;

	inode = kvm_gmem_inode_make_secure_inode(name, size, flags);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto err_put_module;
	}

	file = alloc_file_pseudo(inode, kvm_gmem_mnt, name, O_RDWR,
				 &kvm_gmem_fops);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_put_inode;
	}

	file->f_flags |= O_LARGEFILE;
	file->private_data = priv;

out:
	return file;

err_put_inode:
	iput(inode);
err_put_module:
	module_put(kvm_gmem_fops.owner);
err:
	file = ERR_PTR(err);
	goto out;
}

static int __kvm_gmem_create(struct kvm *kvm, loff_t size, u64 flags)
{
	struct kvm_gmem *gmem;
	struct file *file;
	int fd, err;

	fd = get_unused_fd_flags(0);
	if (fd < 0)
		return fd;

	gmem = kzalloc(sizeof(*gmem), GFP_KERNEL);
	if (!gmem) {
		err = -ENOMEM;
		goto err_fd;
	}

	file = kvm_gmem_inode_create_getfile(gmem, size, flags);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_gmem;
	}

	kvm_get_kvm(kvm);
	gmem->kvm = kvm;
	xa_init(&gmem->bindings);
	list_add(&gmem->entry, &file_inode(file)->i_mapping->i_private_list);

	fd_install(fd, file);
	return fd;

err_gmem:
	kfree(gmem);
err_fd:
	put_unused_fd(fd);
	return err;
}

/* Mask of bits belonging to allocators and are opaque to guest_memfd. */
#define SUPPORTED_CUSTOM_ALLOCATOR_MASK \
	(GUESTMEM_HUGETLB_FLAG_MASK << GUESTMEM_HUGETLB_FLAG_SHIFT)

int kvm_gmem_create(struct kvm *kvm, struct kvm_create_guest_memfd *args)
{
	loff_t size = args->size;
	u64 flags = args->flags;
	u64 valid_flags = 0;

	if (IS_ENABLED(CONFIG_KVM_GMEM_SHARED_MEM))
		valid_flags |= GUEST_MEMFD_FLAG_SUPPORT_SHARED;

	if (flags & GUEST_MEMFD_FLAG_SUPPORT_SHARED)
		valid_flags |= GUEST_MEMFD_FLAG_INIT_PRIVATE;

	if (IS_ENABLED(CONFIG_KVM_GMEM_HUGETLB) &&
	    flags & GUEST_MEMFD_FLAG_HUGETLB) {
		valid_flags |= GUEST_MEMFD_FLAG_HUGETLB |
			       SUPPORTED_CUSTOM_ALLOCATOR_MASK;
	}

	if (flags & ~valid_flags)
		return -EINVAL;

	if (size <= 0 || !PAGE_ALIGNED(size))
		return -EINVAL;

	return __kvm_gmem_create(kvm, size, flags);
}

static bool kvm_gmem_is_same_range(struct kvm *kvm,
				   struct kvm_memory_slot *slot,
				   struct file *file, loff_t offset)
{
	struct mm_struct *mm = kvm->mm;
	loff_t userspace_addr_offset;
	struct vm_area_struct *vma;
	bool ret = false;

	mmap_read_lock(mm);

	vma = vma_lookup(mm, slot->userspace_addr);
	if (!vma)
		goto out;

	if (vma->vm_file != file)
		goto out;

	userspace_addr_offset = slot->userspace_addr - vma->vm_start;
	ret = userspace_addr_offset + (vma->vm_pgoff << PAGE_SHIFT) == offset;
out:
	mmap_read_unlock(mm);

	return ret;
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

	if (kvm_gmem_supports_shared(inode) && slot->userspace_addr &&
	    !kvm_gmem_is_same_range(kvm, slot, file, offset)) {
		goto err;
	}

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
					bool *is_prepared, int *max_order)
{
	struct file *gmem_file = READ_ONCE(slot->gmem.file);
	struct kvm_gmem *gmem = file->private_data;
	struct folio *folio;

	if (file != gmem_file) {
		WARN_ON_ONCE(gmem_file);
		return ERR_PTR(-EFAULT);
	}

	gmem = file->private_data;
	if (xa_load(&gmem->bindings, index) != slot) {
		WARN_ON_ONCE(xa_load(&gmem->bindings, index));
		return ERR_PTR(-EIO);
	}

	folio = kvm_gmem_get_folio(file_inode(file), index);
	if (IS_ERR(folio))
		return folio;

	if (folio_test_hwpoison(folio)) {
		folio_unlock(folio);
		folio_put(folio);
		return ERR_PTR(-EHWPOISON);
	}

	*pfn = folio_file_pfn(folio, index);
	if (max_order)
		*max_order = folio_order(folio);

	*is_prepared = folio_test_uptodate(folio);
	return folio;
}

int kvm_gmem_get_pfn(struct kvm *kvm, struct kvm_memory_slot *slot,
		     gfn_t gfn, kvm_pfn_t *pfn, struct page **page,
		     int *max_order)
{
	pgoff_t index = kvm_gmem_get_index(slot, gfn);
	struct file *file = kvm_gmem_get_file(slot);
	struct folio *folio;
	bool is_prepared = false;
	int r = 0;

	if (!file)
		return -EFAULT;

	filemap_invalidate_lock_shared(file_inode(file)->i_mapping);

	folio = __kvm_gmem_get_pfn(file, slot, index, pfn, &is_prepared, max_order);
	if (IS_ERR(folio)) {
		r = PTR_ERR(folio);
		goto out;
	}

	if (!is_prepared) {
		/*
		 * Use the same address as hugetlb for zeroing private pages
		 * that won't be mapped to userspace anyway.
		 */
		unsigned long addr_hint = folio->index << PAGE_SHIFT;

		r = kvm_gmem_prepare_folio(kvm, slot, gfn, folio, addr_hint);
	}

	folio_unlock(folio);

	if (!r)
		*page = folio_file_page(folio, index);
	else
		folio_put(folio);
out:
	filemap_invalidate_unlock_shared(file_inode(file)->i_mapping);
	fput(file);
	return r;
}
EXPORT_SYMBOL_GPL(kvm_gmem_get_pfn);

/**
 * kvm_gmem_mapping_order() - Get the mapping order for this @gfn in @slot.
 *
 * @slot: the memslot that gfn belongs to.
 * @gfn: the gfn to look up mapping order for.
 *
 * This is equal to max_order that would be returned if kvm_gmem_get_pfn() were
 * called now.
 *
 * Context: This function is racy, it reads shareability using a snapshot. The
 *          caller has to ensure that shareability being changed later will be
 *          handled.
 * Return: the mapping order for this @gfn in @slot.
 */
int kvm_gmem_mapping_order(const struct kvm_memory_slot *slot, gfn_t gfn)
{
	struct inode *inode;
	struct file *file;
	int ret;

	file = kvm_gmem_get_file((struct kvm_memory_slot *)slot);
	if (!file)
		return 0;

	inode = file_inode(file);

	ret = 0;
	if (kvm_gmem_has_custom_allocator(inode)) {
		bool should_split;
		pgoff_t index;

		index = kvm_gmem_get_index(slot, gfn);
		should_split = kvm_gmem_should_split_at_index(inode, index);
		if (!should_split) {
			size_t nr_pages;
			void *priv;

			priv = kvm_gmem_allocator_private(inode);
			nr_pages = kvm_gmem_allocator_ops(inode)->nr_pages_in_folio(priv);

			ret = ilog2(nr_pages);
		}
	}

	fput(file);
	return ret;
}
EXPORT_SYMBOL_GPL(kvm_gmem_mapping_order);

#ifdef CONFIG_KVM_GENERIC_GMEM_POPULATE

static bool kvm_range_is_all_private(struct kvm *kvm, gfn_t gfn, size_t nr_pages)
{
	size_t i;

	for (i = 0; i < nr_pages; ++i) {
		if (!kvm_mem_is_private(kvm, gfn + i))
			return false;
	}

	return true;
}

static size_t private_npages_to_populate(struct kvm *kvm, gfn_t gfn,
					 size_t npages_to_populate)
{
	int order;

	if (npages_to_populate == 1) {
		return kvm_mem_is_private(kvm, gfn) ? 1 : 0;
	}

	order = ilog2(npages_to_populate);
	while (!kvm_range_is_all_private(kvm, gfn, 1 << order)) {
		if (order == 0)
			return 0;

		order--;
	}


	return 1 << order;
}

long kvm_gmem_populate(struct kvm *kvm, gfn_t start_gfn, void __user *src, long npages,
		       kvm_gmem_populate_cb post_populate, void *opaque)
{
	struct file *file;
	struct kvm_memory_slot *slot;
	void __user *p;
	size_t npages_to_populate;

	int ret = 0, max_order;
	long i;

	lockdep_assert_held(&kvm->slots_lock);
	if (npages < 0)
		return -EINVAL;

	slot = gfn_to_memslot(kvm, start_gfn);
	if (!kvm_slot_has_gmem(slot))
		return -EINVAL;

	file = kvm_gmem_get_file(slot);
	if (!file)
		return -EFAULT;

	npages = min_t(ulong, slot->npages - (start_gfn - slot->base_gfn), npages);
	for (i = 0; i < npages; i += npages_to_populate) {
		struct folio *folio;
		gfn_t gfn = start_gfn + i;
		pgoff_t index = kvm_gmem_get_index(slot, gfn);
		bool is_prepared = false;
		kvm_pfn_t pfn;

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		filemap_invalidate_lock(file->f_mapping);
		folio = __kvm_gmem_get_pfn(file, slot, index, &pfn, &is_prepared, &max_order);
		filemap_invalidate_unlock(file->f_mapping);
		if (IS_ERR(folio)) {
			ret = PTR_ERR(folio);
			break;
		}

		if (kvm->arch.vm_type != KVM_X86_TDX_VM && is_prepared) {
			folio_unlock(folio);
			folio_put(folio);
			ret = -EEXIST;
			break;
		}

		folio_unlock(folio);
		WARN_ON(!IS_ALIGNED(gfn, 1 << max_order));

		npages_to_populate = min(npages - i, 1 << max_order);
		npages_to_populate = private_npages_to_populate(
			kvm, gfn, npages_to_populate);
		if (npages_to_populate == 0) {
			ret = -EINVAL;
			goto put_folio_and_exit;
		}

		p = src ? src + i * PAGE_SIZE : NULL;
		ret = post_populate(kvm, gfn, pfn, p, npages_to_populate, opaque);
		if (!ret)
			kvm_gmem_mark_prepared(folio);

put_folio_and_exit:
		folio_put(folio);
		if (ret)
			break;
	}


	fput(file);
	return ret && !i ? ret : i;
}
EXPORT_SYMBOL_GPL(kvm_gmem_populate);
#endif
