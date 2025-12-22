// SPDX-License-Identifier: GPL-2.0
#include <linux/anon_inodes.h>
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/kvm_host.h>
#include <linux/maple_tree.h>
#include <linux/mempolicy.h>
#include <linux/pseudo_fs.h>
#include <linux/pagemap.h>

#include "guest_memfd_hugetlb.h"
#include "kvm_mm.h"

static struct vfsmount *kvm_gmem_mnt;

/*
 * A guest_memfd instance can be associated multiple VMs, each with its own
 * "view" of the underlying physical memory.
 *
 * The gmem's inode is effectively the raw underlying physical storage, and is
 * used to track properties of the physical memory, while each gmem file is
 * effectively a single VM's view of that storage, and is used to track assets
 * specific to its associated VM, e.g. memslots=>gmem bindings.
 */
struct gmem_file {
	struct kvm *kvm;
	struct xarray bindings;
	struct list_head entry;
};

struct gmem_inode {
	struct shared_policy policy;
	struct inode vfs_inode;

	u64 flags;
	struct maple_tree attributes;

	/* The order of the allocated page (before restructuring, if any). */
	u8 page_order;
};

static __always_inline struct gmem_inode *GMEM_I(struct inode *inode)
{
	return container_of(inode, struct gmem_inode, vfs_inode);
}

#define kvm_gmem_for_each_file(f, mapping) \
	list_for_each_entry(f, &(mapping)->i_private_list, entry)

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

static pgoff_t kvm_gmem_get_index(struct kvm_memory_slot *slot, gfn_t gfn)
{
	return gfn - slot->base_gfn + slot->gmem.pgoff;
}

static u64 kvm_gmem_get_attributes(struct inode *inode, pgoff_t index)
{
	void *entry = mtree_load(&GMEM_I(inode)->attributes, index);

	return WARN_ON_ONCE(!entry) ? 0 : xa_to_value(entry);
}

static bool kvm_gmem_is_private_mem(struct inode *inode, pgoff_t index)
{
	return kvm_gmem_get_attributes(inode, index) & KVM_MEMORY_ATTRIBUTE_PRIVATE;
}

static bool kvm_gmem_is_shared_mem(struct inode *inode, pgoff_t index)
{
	return !kvm_gmem_is_private_mem(inode, index);
}

static bool kvm_gmem_range_has_attributes(struct maple_tree *mt,
					  pgoff_t index, size_t nr_pages,
					  u64 attributes)
{
	pgoff_t end = index + nr_pages - 1;
	void *entry;

	mt_for_each(mt, entry, index, end) {
		if (xa_to_value(entry) != attributes)
			return false;
	}

	return true;
}

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

/*
 * Process @folio, which contains @gfn, so that the guest can use it.
 * The folio must be locked and the gfn must be contained in @slot.
 * On successful return the guest sees a zero page so as to avoid
 * leaking host data and the up-to-date flag is set.
 */
static int kvm_gmem_prepare_folio(struct kvm *kvm, struct kvm_memory_slot *slot,
				  gfn_t gfn, struct folio *folio)
{
	pgoff_t index;

	index = kvm_gmem_get_index(slot, gfn);
	index = ALIGN_DOWN(index, folio_nr_pages(folio));
	return __kvm_gmem_prepare_folio(kvm, slot, index, folio);
}

static struct folio *__kvm_gmem_get_folio(struct inode *inode,
					  pgoff_t index,
					  struct mempolicy *policy)
{
	struct address_space *mapping = inode->i_mapping;
	const gfp_t gfp = mapping_gfp_mask(mapping);
	struct folio *folio;
	pgoff_t index_floor;
	int err;

	folio = filemap_lock_folio(mapping, index);
	if (!IS_ERR(folio))
		return folio;

	if (IS_ENABLED(CONFIG_KVM_GUEST_MEMFD_HUGETLB) &&
	    GMEM_I(inode)->flags & GUEST_MEMFD_FLAG_HUGETLB) {
		folio = gmem_hugetlb_alloc_folio(inode->i_private,
						 GMEM_I(inode)->page_order, policy);
		if (IS_ERR(folio))
			return folio;
	} else {
		folio = filemap_alloc_folio(gfp, 0, policy);
	}

	if (!folio)
		return ERR_PTR(-ENOMEM);

	err = mem_cgroup_charge(folio, NULL, gfp);
	if (err)
		goto err_put;

	__folio_set_locked(folio);

	index_floor = round_down(index, folio_nr_pages(folio));
	err = __filemap_add_folio(mapping, folio, index_floor, gfp, NULL);
	if (err) {
		__folio_clear_locked(folio);
		goto err_put;
	}

	return folio;

err_put:
	folio_put(folio);
	return ERR_PTR(err);
}

static struct folio *__maybe_split_fresh_folio(struct folio *folio,
					       pgoff_t requested_index)
{
	struct inode *inode = folio->mapping->host;
	struct gmem_inode *gi = GMEM_I(inode);
	size_t nr_pages = 1 << gi->page_order;
	int ret;

	if (!IS_ENABLED(CONFIG_KVM_GUEST_MEMFD_HUGETLB) || gi->page_order == 0)
		return folio;

	if (kvm_gmem_range_has_attributes(&gi->attributes, folio->index,
					  nr_pages,
					  KVM_MEMORY_ATTRIBUTE_PRIVATE))
		return folio;

	/* Set folio up for splitting, leave only filemap's refcounts on folio. */
	__folio_clear_locked(folio);
	folio_put(folio);

	ret = gmem_hugetlb_restructure_folio(inode->i_mapping, folio->index, 0);
	if (ret)
		return ERR_PTR(ret);

	folio = (struct folio *)folio_page(folio, requested_index - folio->index);
	__folio_set_locked(folio);
	folio_get(folio);

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
	struct address_space *mapping = inode->i_mapping;
	struct mempolicy *policy;
	struct folio *folio;

	/*
	 * Fast-path: See if folio is already present in mapping to avoid
	 * policy_lookup.
	 */
	folio = filemap_lock_folio(mapping, index);
	if (!IS_ERR(folio))
		return folio;

	policy = mpol_shared_policy_lookup(&GMEM_I(inode)->policy, index);
	do {
		folio = __kvm_gmem_get_folio(inode, index, policy);
	} while (IS_ERR(folio) && PTR_ERR(folio) == -EEXIST);

	mpol_cond_put(policy);

	if (IS_ERR(folio))
		return folio;

	inode_add_bytes(inode, folio_size(folio));

	return __maybe_split_fresh_folio(folio, index);
}

static enum kvm_gfn_range_filter kvm_gmem_get_invalidate_filter(struct inode *inode)
{
	/*
	 * TODO: Limit invalidations based on the to-be-invalidated range, i.e.
	 *       invalidate shared/private if and only if there can possibly be
	 *       such mappings.
	 */
	return KVM_FILTER_SHARED | KVM_FILTER_PRIVATE;
}

static void __kvm_gmem_zap(struct gmem_file *f, pgoff_t start, pgoff_t end,
			   enum kvm_gfn_range_filter attr_filter)
{
	bool flush = false, locked = false;
	struct kvm_memory_slot *slot;
	struct kvm *kvm = f->kvm;
	unsigned long index;

	xa_for_each_range(&f->bindings, index, slot, start, end - 1) {
		pgoff_t pgoff = slot->gmem.pgoff;

		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + max(pgoff, start) - pgoff,
			.end = slot->base_gfn + min(pgoff + slot->npages, end) - pgoff,
			.slot = slot,
			.may_block = true,
			.attr_filter = attr_filter,
		};

		if (!locked) {
			KVM_MMU_LOCK(kvm);
			locked = true;
		}

		flush |= kvm_unmap_gfn_range(kvm, &gfn_range);
	}

	if (flush)
		kvm_flush_remote_tlbs(kvm);

	if (locked)
		KVM_MMU_UNLOCK(kvm);
}

static void kvm_gmem_zap(struct inode *inode, pgoff_t start, pgoff_t end)
{
	enum kvm_gfn_range_filter attr_filter;
	struct gmem_file *f;

	attr_filter = kvm_gmem_get_invalidate_filter(inode);

	kvm_gmem_for_each_file(f, inode->i_mapping)
		__kvm_gmem_zap(f, start, end, attr_filter);
}

static void __kvm_gmem_invalidate_begin(struct gmem_file *f, pgoff_t start,
					pgoff_t end)
{
	struct kvm_memory_slot *slot;
	bool found_memslot = false;
	struct kvm *kvm = f->kvm;
	unsigned long index;

	xa_for_each_range(&f->bindings, index, slot, start, end - 1) {
		pgoff_t pgoff = slot->gmem.pgoff;
		pgoff_t range_start, range_end;

		range_start = slot->base_gfn + max(pgoff, start) - pgoff;
		range_end = slot->base_gfn + min(pgoff + slot->npages, end) - pgoff;

		if (!found_memslot) {
			KVM_MMU_LOCK(kvm);
			found_memslot = true;

			kvm_mmu_invalidate_begin(kvm);
		}

		kvm_mmu_invalidate_range_add(kvm, range_start, range_end);
	}

	if (found_memslot)
		KVM_MMU_UNLOCK(kvm);
}

static void kvm_gmem_invalidate_begin(struct inode *inode, pgoff_t start,
				      pgoff_t end)
{
	struct gmem_file *f;

	kvm_gmem_for_each_file(f, inode->i_mapping)
		__kvm_gmem_invalidate_begin(f, start, end);
}

static void __kvm_gmem_invalidate_end(struct gmem_file *f, pgoff_t start,
				      pgoff_t end)
{
	struct kvm *kvm = f->kvm;

	if (xa_find(&f->bindings, &start, end - 1, XA_PRESENT)) {
		KVM_MMU_LOCK(kvm);
		kvm_mmu_invalidate_end(kvm);
		KVM_MMU_UNLOCK(kvm);
	}
}

static void kvm_gmem_invalidate_end(struct inode *inode, pgoff_t start,
				    pgoff_t end)
{
	struct gmem_file *f;

	kvm_gmem_for_each_file(f, inode->i_mapping)
		__kvm_gmem_invalidate_end(f, start, end);
}

static bool kvm_gmem_has_safe_refcount(struct inode *inode, pgoff_t start,
				       size_t nr_pages, pgoff_t *err_index)
{
	struct address_space *mapping = inode->i_mapping;
	const int filemap_get_folios_refcount = 1;
	pgoff_t last = start + nr_pages - 1;
	struct folio_batch fbatch;
	bool safe = true;
	int i;

	folio_batch_init(&fbatch);
	while (safe && filemap_get_folios(mapping, &start, last, &fbatch)) {

		for (i = 0; i < folio_batch_count(&fbatch); ++i) {
			struct folio *folio = fbatch.folios[i];

			if (folio_ref_count(folio) !=
			    folio_nr_pages(folio) + filemap_get_folios_refcount) {
				safe = false;

				if (err_index)
					*err_index = folio->index;

				break;
			}
		}

		folio_batch_release(&fbatch);
	}

	return safe;
}

static size_t kvm_gmem_truncate_folio(struct folio *folio)
{
	size_t nr_bytes;

	folio_lock(folio);

	nr_bytes = folio_size(folio);

	if (folio_mapped(folio))
		unmap_mapping_folio(folio);

	folio_cancel_dirty(folio);
	filemap_remove_folio(folio);

	folio_unlock(folio);

	return nr_bytes;
}

static void kvm_gmem_truncate_range(struct inode *inode, pgoff_t start,
				    size_t nr_pages)
{
	struct folio_batch fbatch;
	long nr_bytes = 0;
	pgoff_t next;
	pgoff_t last;
	int i;

	last = start + nr_pages - 1;

	folio_batch_init(&fbatch);
	next = start;
	while (filemap_get_folios(inode->i_mapping, &next, last, &fbatch)) {
		for (i = 0; i < folio_batch_count(&fbatch); ++i)
			nr_bytes += kvm_gmem_truncate_folio(fbatch.folios[i]);

		folio_batch_release(&fbatch);
		cond_resched();
	}

	inode_sub_bytes(inode, nr_bytes);
}

static int merge_folios_in_range(struct inode *inode, pgoff_t start,
				 size_t nr_pages)
{
	u8 merge_order = GMEM_I(inode)->page_order;
	size_t merge_nr_pages = 1 << merge_order;
	pgoff_t index;
	int ret = 0;

	for (index = start; index < start + nr_pages; index += merge_nr_pages) {
		ret = gmem_hugetlb_restructure_folio(inode->i_mapping, index,
						     merge_order);
		if (ret)
			return ret;
	}

	return ret;
}

/* Assumes that start and nr_pages are aligned to gi->page_order. */
static int merge_truncate_range(struct inode *inode, pgoff_t start,
				size_t nr_pages, bool require_merge)
{
	int ret;

	if (!(GMEM_I(inode)->flags & GUEST_MEMFD_FLAG_HUGETLB)) {
		kvm_gmem_truncate_range(inode, start, nr_pages);
		return 0;
	}

	unmap_mapping_pages(inode->i_mapping, start, nr_pages, false);

	ret = 0;
	if (kvm_gmem_has_safe_refcount(inode, start, nr_pages, NULL)) {
		ret = merge_folios_in_range(inode, start, nr_pages);
		if (ret) {
			if (require_merge)
				return ret;
			else
				ret = 0;
		}
	} else if (require_merge) {
		return -EAGAIN;
	}

	kvm_gmem_truncate_range(inode, start, nr_pages);

	return ret;
}

static int __kvm_gmem_split_private(struct gmem_file *f, pgoff_t start, pgoff_t end)
{
	enum kvm_gfn_range_filter attr_filter = KVM_FILTER_PRIVATE;

	bool locked = false;
	struct kvm_memory_slot *slot;
	struct kvm *kvm = f->kvm;
	unsigned long index;
	int ret = 0;

	xa_for_each_range(&f->bindings, index, slot, start, end - 1) {
		pgoff_t pgoff = slot->gmem.pgoff;
		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + max(pgoff, start) - pgoff,
			.end = slot->base_gfn + min(pgoff + slot->npages, end) - pgoff,
			.slot = slot,
			.may_block = true,
			.attr_filter = attr_filter,
		};

		if (!locked) {
			KVM_MMU_LOCK(kvm);
			locked = true;
		}

		ret = kvm_split_cross_boundary_leafs(kvm, &gfn_range, false);
		if (ret)
			break;
	}

	if (locked)
		KVM_MMU_UNLOCK(kvm);

	return ret;
}

static int kvm_gmem_split_private(struct inode *inode, pgoff_t start, pgoff_t end)
{
	struct gmem_file *f;
	int r = 0;

	kvm_gmem_for_each_file(f, inode->i_mapping) {
		r = __kvm_gmem_split_private(f, start, end);
		if (r)
			break;
	}
	return r;
}

static long kvm_gmem_punch_hole(struct inode *inode, loff_t offset, loff_t len)
{
	pgoff_t start = offset >> PAGE_SHIFT;
	pgoff_t end = (offset + len) >> PAGE_SHIFT;
	long ret;

	/*
	 * Bindings must be stable across invalidation to ensure the start+end
	 * are balanced.
	 */
	filemap_invalidate_lock(inode->i_mapping);

	kvm_gmem_invalidate_begin(inode, start, end);

	ret = kvm_gmem_split_private(inode, start, end);
	if (ret) {
		kvm_gmem_invalidate_end(inode, start, end);
		filemap_invalidate_unlock(inode->i_mapping);
		return ret;
	}
	kvm_gmem_zap(inode, start, end);

	ret = merge_truncate_range(inode, start, len >> PAGE_SHIFT, true);

	kvm_gmem_invalidate_end(inode, start, end);

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
	size_t page_size;
	int ret;

	if (!(mode & FALLOC_FL_KEEP_SIZE))
		return -EOPNOTSUPP;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	page_size = PAGE_SIZE << GMEM_I(file_inode(file))->page_order;
	if (!IS_ALIGNED(offset, page_size) || !IS_ALIGNED(len, page_size))
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
	struct gmem_file *f = file->private_data;
	struct kvm_memory_slot *slot;
	struct kvm *kvm = f->kvm;
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

	xa_for_each(&f->bindings, index, slot)
		WRITE_ONCE(slot->gmem.file, NULL);

	/*
	 * All in-flight operations are gone and new bindings can be created.
	 * Zap all SPTEs pointed at by this file.  Do not free the backing
	 * memory, as its lifetime is associated with the inode, not the file.
	 */
	__kvm_gmem_invalidate_begin(f, 0, -1ul);
	__kvm_gmem_zap(f, 0, -1ul, kvm_gmem_get_invalidate_filter(inode));
	__kvm_gmem_invalidate_end(f, 0, -1ul);

	list_del(&f->entry);

	filemap_invalidate_unlock(inode->i_mapping);

	mutex_unlock(&kvm->slots_lock);

	xa_destroy(&f->bindings);
	kfree(f);

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

DEFINE_CLASS(gmem_get_file, struct file *, if (_T) fput(_T),
	     kvm_gmem_get_file(slot), struct kvm_memory_slot *slot);

static bool kvm_gmem_supports_mmap(struct inode *inode)
{
	return GMEM_I(inode)->flags & GUEST_MEMFD_FLAG_MMAP;
}

static vm_fault_t kvm_gmem_fault_user_mapping(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct folio *folio;
	vm_fault_t ret = VM_FAULT_LOCKED;

	if (((loff_t)vmf->pgoff << PAGE_SHIFT) >= i_size_read(inode))
		return VM_FAULT_SIGBUS;

	filemap_invalidate_lock_shared(inode->i_mapping);
	if (kvm_gmem_is_shared_mem(inode, vmf->pgoff))
		folio = kvm_gmem_get_folio(inode, vmf->pgoff);
	else
		folio = ERR_PTR(-EACCES);
	filemap_invalidate_unlock_shared(inode->i_mapping);

	if (IS_ERR(folio)) {
		if (PTR_ERR(folio) == -EAGAIN)
			return VM_FAULT_RETRY;

		return vmf_error(PTR_ERR(folio));
	}

	if (WARN_ON_ONCE(folio_test_large(folio))) {
		ret = VM_FAULT_SIGBUS;
		goto out_folio;
	}

	if (!folio_test_uptodate(folio)) {
		clear_highpage(folio_page(folio, 0));
		folio_mark_uptodate(folio);
	}

	vmf->page = folio_file_page(folio, vmf->pgoff);

out_folio:
	if (ret != VM_FAULT_LOCKED) {
		folio_unlock(folio);
		folio_put(folio);
	}

	return ret;
}

#ifdef CONFIG_NUMA
static int kvm_gmem_set_policy(struct vm_area_struct *vma, struct mempolicy *mpol)
{
	struct inode *inode = file_inode(vma->vm_file);

	return mpol_set_shared_policy(&GMEM_I(inode)->policy, vma, mpol);
}

static struct mempolicy *kvm_gmem_get_policy(struct vm_area_struct *vma,
					     unsigned long addr, pgoff_t *pgoff)
{
	struct inode *inode = file_inode(vma->vm_file);

	*pgoff = vma->vm_pgoff + ((addr - vma->vm_start) >> PAGE_SHIFT);

	/*
	 * Return the memory policy for this index, or NULL if none is set.
	 *
	 * Returning NULL, e.g. instead of the current task's memory policy, is
	 * important for the .get_policy kernel ABI: it indicates that no
	 * explicit policy has been set via mbind() for this memory. The caller
	 * can then replace NULL with the default memory policy instead of the
	 * current task's memory policy.
	 */
	return mpol_shared_policy_lookup(&GMEM_I(inode)->policy, *pgoff);
}
#endif /* CONFIG_NUMA */

static const struct vm_operations_struct kvm_gmem_vm_ops = {
	.fault		= kvm_gmem_fault_user_mapping,
#ifdef CONFIG_NUMA
	.get_policy	= kvm_gmem_get_policy,
	.set_policy	= kvm_gmem_set_policy,
#endif
};

static int kvm_gmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	if (!kvm_gmem_supports_mmap(file_inode(file)))
		return -ENODEV;

	if ((vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) !=
	    (VM_SHARED | VM_MAYSHARE)) {
		return -EINVAL;
	}

	vma->vm_ops = &kvm_gmem_vm_ops;

	return 0;
}

unsigned long kvm_gmem_get_memory_attributes(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	/*
	 * If this gfn has no associated memslot, there's no chance of the gfn
	 * being backed by private memory, since guest_memfd must be used for
	 * private memory, and guest_memfd must be associated with some memslot.
	 */
	if (!slot)
		return 0;

	CLASS(gmem_get_file, file)(slot);
	if (!file)
		return false;

	/*
	 * Don't take the filemap invalidation lock, as temporarily acquiring
	 * that lock wouldn't provide any meaningful protection.  The caller
	 * _must_ protect consumption of private vs. shared by checking
	 * mmu_invalidate_retry_gfn() under mmu_lock.
	 */
	guard(rcu)();

	return kvm_gmem_get_attributes(file_inode(file),
				       kvm_gmem_get_index(slot, gfn));
}
EXPORT_SYMBOL_GPL(kvm_gmem_get_memory_attributes);

/*
 * Preallocate memory for attributes to be stored on a maple tree, pointed to
 * by mas.  Adjacent ranges with attributes identical to the new attributes
 * will be merged.  Also sets mas's bounds up for storing attributes.
 *
 * This maintains the invariant that ranges with the same attributes will
 * always be merged.
 */
static int kvm_gmem_mas_preallocate(struct ma_state *mas, u64 attributes,
				    pgoff_t start, size_t nr_pages)
{
	pgoff_t end = start + nr_pages;
	pgoff_t last = end - 1;
	void *entry;

	/* Try extending range. entry is NULL on overflow/wrap-around. */
	mas_set_range(mas, end, end);
	entry = mas_find(mas, end);
	if (entry && xa_to_value(entry) == attributes)
		last = mas->last;

	if (start > 0) {
		mas_set_range(mas, start - 1, start - 1);
		entry = mas_find(mas, start - 1);
		if (entry && xa_to_value(entry) == attributes)
			start = mas->index;
	}

	mas_set_range(mas, start, last);
	return mas_preallocate(mas, xa_mk_value(attributes), GFP_KERNEL);
}

static int kvm_gmem_restructure(struct inode *inode, pgoff_t start,
				size_t nr_pages, bool to_private,
				pgoff_t *err_index)
{
	struct gmem_inode *gi = GMEM_I(inode);
	pgoff_t aligned_start, aligned_end;
	pgoff_t end = start + nr_pages;
	u8 to_order;
	int ret;

	if (!IS_ENABLED(CONFIG_KVM_GUEST_MEMFD_HUGETLB) || gi->page_order == 0)
		return 0;

	aligned_start = round_down(start, 1 << gi->page_order);
	aligned_end = aligned_start + (1 << gi->page_order);
	to_order = 0;
	if (to_private) {
		bool all_rest_private = true;

		if (start > aligned_start &&
		    !kvm_gmem_range_has_attributes(&gi->attributes, aligned_start,
						   start - aligned_start,
						   KVM_MEMORY_ATTRIBUTE_PRIVATE))
			all_rest_private = false;

		if (all_rest_private && end < aligned_end &&
		    !kvm_gmem_range_has_attributes(&gi->attributes, end,
						   aligned_end - end,
						   KVM_MEMORY_ATTRIBUTE_PRIVATE))
			all_rest_private = false;

		if (all_rest_private)
			to_order = gi->page_order;
	}

	ret = gmem_hugetlb_restructure_folio(inode->i_mapping, aligned_start, to_order);
	if (ret)
		*err_index = start;

	return ret;
}

static pgoff_t kvm_gmem_compute_invalidate_start(struct inode *inode,
						 pgoff_t index)
{
	struct gmem_inode *gi = GMEM_I(inode);

	if (!IS_ENABLED(CONFIG_KVM_GUEST_MEMFD_HUGETLB) || gi->page_order == 0)
		return index;

	return round_down(index, 1 << gi->page_order);
}

static pgoff_t kvm_gmem_compute_invalidate_end(struct inode *inode,
					       pgoff_t index)
{
	struct gmem_inode *gi = GMEM_I(inode);

	if (!IS_ENABLED(CONFIG_KVM_GUEST_MEMFD_HUGETLB) || gi->page_order == 0)
		return index;

	return round_up(index, 1 << gi->page_order);
}

static int kvm_gmem_convert(struct inode *inode, pgoff_t start,
			    size_t nr_pages, uint64_t attrs,
			    pgoff_t *err_index)
{
	bool to_private = attrs & KVM_MEMORY_ATTRIBUTE_PRIVATE;
	struct address_space *mapping = inode->i_mapping;
	struct gmem_inode *gi = GMEM_I(inode);
	pgoff_t end = start + nr_pages;
	pgoff_t invalidate_start;
	pgoff_t invalidate_end;
	struct maple_tree *mt;
	struct ma_state mas;
	int r;

	mt = &gi->attributes;

	mas_init(&mas, mt, start);

	r = kvm_gmem_mas_preallocate(&mas, attrs, start, nr_pages);
	if (r) {
		*err_index = start;
		return r;
	}

	if (to_private) {
		unmap_mapping_pages(mapping, start, nr_pages, false);

		if (!kvm_gmem_has_safe_refcount(inode, start, nr_pages, err_index)) {
			mas_destroy(&mas);
			return -EAGAIN;
		}
	}

	invalidate_start = kvm_gmem_compute_invalidate_start(inode, start);
	invalidate_end = kvm_gmem_compute_invalidate_end(inode, end);
	kvm_gmem_invalidate_begin(inode, invalidate_start, invalidate_end);

	if (!to_private) {
		r = kvm_gmem_split_private(inode, start, end);
		if (r) {
			*err_index = start;
			mas_destroy(&mas);
			kvm_gmem_invalidate_end(inode, invalidate_start, invalidate_end);
			return r;
		}
	}

	kvm_gmem_zap(inode, start, end);
	kvm_gmem_invalidate_end(inode, invalidate_start, invalidate_end);

	r = kvm_gmem_restructure(inode, start, nr_pages, to_private, err_index);
	if (r) {
		mas_destroy(&mas);
		return r;
	}

	mas_store_prealloc(&mas, xa_mk_value(attrs));
	return 0;
}

static int __kvm_gmem_set_attributes(struct inode *inode, pgoff_t start,
				     size_t nr_pages, uint64_t attrs,
				     pgoff_t *err_index)
{
	struct address_space *mapping = inode->i_mapping;
	struct gmem_inode *gi = GMEM_I(inode);
	pgoff_t end = start + nr_pages;
	pgoff_t batch_start, batch_end;
	size_t batch_nr_pages;
	struct maple_tree *mt;
	size_t batch_size;
	int r = 0;

	mt = &gi->attributes;

	filemap_invalidate_lock(mapping);

	if (kvm_gmem_range_has_attributes(mt, start, nr_pages, attrs))
		goto done;

	/* For page_order > 0, convert one huge page at a time. */
	if (gi->page_order > 0)
		batch_size = 1 << gi->page_order;
	else
		batch_size = inode->i_size >> PAGE_SHIFT;

	for (batch_start = start; batch_start < end; batch_start += batch_nr_pages) {
		batch_end = min(round_up(batch_start + 1, batch_size), end);
		batch_nr_pages = batch_end - batch_start;

		r = kvm_gmem_convert(inode, batch_start, batch_nr_pages, attrs,
				     err_index);
		if (r)
			break;
	}
done:
	filemap_invalidate_unlock(mapping);
	return r;
}

static long kvm_gmem_set_attributes(struct file *file, void __user *argp)
{
	struct gmem_file *f = file->private_data;
	struct inode *inode = file_inode(file);
	struct kvm_memory_attributes2 attrs;
	pgoff_t err_index;
	size_t nr_pages;
	pgoff_t index;
	int r;

	if (copy_from_user(&attrs, argp, sizeof(attrs)))
		return -EFAULT;

	if (attrs.flags)
		return -EINVAL;
	if (attrs.attributes & ~kvm_supported_mem_attributes(f->kvm))
		return -EINVAL;
	if (attrs.size == 0 || attrs.offset + attrs.size < attrs.offset)
		return -EINVAL;
	if (!PAGE_ALIGNED(attrs.offset) || !PAGE_ALIGNED(attrs.size))
		return -EINVAL;

	if (attrs.offset >= inode->i_size ||
	    attrs.offset + attrs.size > inode->i_size)
		return -EINVAL;

	nr_pages = attrs.size >> PAGE_SHIFT;
	index = attrs.offset >> PAGE_SHIFT;
	r = __kvm_gmem_set_attributes(inode, index, nr_pages, attrs.attributes,
				      &err_index);
	if (r) {
		attrs.error_offset = err_index << PAGE_SHIFT;

		if (copy_to_user(argp, &attrs, sizeof(attrs)))
			return -EFAULT;
	}

	return r;
}

static long kvm_gmem_ioctl(struct file *file, unsigned int ioctl,
			   unsigned long arg)
{
	switch (ioctl) {
	case KVM_SET_MEMORY_ATTRIBUTES2:
		if (vm_memory_attributes)
			return -ENOTTY;

		return kvm_gmem_set_attributes(file, (void __user *)arg);
	default:
		return -ENOTTY;
	}
}

static struct file_operations kvm_gmem_fops = {
	.mmap		= kvm_gmem_mmap,
	.open		= generic_file_open,
	.release	= kvm_gmem_release,
	.fallocate	= kvm_gmem_fallocate,
	.unlocked_ioctl	= kvm_gmem_ioctl,
};

static int kvm_gmem_migrate_folio(struct address_space *mapping,
				  struct folio *dst, struct folio *src,
				  enum migrate_mode mode)
{
	WARN_ON_ONCE(1);
	return -EINVAL;
}

static int kvm_gmem_error_folio(struct address_space *mapping, struct folio *folio)
{
	pgoff_t start, end;

	filemap_invalidate_lock_shared(mapping);

	start = folio->index;
	end = start + folio_nr_pages(folio);

	kvm_gmem_invalidate_begin(mapping->host, start, end);
	kvm_gmem_zap(mapping->host, start, end);

	/*
	 * Do not truncate the range, what action is taken in response to the
	 * error is userspace's decision (assuming the architecture supports
	 * gracefully handling memory errors).  If/when the guest attempts to
	 * access a poisoned page, kvm_gmem_get_pfn() will return -EHWPOISON,
	 * at which point KVM can either terminate the VM or propagate the
	 * error to userspace.
	 */

	kvm_gmem_invalidate_end(mapping->host, start, end);

	filemap_invalidate_unlock_shared(mapping);

	return MF_DELAYED;
}

static void kvm_gmem_free_folio(struct folio *folio)
{
	folio_clear_unevictable(folio);

	/*
	 * Clear PG_uptodate for HugeTLB folios to reset page. For
	 * native-page-size pages, PG_uptodate remains safely cleared as part of
	 * regular freeing processes.
	 */
	folio_clear_uptodate(folio);

#ifdef CONFIG_HAVE_KVM_ARCH_GMEM_INVALIDATE
	kvm_arch_gmem_invalidate(folio_pfn(folio),
				 folio_pfn(folio) + folio_nr_pages(folio));
#endif
}

static const struct address_space_operations kvm_gmem_aops = {
	.dirty_folio = noop_dirty_folio,
	.migrate_folio = kvm_gmem_migrate_folio,
	.error_remove_folio = kvm_gmem_error_folio,
	.free_folio = kvm_gmem_free_folio,
};

static void kvm_gmem_hugetlb_free_folio(struct folio *folio)
{
	kvm_gmem_free_folio(folio);
	gmem_hugetlb_free_folio(folio);
}

static const struct address_space_operations kvm_gmem_hugetlb_aops = {
	.dirty_folio = noop_dirty_folio,
	.migrate_folio = kvm_gmem_migrate_folio,
	.error_remove_folio = kvm_gmem_error_folio,
	.free_folio = kvm_gmem_hugetlb_free_folio,
};

static int kvm_gmem_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			    struct iattr *attr)
{
	return -EINVAL;
}
static const struct inode_operations kvm_gmem_iops = {
	.setattr	= kvm_gmem_setattr,
};

bool __weak kvm_arch_supports_gmem_init_shared(struct kvm *kvm)
{
	return true;
}

static int kvm_gmem_init_inode(struct inode *inode, loff_t size, u64 flags,
			       u8 page_order)
{
	struct gmem_inode *gi = GMEM_I(inode);
	MA_STATE(mas, &gi->attributes, 0, (size >> PAGE_SHIFT) - 1);
	u64 attrs;
	int r;

	r = gmem_hugetlb_init(inode, flags, size, page_order);
	if (r)
		return r;

	inode->i_op = &kvm_gmem_iops;
	inode->i_mapping->a_ops = flags & GUEST_MEMFD_FLAG_HUGETLB ?
					  &kvm_gmem_hugetlb_aops :
					  &kvm_gmem_aops;
	inode->i_mode |= S_IFREG;
	inode->i_size = size;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_inaccessible(inode->i_mapping);
	/* Unmovable mappings are supposed to be marked unevictable as well. */
	WARN_ON_ONCE(!mapping_unevictable(inode->i_mapping));

	gi->flags = flags;
	gi->page_order = page_order;

	mt_set_external_lock(&gi->attributes,
			     &inode->i_mapping->invalidate_lock);

	/*
	 * Store default attributes for the entire gmem instance. Ensuring every
	 * index is represented in the maple tree at all times simplifies the
	 * conversion and merging logic.
	 */
	attrs = gi->flags & GUEST_MEMFD_FLAG_INIT_SHARED ? 0 : KVM_MEMORY_ATTRIBUTE_PRIVATE;

	/*
	 * Acquire the invalidation lock purely to make lockdep happy. There
	 * should be no races at this time since the inode hasn't yet been fully
	 * created.
	 */
	filemap_invalidate_lock(inode->i_mapping);
	r = mas_store_gfp(&mas, xa_mk_value(attrs), GFP_KERNEL);
	filemap_invalidate_unlock(inode->i_mapping);

	return r;
}

static int __kvm_gmem_create(struct kvm *kvm, loff_t size, u64 flags, u8 page_order)
{
	static const char *name = "[kvm-gmem]";
	struct gmem_file *f;
	struct inode *inode;
	struct file *file;
	int fd, err;

	fd = get_unused_fd_flags(0);
	if (fd < 0)
		return fd;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f) {
		err = -ENOMEM;
		goto err_fd;
	}

	/* __fput() will take care of fops_put(). */
	if (!fops_get(&kvm_gmem_fops)) {
		err = -ENOENT;
		goto err_gmem;
	}

	inode = anon_inode_make_secure_inode(kvm_gmem_mnt->mnt_sb, name, NULL);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto err_fops;
	}

	err = kvm_gmem_init_inode(inode, size, flags, page_order);
	if (err)
		goto err_inode;

	file = alloc_file_pseudo(inode, kvm_gmem_mnt, name, O_RDWR, &kvm_gmem_fops);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_inode;
	}

	file->f_flags |= O_LARGEFILE;
	file->private_data = f;

	kvm_get_kvm(kvm);
	f->kvm = kvm;
	xa_init(&f->bindings);
	list_add(&f->entry, &inode->i_mapping->i_private_list);

	fd_install(fd, file);
	return fd;

err_inode:
	iput(inode);
err_fops:
	fops_put(&kvm_gmem_fops);
err_gmem:
	kfree(f);
err_fd:
	put_unused_fd(fd);
	return err;
}

int kvm_gmem_create(struct kvm *kvm, struct kvm_create_guest_memfd *args)
{
	loff_t size = args->size;
	u64 flags = args->flags;
	u8 page_order = 0;

	if (flags & ~kvm_gmem_get_supported_flags(kvm))
		return -EINVAL;

	if (args->page_order && !(flags & GUEST_MEMFD_FLAG_HUGETLB))
		return -EINVAL;

	if (flags & GUEST_MEMFD_FLAG_HUGETLB) {
		if (flags & GUEST_MEMFD_FLAG_INIT_SHARED)
			return -EINVAL;

		page_order = args->page_order;
		if (!gmem_hugetlb_valid_order(page_order))
			return -EINVAL;
	}

	if (size <= 0 || !IS_ALIGNED(size, PAGE_SIZE << page_order))
		return -EINVAL;

	return __kvm_gmem_create(kvm, size, flags, page_order);
}

int kvm_gmem_bind(struct kvm *kvm, struct kvm_memory_slot *slot,
		  unsigned int fd, loff_t offset)
{
	loff_t size = slot->npages << PAGE_SHIFT;
	unsigned long start, end;
	struct gmem_file *f;
	struct inode *inode;
	struct file *file;
	int r = -EINVAL;

	BUILD_BUG_ON(sizeof(gfn_t) != sizeof(slot->gmem.pgoff));

	file = fget(fd);
	if (!file)
		return -EBADF;

	if (file->f_op != &kvm_gmem_fops)
		goto err;

	f = file->private_data;
	if (f->kvm != kvm)
		goto err;

	inode = file_inode(file);

	if (offset < 0 || !PAGE_ALIGNED(offset) ||
	    offset + size > i_size_read(inode))
		goto err;

	filemap_invalidate_lock(inode->i_mapping);

	start = offset >> PAGE_SHIFT;
	end = start + slot->npages;

	if (!xa_empty(&f->bindings) &&
	    xa_find(&f->bindings, &start, end - 1, XA_PRESENT)) {
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
	if (kvm_gmem_supports_mmap(inode))
		slot->flags |= KVM_MEMSLOT_GMEM_ONLY;

	xa_store_range(&f->bindings, start, end - 1, slot, GFP_KERNEL);
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

static void __kvm_gmem_unbind(struct kvm_memory_slot *slot, struct gmem_file *f)
{
	unsigned long start = slot->gmem.pgoff;
	unsigned long end = start + slot->npages;

	xa_store_range(&f->bindings, start, end - 1, NULL, GFP_KERNEL);

	/*
	 * synchronize_srcu(&kvm->srcu) ensured that kvm_gmem_get_pfn()
	 * cannot see this memslot.
	 */
	WRITE_ONCE(slot->gmem.file, NULL);
}

void kvm_gmem_unbind(struct kvm_memory_slot *slot)
{
	/*
	 * Nothing to do if the underlying file was _already_ closed, as
	 * kvm_gmem_release() invalidates and nullifies all bindings.
	 */
	if (!slot->gmem.file)
		return;

	CLASS(gmem_get_file, file)(slot);

	/*
	 * However, if the file is _being_ closed, then the bindings need to be
	 * removed as kvm_gmem_release() might not run until after the memslot
	 * is freed.  Note, modifying the bindings is safe even though the file
	 * is dying as kvm_gmem_release() nullifies slot->gmem.file under
	 * slots_lock, and only puts its reference to KVM after destroying all
	 * bindings.  I.e. reaching this point means kvm_gmem_release() hasn't
	 * yet destroyed the bindings or freed the gmem_file, and can't do so
	 * until the caller drops slots_lock.
	 */
	if (!file) {
		__kvm_gmem_unbind(slot, slot->gmem.file->private_data);
		return;
	}

	filemap_invalidate_lock(file->f_mapping);
	__kvm_gmem_unbind(slot, file->private_data);
	filemap_invalidate_unlock(file->f_mapping);
}

/**
 * kvm_gmem_mapping_order - get the mapping order and pfn for gfn as if a
 * kvm_gmem_get_pfn() were to be called now, but without actually allocating.
 *
 * @slot: The memslot (containing gfn) to look up.
 * @gfn: The gfn we want to look up. Must belong to provided @slot.
 * @pfn: Pointer to pfn to write to.
 *
 * Return: The mapping order for this gfn. Will return order 0 on any
 *         error. *pfn will only be written if the folio was previously
 *         allocated, otherwise *pfn will be left unmodified.
 */
int kvm_gmem_mapping_order(struct kvm_memory_slot *slot, gfn_t gfn,
			   kvm_pfn_t *pfn)
{
	struct gmem_inode *gi;
	struct inode *inode;
	struct folio *folio;
	pgoff_t index_floor;
	struct file *file;
	size_t nr_pages;
	pgoff_t index;
	int order;

	file = kvm_gmem_get_file(slot);
	if (!file)
		return 0;

	inode = file_inode(file);
	gi = GMEM_I(inode);
	index = kvm_gmem_get_index(slot, gfn);
	nr_pages = 1 << gi->page_order;
	index_floor = round_down(index, nr_pages);

	order = 0;
	if (kvm_gmem_range_has_attributes(&gi->attributes, index,
					  nr_pages,
					  KVM_MEMORY_ATTRIBUTE_PRIVATE)) {
		order = gi->page_order;
	}

	folio = filemap_get_folio(inode->i_mapping, index);
	if (!IS_ERR(folio)) {
		*pfn = folio_file_pfn(folio, index);
		folio_put(folio);
	}

	fput(file);
	return order;
}

/* Returns a locked folio on success.  */
static struct folio *__kvm_gmem_get_pfn(struct file *file,
					struct kvm_memory_slot *slot,
					pgoff_t index, kvm_pfn_t *pfn,
					int *max_order)
{
	struct file *slot_file = READ_ONCE(slot->gmem.file);
	struct gmem_file *f = file->private_data;
	struct folio *folio;

	if (file != slot_file) {
		WARN_ON_ONCE(slot_file);
		return ERR_PTR(-EFAULT);
	}

	if (xa_load(&f->bindings, index) != slot) {
		WARN_ON_ONCE(xa_load(&f->bindings, index));
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

	return folio;
}

int kvm_gmem_get_pfn(struct kvm *kvm, struct kvm_memory_slot *slot,
		     gfn_t gfn, kvm_pfn_t *pfn, struct page **page,
		     int *max_order)
{
	pgoff_t index = kvm_gmem_get_index(slot, gfn);
	struct folio *folio;
	int r = 0;

	CLASS(gmem_get_file, file)(slot);
	if (!file)
		return -EFAULT;

	filemap_invalidate_lock_shared(file_inode(file)->i_mapping);

	folio = __kvm_gmem_get_pfn(file, slot, index, pfn, max_order);
	if (IS_ERR(folio)) {
		r = PTR_ERR(folio);
		goto out;
	}

	if (!folio_test_uptodate(folio)) {
		clear_highpage(folio_page(folio, 0));
		folio_mark_uptodate(folio);
	}
	r = kvm_gmem_prepare_folio(kvm, slot, gfn, folio);

	folio_unlock(folio);

	if (!r)
		*page = folio_file_page(folio, index);
	else
		folio_put(folio);

out:
	filemap_invalidate_unlock_shared(file_inode(file)->i_mapping);
	return r;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_gmem_get_pfn);

#ifdef CONFIG_HAVE_KVM_ARCH_GMEM_POPULATE
static bool kvm_gmem_range_is_private(struct gmem_inode *gi, pgoff_t index,
				      size_t nr_pages, struct kvm *kvm, gfn_t gfn)
{
	if (vm_memory_attributes)
		return kvm_range_has_vm_memory_attributes(kvm, gfn, gfn + nr_pages,
						       KVM_MEMORY_ATTRIBUTE_PRIVATE,
						       KVM_MEMORY_ATTRIBUTE_PRIVATE);

	return kvm_gmem_range_has_attributes(&gi->attributes, index, nr_pages,
					     KVM_MEMORY_ATTRIBUTE_PRIVATE);
}

static long __kvm_gmem_populate(struct kvm *kvm, struct kvm_memory_slot *slot,
				struct file *file, gfn_t gfn, struct page *src_page,
				kvm_gmem_populate_cb post_populate, void *opaque)
{
	pgoff_t index = kvm_gmem_get_index(slot, gfn);
	struct gmem_inode *gi;
	struct folio *folio;
	kvm_pfn_t pfn;
	int ret;

	gi = GMEM_I(file_inode(file));

	filemap_invalidate_lock(file->f_mapping);

	folio = __kvm_gmem_get_pfn(file, slot, index, &pfn, NULL);
	if (IS_ERR(folio)) {
		ret = PTR_ERR(folio);
		goto out_unlock;
	}

	folio_unlock(folio);

	if (!kvm_gmem_range_is_private(gi, index, 1, kvm, gfn)) {
		ret = -EINVAL;
		goto out_put_folio;
	}

	ret = post_populate(kvm, gfn, pfn, src_page, opaque);
	if (!ret)
		folio_mark_uptodate(folio);

out_put_folio:
	folio_put(folio);
out_unlock:
	filemap_invalidate_unlock(file->f_mapping);
	return ret;
}

long kvm_gmem_populate(struct kvm *kvm, gfn_t start_gfn, void __user *src, long npages,
		       kvm_gmem_populate_cb post_populate, void *opaque)
{
	struct kvm_memory_slot *slot;
	int ret = 0;
	long i;

	lockdep_assert_held(&kvm->slots_lock);

	if (WARN_ON_ONCE(npages <= 0))
		return -EINVAL;

	if (WARN_ON_ONCE(!PAGE_ALIGNED(src)))
		return -EINVAL;

	slot = gfn_to_memslot(kvm, start_gfn);
	if (!kvm_slot_has_gmem(slot))
		return -EINVAL;

	CLASS(gmem_get_file, file)(slot);
	if (!file)
		return -EFAULT;

	npages = min_t(ulong, slot->npages - (start_gfn - slot->base_gfn), npages);
	for (i = 0; i < npages; i++) {
		struct page *src_page = NULL;
		void __user *p;

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		p = src ? src + i * PAGE_SIZE : NULL;
		if (p) {
			ret = get_user_pages_fast((unsigned long)p, 1, 0, &src_page);
			if (ret < 0)
				break;
			if (ret != 1) {
				ret = -ENOMEM;
				break;
			}
		}

		ret = __kvm_gmem_populate(kvm, slot, file, start_gfn + i, src_page,
					  post_populate, opaque);

		if (src_page)
			put_page(src_page);

		if (ret)
			break;
	}

	return ret && !i ? ret : i;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_gmem_populate);
#endif

static struct kmem_cache *kvm_gmem_inode_cachep;

static void kvm_gmem_init_inode_once(void *__gi)
{
	struct gmem_inode *gi = __gi;

	/*
	 * Note!  Don't initialize the inode with anything specific to the
	 * guest_memfd instance, or that might be specific to how the inode is
	 * used (from the VFS-layer's perspective).  This hook is called only
	 * during the initial slab allocation, i.e. only fields/state that are
	 * idempotent across _all_ use of the inode _object_ can be initialized
	 * at this time!
	 */
	inode_init_once(&gi->vfs_inode);
}

static struct inode *kvm_gmem_alloc_inode(struct super_block *sb)
{
	struct gmem_inode *gi;

	gi = alloc_inode_sb(sb, kvm_gmem_inode_cachep, GFP_KERNEL);
	if (!gi)
		return NULL;

	mpol_shared_policy_init(&gi->policy, NULL);

	/*
	 * Memory attributes are protected the filemap invalidation lock, but
	 * the lock structure isn't available at this time.  Immediately mark
	 * maple tree as using external locking so that accessing the tree
	 * before its fully initialized results in NULL pointer dereferences
	 * and not more subtle bugs.
	 */
	mt_init_flags(&gi->attributes, MT_FLAGS_LOCK_EXTERN);

	gi->flags = 0;
	return &gi->vfs_inode;
}

static void kvm_gmem_destroy_inode(struct inode *inode)
{
	struct gmem_inode *gi = GMEM_I(inode);

	mpol_free_shared_policy(&gi->policy);

	/*
	 * Note!  Checking for an empty tree is functionally necessary to avoid
	 * explosions if the tree hasn't been initialized, i.e. if the inode is
	 * being destroyed before guest_memfd can set the external lock.
	 */
	if (!mtree_empty(&gi->attributes)) {
		/*
		 * Acquire the invalidation lock purely to make lockdep happy,
		 * the inode is unreachable at this point.
		 */
		filemap_invalidate_lock(inode->i_mapping);
		__mt_destroy(&gi->attributes);
		filemap_invalidate_unlock(inode->i_mapping);
	}

	/*
	 * Releasing in .free_inode() possibly happens after RCU delay. Hence,
	 * teardown and release resources in .destroy_inode(), to restore
	 * HugeTLB resources in process context.
	 */
	gmem_hugetlb_teardown(inode, gi->page_order, gi->flags);
}

static void kvm_gmem_free_inode(struct inode *inode)
{
	kmem_cache_free(kvm_gmem_inode_cachep, GMEM_I(inode));
}

static void kvm_gmem_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final_prepare(inode->i_mapping);

	merge_truncate_range(inode, 0, inode->i_size >> PAGE_SHIFT, false);

	clear_inode(inode);
}

static const struct super_operations kvm_gmem_super_operations = {
	.statfs		= simple_statfs,
	.alloc_inode	= kvm_gmem_alloc_inode,
	.destroy_inode	= kvm_gmem_destroy_inode,
	.free_inode	= kvm_gmem_free_inode,
	.evict_inode    = kvm_gmem_evict_inode,
};

static int kvm_gmem_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx;

	if (!init_pseudo(fc, GUEST_MEMFD_MAGIC))
		return -ENOMEM;

	fc->s_iflags |= SB_I_NOEXEC;
	fc->s_iflags |= SB_I_NODEV;
	ctx = fc->fs_private;
	ctx->ops = &kvm_gmem_super_operations;

	return 0;
}

static struct file_system_type kvm_gmem_fs = {
	.name		 = "guest_memfd",
	.init_fs_context = kvm_gmem_init_fs_context,
	.kill_sb	 = kill_anon_super,
};

static int kvm_gmem_init_mount(void)
{
	kvm_gmem_mnt = kern_mount(&kvm_gmem_fs);

	if (IS_ERR(kvm_gmem_mnt))
		return PTR_ERR(kvm_gmem_mnt);

	kvm_gmem_mnt->mnt_flags |= MNT_NOEXEC;
	return 0;
}

int kvm_gmem_init(struct module *module)
{
	struct kmem_cache_args args = {
		.align = 0,
		.ctor = kvm_gmem_init_inode_once,
	};
	int ret;

	kvm_gmem_fops.owner = module;
	kvm_gmem_inode_cachep = kmem_cache_create("kvm_gmem_inode_cache",
						  sizeof(struct gmem_inode),
						  &args, SLAB_ACCOUNT);
	if (!kvm_gmem_inode_cachep)
		return -ENOMEM;

	ret = kvm_gmem_init_mount();
	if (ret) {
		kmem_cache_destroy(kvm_gmem_inode_cachep);
		return ret;
	}
	return 0;
}

void kvm_gmem_exit(void)
{
	kern_unmount(kvm_gmem_mnt);
	kvm_gmem_mnt = NULL;
	rcu_barrier();
	kmem_cache_destroy(kvm_gmem_inode_cachep);
}
