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
#include <linux/hugetlb.h>

#include <uapi/linux/magic.h>

#include "kvm_mm.h"

static struct vfsmount *kvm_gmem_mnt;

struct kvm_gmem {
	struct kvm *kvm;
	u64 flags;
	struct xarray bindings;
	struct {
		struct hstate *h;
		struct hugepage_subpool *spool;
		struct resv_map *resv_map;
	} hugetlb;
};

static loff_t kvm_gmem_get_size(struct file *file)
{
	return i_size_read(file_inode(file));
}

static struct folio *kvm_gmem_hugetlb_alloc_and_cache_folio(
	struct file *file, pgoff_t hindex)
{
	int err;
	struct folio *folio;
	struct kvm_gmem *gmem;
	struct hstate *h;
	struct resv_map *resv_map;
	unsigned long offset;
	struct vm_area_struct pseudo_vma;

	gmem = file->private_data;
	h = gmem->hugetlb.h;
	resv_map = gmem->hugetlb.resv_map;
	offset = hindex << huge_page_shift(h);

	vma_init(&pseudo_vma, NULL);
	vm_flags_init(&pseudo_vma, VM_HUGETLB | VM_MAYSHARE | VM_SHARED);
	/* vma infrastructure is dependent on vm_file being set */
	pseudo_vma.vm_file = file;

	/* TODO setup NUMA policy. Meanwhile, fallback to get_task_policy(). */
	pseudo_vma.vm_policy = NULL;
	folio = alloc_hugetlb_folio_from_subpool(
		gmem->hugetlb.spool, h, resv_map, &pseudo_vma, offset, 0);
	/* Remember to take and drop refcount from vm_policy */
	if (IS_ERR(folio))
		return folio;

	/*
	 * FIXME: Skip clearing pages when trusted firmware will do it when
	 * assigning memory to the guest.
	 */
	clear_huge_page(&folio->page, offset, pages_per_huge_page(h));
	__folio_mark_uptodate(folio);
	err = hugetlb_filemap_add_folio(file->f_mapping, h, folio, hindex);
	if (unlikely(err)) {
		restore_reserve_on_error(resv_map, hindex, true, folio);
		folio_put(folio);
		folio = ERR_PTR(err);
	}

	return folio;
}

/**
 * Gets a hugetlb folio, from @file, at @index (in terms of PAGE_SIZE) within
 * the file.
 *
 * The returned folio will be in @file's page cache, and locked.
 */
static struct folio *kvm_gmem_hugetlb_get_folio(struct file *file, pgoff_t index)
{
	struct folio *folio;
	u32 hash;
	/* hindex is in terms of huge_page_size(h) and not PAGE_SIZE */
	pgoff_t hindex;
	struct kvm_gmem *gmem;
	struct hstate *h;
	struct address_space *mapping;

	gmem = file->private_data;
	h = gmem->hugetlb.h;
	hindex = index >> huge_page_order(h);

	mapping = file->f_mapping;
	hash = hugetlb_fault_mutex_hash(mapping, hindex);
	mutex_lock(&hugetlb_fault_mutex_table[hash]);

	rcu_read_lock();
	folio = filemap_lock_folio(mapping, hindex);
	rcu_read_unlock();
	if (folio)
		goto folio_valid;

	folio = kvm_gmem_hugetlb_alloc_and_cache_folio(file, hindex);
	/*
	 * TODO Perhaps the interface of kvm_gmem_get_folio should change to better
	 * report errors
	 */
	if (IS_ERR(folio))
		folio = NULL;

folio_valid:
	mutex_unlock(&hugetlb_fault_mutex_table[hash]);

	return folio;
}

static struct folio *kvm_gmem_get_huge_folio(struct file *file, pgoff_t index)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	unsigned long huge_index = round_down(index, HPAGE_PMD_NR);
	struct address_space *mapping  = file->f_mapping;
	struct kvm_gmem *gmem = file->private_data;
	gfp_t gfp = mapping_gfp_mask(mapping);
	struct folio *folio;

	if (!(gmem->flags & KVM_GUEST_MEMFD_HUGE_PMD))
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

/**
 * Gets a folio, from @file, at @index (in terms of PAGE_SIZE) within the file.
 *
 * The returned folio will be in @file's page cache and locked.
 */
static struct folio *kvm_gmem_get_folio(struct file *file, pgoff_t index)
{
	struct folio *folio;
	struct kvm_gmem *gmem = file->private_data;

	if (gmem->flags & KVM_GUEST_MEMFD_HUGETLB) {
		folio = kvm_gmem_hugetlb_get_folio(file, index);

		/* hugetlb gmem does not fall back to non-hugetlb pages */
		if (!folio)
			return NULL;

		/*
		 * Don't need to clear pages because
		 * kvm_gmem_hugetlb_alloc_and_cache_folio() already clears pages
		 * when allocating
		 */
	} else {
		folio = kvm_gmem_get_huge_folio(file, index);
		if (!folio) {
			folio = filemap_grab_folio(file->f_mapping, index);
			if (!folio)
				return NULL;
		}

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

		/*
		 * filemap_grab_folio() uses FGP_ACCESSED, which already called
		 * folio_mark_accessed(), so we clear it.
		 * TODO: Should we instead be clearing this when truncating?
		 * TODO: maybe don't use FGP_ACCESSED at all and call __filemap_get_folio directly.
		 */
		folio_clear_referenced(folio);
	}

	/*
	 * Indicate that this folio matches the backing store (in this case, has
	 * been initialized with zeroes)
	 */
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
		pgoff_t index_start = max(slot->gmem.index, start);
		pgoff_t index_end = min(slot->gmem.index + slot->npages, end);
		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + index_start - slot->gmem.index,
			.end = slot->base_gfn + index_end - slot->gmem.index,
			.slot = slot,
			.pte = __pte(0),
			.only_private = true,
			.only_shared = false,
			.may_block = true,
		};

		if ((start < slot->gmem.index ||
		     end > slot->gmem.index + slot->npages)) {
			WARN_ON_ONCE(!(start == 0 && end == -1ul));
			continue;
		}

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

void __weak kvm_arch_gmem_invalidate(struct kvm *kvm, kvm_pfn_t start, kvm_pfn_t end)
{
}

/* Handle arch-specific hooks needed before releasing guarded pages. */
static void kvm_gmem_issue_arch_invalidate(struct kvm *kvm, struct file *file,
					   pgoff_t start, pgoff_t end)
{
	pgoff_t file_end = i_size_read(file_inode(file)) >> PAGE_SHIFT;
	pgoff_t index = start;

	end = min(end, file_end);

	while (index < end) {
		struct folio *folio;
		unsigned int order;
		struct page *page;
		kvm_pfn_t pfn;

		folio = __filemap_get_folio(file->f_mapping, index,
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

static void kvm_gmem_hugetlb_truncate_range(struct inode *inode,
					    loff_t offset, loff_t len)
{
	loff_t hsize;
	loff_t full_hpage_start;
	loff_t full_hpage_end;
	struct kvm_gmem *gmem;
	struct hstate *h;
	struct address_space *mapping;

	mapping = inode->i_mapping;
	gmem = mapping->private_data;
	h = gmem->hugetlb.h;
	hsize = huge_page_size(h);
	full_hpage_start = round_up(offset, hsize);
	full_hpage_end = round_down(offset + len, hsize);

	/* If range starts before first full page, zero partial page. */
	if (offset < full_hpage_start) {
		hugetlb_zero_partial_page(
			h, mapping, offset, min(offset + len, full_hpage_start));
	}

	/* Remove full pages from the file. */
	if (full_hpage_end > full_hpage_start) {
		remove_mapping_hugepages(mapping, h, gmem->hugetlb.spool,
					 gmem->hugetlb.resv_map, inode,
					 full_hpage_start, full_hpage_end);
	}


	/* If range extends beyond last full page, zero partial page. */
	if ((offset + len) > full_hpage_end && (offset + len) > full_hpage_start) {
		hugetlb_zero_partial_page(
			h, mapping, full_hpage_end, offset + len);
	}
}

static long kvm_gmem_punch_hole(struct file *file, loff_t offset, loff_t len)
{
	struct kvm_gmem *gmem = file->private_data;
	struct kvm *kvm = gmem->kvm;
	pgoff_t start, end;

	if (!PAGE_ALIGNED(offset) || !PAGE_ALIGNED(len))
		return 0;

	start = offset >> PAGE_SHIFT;
	end = (offset + len) >> PAGE_SHIFT;

	/*
	 * Bindings must stable across invalidation to ensure the start+end
	 * are balanced.
	 */
	filemap_invalidate_lock(file->f_mapping);

	kvm_gmem_invalidate_begin(kvm, gmem, start, end);

	kvm_gmem_issue_arch_invalidate(kvm, file, start, end);
	if (gmem->flags & KVM_GUEST_MEMFD_HUGETLB)
		kvm_gmem_hugetlb_truncate_range(file_inode(file), offset, len);
	else
		truncate_inode_pages_range(file->f_mapping, offset, offset + len - 1);

	kvm_gmem_invalidate_end(kvm, gmem, start, end);

	filemap_invalidate_unlock(file->f_mapping);

	return 0;
}

static long kvm_gmem_allocate(struct file *file, loff_t offset, loff_t len)
{
	struct address_space *mapping = file->f_mapping;
	struct kvm_gmem *gmem = file->private_data;
	pgoff_t start, index, end;
	int r;

	/* Dedicated guest is immutable by default. */
	if (offset + len > kvm_gmem_get_size(file))
		return -EINVAL;

	filemap_invalidate_lock_shared(mapping);

	if (gmem->flags & KVM_GUEST_MEMFD_HUGETLB) {
		start = offset >> huge_page_shift(gmem->hugetlb.h);
		end = ALIGN(offset + len, huge_page_size(gmem->hugetlb.h)) >> PAGE_SHIFT;
	} else {
		start = offset >> PAGE_SHIFT;
		/* Align so that at least 1 page is allocated */
		end = ALIGN(offset + len, PAGE_SIZE) >> PAGE_SHIFT;
	}

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

		index += folio_nr_pages(folio);

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
	/*
	 * This is called when the last reference to the file is released. Only
	 * clean up file-related stuff. struct kvm_gmem is also referred to in
	 * the inode, so clean that up in kvm_gmem_evict_inode().
	 */
	file->f_mapping = NULL;
	file->private_data = NULL;

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

static int kvm_gmem_hugetlb_setup(struct inode *inode, struct kvm_gmem *gmem,
				  loff_t size, u64 flags)
{
	int page_size_log;
	int hstate_idx;
	long hpages;
	struct resv_map *resv_map;
	struct hugepage_subpool *spool;
	struct hstate *h;

	page_size_log = (flags >> KVM_GUEST_MEMFD_HUGE_SHIFT) & KVM_GUEST_MEMFD_HUGE_MASK;
	hstate_idx = get_hstate_idx(page_size_log);
	if (hstate_idx < 0)
		return -ENOENT;

	h = &hstates[hstate_idx];
	/* Round up to accommodate size requests that don't align with huge pages */
	hpages = round_up(size, huge_page_size(h)) >> huge_page_shift(h);
	spool = hugepage_new_subpool(h, hpages, hpages);
	if (!spool)
		goto out;

	resv_map = resv_map_alloc();
	if (!resv_map)
		goto out_subpool;

	inode->i_blkbits = huge_page_shift(h);

	gmem->hugetlb.h = h;
	gmem->hugetlb.spool = spool;
	gmem->hugetlb.resv_map = resv_map;

	return 0;

out_subpool:
	kfree(spool);
out:
	return -ENOMEM;
}

static struct inode *kvm_gmem_create_inode(struct kvm *kvm, loff_t size, u64 flags,
					   struct vfsmount *mnt)
{
	int err;
	struct inode *inode;
	struct kvm_gmem *gmem;
	const char *anon_name = "[kvm-gmem]";
	const struct qstr qname = QSTR_INIT(anon_name, strlen(anon_name));

	inode = alloc_anon_inode(mnt->mnt_sb);
	if (IS_ERR(inode))
		return inode;

	err = security_inode_init_security_anon(inode, &qname, NULL);
	if (err)
		goto err_inode;

	err = -ENOMEM;
	gmem = kzalloc(sizeof(*gmem), GFP_KERNEL);
	if (!gmem)
		goto err_inode;

	if (flags & KVM_GUEST_MEMFD_HUGETLB) {
		err = kvm_gmem_hugetlb_setup(inode, gmem, size, flags);
		if (err)
			goto err_gmem;
	}

	xa_init(&gmem->bindings);

	kvm_get_kvm(kvm);
	gmem->kvm = kvm;
	gmem->flags = flags;

	inode->i_op = &kvm_gmem_iops;
	inode->i_mapping->a_ops = &kvm_gmem_aops;
	inode->i_mapping->private_data = gmem;
	inode->i_mode |= S_IFREG;
	inode->i_size = size;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_large_folios(inode->i_mapping);
	mapping_set_unevictable(inode->i_mapping);

	return inode;

err_gmem:
	kfree(gmem);
err_inode:
	iput(inode);
	return ERR_PTR(err);
}


static struct file *kvm_gmem_create_file(struct kvm *kvm, loff_t size, u64 flags,
					 struct vfsmount *mnt)
{
	struct file *file;
	struct inode *inode;

	inode = kvm_gmem_create_inode(kvm, size, flags, mnt);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	file = alloc_file_pseudo(inode, mnt, "kvm-gmem", O_RDWR, &kvm_gmem_fops);
	if (IS_ERR(file)) {
		iput(inode);
		return file;
	}

	file->f_flags |= O_LARGEFILE;
	file->f_mapping = inode->i_mapping;
	file->private_data = inode->i_mapping->private_data;

	return file;
}

#define KVM_GUEST_MEMFD_ALL_FLAGS (KVM_GUEST_MEMFD_HUGE_PMD | KVM_GUEST_MEMFD_HUGETLB)

int kvm_gmem_create(struct kvm *kvm, struct kvm_create_guest_memfd *gmem)
{
	int fd;
	struct file *file;
	loff_t size = gmem->size;
	u64 flags = gmem->flags;

	if (size < 0 || !PAGE_ALIGNED(size))
		return -EINVAL;

	if (!(flags & KVM_GUEST_MEMFD_HUGETLB)) {
		if (flags & ~(unsigned int)KVM_GUEST_MEMFD_ALL_FLAGS)
			return -EINVAL;
	} else {
		/* Allow huge page size encoding in flags. */
		if (flags & ~(unsigned int)(KVM_GUEST_MEMFD_ALL_FLAGS |
				(KVM_GUEST_MEMFD_HUGE_MASK << KVM_GUEST_MEMFD_HUGE_SHIFT)))
			return -EINVAL;
	}

	if (flags & KVM_GUEST_MEMFD_HUGE_PMD) {
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		if (!IS_ALIGNED(size, HPAGE_PMD_SIZE))
			return -EINVAL;
#else
		return -EINVAL;
#endif
	}

	fd = get_unused_fd_flags(0);
	if (fd < 0)
		return fd;

	file = kvm_gmem_create_file(kvm, size, flags, kvm_gmem_mnt);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	fd_install(fd, file);
	return fd;
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

	/*
	 * folio_file_page() always returns the head page for hugetlb
	 * folios. Reimplement to get the page within this folio, even for
	 * hugetlb pages.
	 */
	page = folio_page(folio, index & (folio_nr_pages(folio) - 1));

	*pfn = page_to_pfn(page);
	*order = thp_order(compound_head(page));

	folio_unlock(folio);
	fput(file);

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_gmem_get_pfn);

static void kvm_gmem_evict_inode(struct inode *inode)
{
	struct kvm_gmem *gmem = inode->i_mapping->private_data;
	struct kvm_memory_slot *slot;
	struct kvm *kvm;
	unsigned long index;

	/*
	 * If iput() was called before inode is completely set up due to some
	 * error in kvm_gmem_create_inode(), gmem will be NULL.
	 */
	if (!gmem)
		goto basic_cleanup;

	kvm = gmem->kvm;

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
	kvm_gmem_issue_arch_invalidate(gmem->kvm, /* FIXME: file */NULL, 0, -1ul);
	if (gmem->flags & KVM_GUEST_MEMFD_HUGETLB) {
		truncate_inode_pages_final_prepare(inode->i_mapping);
		remove_mapping_hugepages(
			inode->i_mapping, gmem->hugetlb.h, gmem->hugetlb.spool,
			gmem->hugetlb.resv_map, inode, 0, LLONG_MAX);

		resv_map_release(&gmem->hugetlb.resv_map->refs);
		hugepage_put_subpool(gmem->hugetlb.spool);
	} else {
		truncate_inode_pages_final(inode->i_mapping);
	}
	kvm_gmem_invalidate_end(kvm, gmem, 0, -1ul);

	mutex_unlock(&kvm->slots_lock);

	WARN_ON_ONCE(!(mapping_empty(inode->i_mapping)));

	xa_destroy(&gmem->bindings);
	kfree(gmem);

	kvm_put_kvm(kvm);

basic_cleanup:
	clear_inode(inode);
}

static const struct super_operations kvm_gmem_super_operations = {
	/*
	 * TODO update statfs handler for kvm_gmem. What should the statfs
	 * handler return?
	 */
	.statfs		= simple_statfs,
	.evict_inode	= kvm_gmem_evict_inode,
};

bool kvm_gmem_check_alignment(const struct kvm_userspace_memory_region2 *mem)
{
	size_t page_size;

	if (mem->flags & KVM_GUEST_MEMFD_HUGETLB) {
		size_t page_size_log = ((mem->flags >> KVM_GUEST_MEMFD_HUGE_SHIFT)
					& KVM_GUEST_MEMFD_HUGE_MASK);
		page_size = 1UL << page_size_log;
	} else if (mem->flags & KVM_GUEST_MEMFD_HUGE_PMD) {
		page_size = HPAGE_PMD_SIZE;
	} else {
		page_size = PAGE_SIZE;
	}

	return (IS_ALIGNED(mem->gmem_offset, page_size) &&
		IS_ALIGNED(mem->memory_size, page_size));
}

static int kvm_gmem_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx;

	if (!init_pseudo(fc, GUEST_MEMORY_MAGIC))
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
