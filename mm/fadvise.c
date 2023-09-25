// SPDX-License-Identifier: GPL-2.0
/*
 * mm/fadvise.c
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 11Jan2003	Andrew Morton
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/fadvise.h>
#include <linux/writeback.h>
#include <linux/syscalls.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>

#include <asm/unistd.h>

#include "internal.h"

static int fadvise_inject_error(struct file *file, struct address_space *mapping,
				loff_t offset, off_t endbyte, int advice)
{
	pgoff_t start_index, end_index, index, next;
	struct folio *folio;
	unsigned int shift;
	unsigned long pfn;
	int ret;

	if (!IS_ENABLED(CONFIG_MEMORY_FAILURE))
		return -EOPNOTSUPP;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (is_file_hugepages(file))
		shift = huge_page_shift(hstate_file(file));
	else
		shift = PAGE_SHIFT;
	start_index = offset >> shift;
	end_index = endbyte >> shift;

	index = start_index;
	while (index <= end_index) {
		folio = filemap_get_folio(mapping, index);
		if (IS_ERR(folio))
			return PTR_ERR(folio);

		next = folio_next_index(folio);
		pfn = folio_pfn(folio);
		if (advice == FADV_SOFT_OFFLINE) {
			pr_info("Soft offlining pfn %#lx at file index %#lx\n",
				pfn, index);
			ret = soft_offline_page(pfn, MF_COUNT_INCREASED);
		} else {
			pr_info("Injecting memory failure for pfn %#lx at file index %#lx\n",
				pfn, index);
			ret = memory_failure(pfn, MF_COUNT_INCREASED | MF_SW_SIMULATED);
			if (ret == -EOPNOTSUPP)
				ret = 0;
		}

		if (ret)
			return ret;
		index = next;
	}

	return 0;
}

#ifdef CONFIG_X86_MCE_INJECT
static BLOCKING_NOTIFIER_HEAD(mce_injector_chain);

void fadvise_register_mce_injector_chain(struct notifier_block *nb)
{
	blocking_notifier_chain_register(&mce_injector_chain, nb);
}
EXPORT_SYMBOL_GPL(fadvise_register_mce_injector_chain);

void fadvise_unregister_mce_injector_chain(struct notifier_block *nb)
{
	blocking_notifier_chain_unregister(&mce_injector_chain, nb);
}
EXPORT_SYMBOL_GPL(fadvise_unregister_mce_injector_chain);

static void fadvise_call_mce_injector_chain(unsigned long physaddr)
{
	blocking_notifier_call_chain(&mce_injector_chain, physaddr, NULL);
}
#else
static void fadvise_call_mce_injector_chain(unsigned long physaddr)
{
}
#endif

static int fadvise_inject_mce(struct file *file, struct address_space *mapping,
			      loff_t offset)
{
	unsigned long page_mask, physaddr;
	struct folio *folio;
	pgoff_t index;

	if (!IS_ENABLED(CONFIG_X86_MCE_INJECT))
		return -EOPNOTSUPP;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (is_file_hugepages(file)) {
		index = offset >> huge_page_shift(hstate_file(file));
		page_mask = huge_page_mask(hstate_file(file));
	} else {
		index = offset >> PAGE_SHIFT;
		page_mask = PAGE_MASK;
	}

	folio = filemap_get_folio(mapping, index);
	if (IS_ERR(folio))
		return PTR_ERR(folio);

	physaddr = (folio_pfn(folio) << PAGE_SHIFT) | (offset & ~page_mask);
	folio_put(folio);

	pr_info("Injecting mce for address %#lx at file offset %#llx\n",
		physaddr, offset);
	fadvise_call_mce_injector_chain(physaddr);
	return 0;
}

/*
 * POSIX_FADV_WILLNEED could set PG_Referenced, and POSIX_FADV_NOREUSE could
 * deactivate the pages and clear PG_Referenced.
 */

int generic_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	struct inode *inode;
	struct address_space *mapping;
	struct backing_dev_info *bdi;
	loff_t endbyte;			/* inclusive */
	pgoff_t start_index;
	pgoff_t end_index;
	unsigned long nrpages;

	inode = file_inode(file);
	if (S_ISFIFO(inode->i_mode))
		return -ESPIPE;

	mapping = file->f_mapping;
	if (!mapping || len < 0)
		return -EINVAL;

	bdi = inode_to_bdi(mapping->host);

	if (IS_DAX(inode) || (bdi == &noop_backing_dev_info)) {
		switch (advice) {
		case POSIX_FADV_NORMAL:
		case POSIX_FADV_RANDOM:
		case POSIX_FADV_SEQUENTIAL:
		case POSIX_FADV_WILLNEED:
		case POSIX_FADV_NOREUSE:
		case POSIX_FADV_DONTNEED:
			/* no bad return value, but ignore advice */
			return 0;
		case FADV_HWPOISON:
		case FADV_SOFT_OFFLINE:
		case FADV_MCE_INJECT:
			break;
		default:
			return -EINVAL;
		}
	}

	/*
	 * Careful about overflows. Len == 0 means "as much as possible".  Use
	 * unsigned math because signed overflows are undefined and UBSan
	 * complains.
	 */
	endbyte = (u64)offset + (u64)len;
	if (!len || endbyte < len)
		endbyte = LLONG_MAX;
	else
		endbyte--;		/* inclusive */

	switch (advice) {
	case POSIX_FADV_NORMAL:
		file->f_ra.ra_pages = bdi->ra_pages;
		spin_lock(&file->f_lock);
		file->f_mode &= ~(FMODE_RANDOM | FMODE_NOREUSE);
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_RANDOM:
		spin_lock(&file->f_lock);
		file->f_mode |= FMODE_RANDOM;
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_SEQUENTIAL:
		file->f_ra.ra_pages = bdi->ra_pages * 2;
		spin_lock(&file->f_lock);
		file->f_mode &= ~FMODE_RANDOM;
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_WILLNEED:
		/* First and last PARTIAL page! */
		start_index = offset >> PAGE_SHIFT;
		end_index = endbyte >> PAGE_SHIFT;

		/* Careful about overflow on the "+1" */
		nrpages = end_index - start_index + 1;
		if (!nrpages)
			nrpages = ~0UL;

		force_page_cache_readahead(mapping, file, start_index, nrpages);
		break;
	case POSIX_FADV_NOREUSE:
		spin_lock(&file->f_lock);
		file->f_mode |= FMODE_NOREUSE;
		spin_unlock(&file->f_lock);
		break;
	case POSIX_FADV_DONTNEED:
		__filemap_fdatawrite_range(mapping, offset, endbyte,
					   WB_SYNC_NONE);

		/*
		 * First and last FULL page! Partial pages are deliberately
		 * preserved on the expectation that it is better to preserve
		 * needed memory than to discard unneeded memory.
		 */
		start_index = (offset+(PAGE_SIZE-1)) >> PAGE_SHIFT;
		end_index = (endbyte >> PAGE_SHIFT);
		/*
		 * The page at end_index will be inclusively discarded according
		 * by invalidate_mapping_pages(), so subtracting 1 from
		 * end_index means we will skip the last page.  But if endbyte
		 * is page aligned or is at the end of file, we should not skip
		 * that page - discarding the last page is safe enough.
		 */
		if ((endbyte & ~PAGE_MASK) != ~PAGE_MASK &&
				endbyte != inode->i_size - 1) {
			/* First page is tricky as 0 - 1 = -1, but pgoff_t
			 * is unsigned, so the end_index >= start_index
			 * check below would be true and we'll discard the whole
			 * file cache which is not what was asked.
			 */
			if (end_index == 0)
				break;

			end_index--;
		}

		if (end_index >= start_index) {
			unsigned long nr_failed = 0;

			/*
			 * It's common to FADV_DONTNEED right after
			 * the read or write that instantiates the
			 * pages, in which case there will be some
			 * sitting on the local LRU cache. Try to
			 * avoid the expensive remote drain and the
			 * second cache tree walk below by flushing
			 * them out right away.
			 */
			lru_add_drain();

			mapping_try_invalidate(mapping, start_index, end_index,
					&nr_failed);

			/*
			 * The failures may be due to the folio being
			 * in the LRU cache of a remote CPU. Drain all
			 * caches and try again.
			 */
			if (nr_failed) {
				lru_add_drain_all();
				invalidate_mapping_pages(mapping, start_index,
						end_index);
			}
		}
		break;
	case FADV_HWPOISON:
	case FADV_SOFT_OFFLINE:
		return fadvise_inject_error(file, mapping, offset, endbyte, advice);
	case FADV_MCE_INJECT:
		return fadvise_inject_mce(file, mapping, offset);
	default:
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(generic_fadvise);

int vfs_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	if (file->f_op->fadvise)
		return file->f_op->fadvise(file, offset, len, advice);

	return generic_fadvise(file, offset, len, advice);
}
EXPORT_SYMBOL(vfs_fadvise);

#ifdef CONFIG_ADVISE_SYSCALLS

int ksys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice)
{
	struct fd f = fdget(fd);
	int ret;

	if (!f.file)
		return -EBADF;

	ret = vfs_fadvise(f.file, offset, len, advice);

	fdput(f);
	return ret;
}

SYSCALL_DEFINE4(fadvise64_64, int, fd, loff_t, offset, loff_t, len, int, advice)
{
	return ksys_fadvise64_64(fd, offset, len, advice);
}

#ifdef __ARCH_WANT_SYS_FADVISE64

SYSCALL_DEFINE4(fadvise64, int, fd, loff_t, offset, size_t, len, int, advice)
{
	return ksys_fadvise64_64(fd, offset, len, advice);
}

#endif

#if defined(CONFIG_COMPAT) && defined(__ARCH_WANT_COMPAT_FADVISE64_64)

COMPAT_SYSCALL_DEFINE6(fadvise64_64, int, fd, compat_arg_u64_dual(offset),
		       compat_arg_u64_dual(len), int, advice)
{
	return ksys_fadvise64_64(fd, compat_arg_u64_glue(offset),
				 compat_arg_u64_glue(len), advice);
}

#endif
#endif
