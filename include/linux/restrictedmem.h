/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_RESTRICTEDMEM_H
#define _LINUX_RESTRICTEDMEM_H

#include <linux/file.h>
#include <linux/magic.h>
#include <linux/pfn_t.h>

struct restrictedmem_notifier;

struct restrictedmem_notifier_ops {
	void (*invalidate_start)(struct restrictedmem_notifier *notifier,
				 pgoff_t start, pgoff_t end);
	void (*invalidate_end)(struct restrictedmem_notifier *notifier,
			       pgoff_t start, pgoff_t end);
	void (*error)(struct restrictedmem_notifier *notifier,
			       pgoff_t start, pgoff_t end);
};

struct restrictedmem_notifier {
	const struct restrictedmem_notifier_ops *ops;
};

#ifdef CONFIG_RESTRICTEDMEM

int restrictedmem_bind(struct file *file, pgoff_t start, pgoff_t end,
		       struct restrictedmem_notifier *notifier, bool exclusive);
void restrictedmem_unbind(struct file *file, pgoff_t start, pgoff_t end,
			  struct restrictedmem_notifier *notifier);

int restrictedmem_get_page(struct file *file, pgoff_t offset,
			   struct page **pagep, int *order);

static inline bool file_is_restrictedmem(struct file *file)
{
	return file->f_inode->i_sb->s_magic == RESTRICTEDMEM_MAGIC;
}

#else

static inline bool file_is_restrictedmem(struct file *file)
{
	return false;
}

#endif /* CONFIG_RESTRICTEDMEM */

#endif /* _LINUX_RESTRICTEDMEM_H */
