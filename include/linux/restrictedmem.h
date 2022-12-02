/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_RESTRICTEDMEM_H

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
	struct list_head list;
	const struct restrictedmem_notifier_ops *ops;
};

#ifdef CONFIG_RESTRICTEDMEM

void restrictedmem_register_notifier(struct file *file,
				     struct restrictedmem_notifier *notifier);
void restrictedmem_unregister_notifier(struct file *file,
				       struct restrictedmem_notifier *notifier);

int restrictedmem_get_page(struct file *file, pgoff_t offset,
			   struct page **pagep, int *order);

static inline bool file_is_restrictedmem(struct file *file)
{
	return file->f_inode->i_sb->s_magic == RESTRICTEDMEM_MAGIC;
}

void restrictedmem_error_page(struct page *page, struct address_space *mapping);

#else

static inline void restrictedmem_register_notifier(struct file *file,
				     struct restrictedmem_notifier *notifier)
{
}

static inline void restrictedmem_unregister_notifier(struct file *file,
				       struct restrictedmem_notifier *notifier)
{
}

static inline int restrictedmem_get_page(struct file *file, pgoff_t offset,
					 struct page **pagep, int *order)
{
	return -1;
}

static inline bool file_is_restrictedmem(struct file *file)
{
	return false;
}

static inline void restrictedmem_error_page(struct page *page,
					    struct address_space *mapping)
{
}

#endif /* CONFIG_RESTRICTEDMEM */

#endif /* _LINUX_RESTRICTEDMEM_H */
