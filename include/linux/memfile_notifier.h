/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MEMFILE_NOTIFIER_H
#define _LINUX_MEMFILE_NOTIFIER_H

#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/fs.h>

struct memfile_notifier;

struct memfile_notifier_ops {
	void (*invalidate)(struct memfile_notifier *notifier,
			   pgoff_t start, pgoff_t end);
	void (*fallocate)(struct memfile_notifier *notifier,
			  pgoff_t start, pgoff_t end);
};

struct memfile_pfn_ops {
	long (*get_lock_pfn)(struct inode *inode, pgoff_t offset, int *order);
	void (*put_unlock_pfn)(unsigned long pfn);
};

struct memfile_notifier {
	struct list_head list;
	struct memfile_notifier_ops *ops;
};

struct memfile_notifier_list {
	struct list_head head;
	spinlock_t lock;
};

struct memfile_backing_store {
	struct list_head list;
	struct memfile_pfn_ops pfn_ops;
	struct memfile_notifier_list* (*get_notifier_list)(struct inode *inode);
};

#ifdef CONFIG_MEMFILE_NOTIFIER
/* APIs for backing stores */
static inline void memfile_notifier_list_init(struct memfile_notifier_list *list)
{
	INIT_LIST_HEAD(&list->head);
	spin_lock_init(&list->lock);
}

extern void memfile_notifier_invalidate(struct memfile_notifier_list *list,
					pgoff_t start, pgoff_t end);
extern void memfile_notifier_fallocate(struct memfile_notifier_list *list,
				       pgoff_t start, pgoff_t end);
extern void memfile_register_backing_store(struct memfile_backing_store *bs);
extern void memfile_unregister_backing_store(struct memfile_backing_store *bs);

/*APIs for notifier consumers */
extern int memfile_register_notifier(struct inode *inode,
				     struct memfile_notifier *notifier,
				     struct memfile_pfn_ops **pfn_ops);
extern void memfile_unregister_notifier(struct inode *inode,
					struct memfile_notifier *notifier);

#endif /* CONFIG_MEMFILE_NOTIFIER */

#endif /* _LINUX_MEMFILE_NOTIFIER_H */
