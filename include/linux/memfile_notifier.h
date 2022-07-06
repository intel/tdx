/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MEMFILE_NOTIFIER_H
#define _LINUX_MEMFILE_NOTIFIER_H

#include <linux/pfn_t.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/fs.h>

/* memory in the file is inaccessible from userspace (e.g. read/write/mmap) */
#define MEMFILE_F_USER_INACCESSIBLE	BIT(0)
/* memory in the file is unmovable (e.g. via pagemigration)*/
#define MEMFILE_F_UNMOVABLE		BIT(1)
/* memory in the file is unreclaimable (e.g. via kswapd) */
#define MEMFILE_F_UNRECLAIMABLE		BIT(2)

#define MEMFILE_F_ALLOWED_MASK		(MEMFILE_F_USER_INACCESSIBLE | \
					MEMFILE_F_UNMOVABLE | \
					MEMFILE_F_UNRECLAIMABLE)

struct memfile_node {
	struct list_head	notifiers;	/* registered notifiers */
	unsigned long		flags;		/* MEMFILE_F_* flags */
};

struct memfile_backing_store {
	struct list_head list;
	spinlock_t lock;
	struct memfile_node* (*lookup_memfile_node)(struct file *file);
	int (*get_pfn)(struct file *file, pgoff_t offset, pfn_t *pfn,
		       int *order);
	void (*put_pfn)(pfn_t pfn);
};

struct memfile_notifier;
struct memfile_notifier_ops {
	void (*invalidate)(struct memfile_notifier *notifier,
			   pgoff_t start, pgoff_t end);
};

struct memfile_notifier {
	struct list_head list;
	struct memfile_notifier_ops *ops;
	struct memfile_backing_store *bs;
};

static inline void memfile_node_init(struct memfile_node *node)
{
	INIT_LIST_HEAD(&node->notifiers);
	node->flags = 0;
}

#ifdef CONFIG_MEMFILE_NOTIFIER
/* APIs for backing stores */
extern void memfile_register_backing_store(struct memfile_backing_store *bs);
extern int memfile_node_set_flags(struct file *file, unsigned long flags);
extern void memfile_notifier_invalidate(struct memfile_node *node,
					pgoff_t start, pgoff_t end);
/*APIs for notifier consumers */
extern int memfile_register_notifier(struct file *file, unsigned long flags,
				     struct memfile_notifier *notifier);
extern void memfile_unregister_notifier(struct memfile_notifier *notifier);

#else /* !CONFIG_MEMFILE_NOTIFIER */
static inline void memfile_register_backing_store(struct memfile_backing_store *bs)
{
}

static inline int memfile_node_set_flags(struct file *file, unsigned long flags)
{
	return -EOPNOTSUPP;
}

static inline void memfile_notifier_invalidate(struct memfile_node *node,
					       pgoff_t start, pgoff_t end)
{
}

static inline int memfile_register_notifier(struct file *file,
					    unsigned long flags,
					    struct memfile_notifier *notifier)
{
	return -EOPNOTSUPP;
}

static inline void memfile_unregister_notifier(struct memfile_notifier *notifier)
{
}

#endif /* CONFIG_MEMFILE_NOTIFIER */

#endif /* _LINUX_MEMFILE_NOTIFIER_H */
