/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_MEMFD_H
#define __LINUX_MEMFD_H

#include <linux/file.h>
#include <linux/pfn_t.h>

#ifdef CONFIG_MEMFD_CREATE
extern long memfd_fcntl(struct file *file, unsigned int cmd, unsigned long arg);
#else
static inline long memfd_fcntl(struct file *f, unsigned int c, unsigned long a)
{
	return -EINVAL;
}
#endif

struct inaccessible_notifier;

struct inaccessible_notifier_ops {
	void (*invalidate)(struct inaccessible_notifier *notifier,
			   pgoff_t start, pgoff_t end);
};

struct inaccessible_notifier {
	struct list_head list;
	const struct inaccessible_notifier_ops *ops;
};

void inaccessible_register_notifier(struct file *file,
				    struct inaccessible_notifier *notifier);
void inaccessible_unregister_notifier(struct file *file,
				      struct inaccessible_notifier *notifier);

int inaccessible_get_pfn(struct file *file, pgoff_t offset, pfn_t *pfn,
			 int *order);
void inaccessible_put_pfn(struct file *file, pfn_t pfn);

struct file *memfd_mkinaccessible(struct file *memfd);

#endif /* __LINUX_MEMFD_H */
