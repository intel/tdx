// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/memfile_notifier.c
 *
 *  Copyright (C) 2022  Intel Corporation.
 *             Chao Peng <chao.p.peng@linux.intel.com>
 */

#include <linux/memfile_notifier.h>
#include <linux/pagemap.h>
#include <linux/srcu.h>

DEFINE_STATIC_SRCU(memfile_srcu);
static __ro_after_init LIST_HEAD(backing_store_list);

void memfile_notifier_populate(struct memfile_node *node,
			       pgoff_t start, pgoff_t end)
{
	struct memfile_notifier *notifier;
	int id;

	id = srcu_read_lock(&memfile_srcu);
	list_for_each_entry_srcu(notifier, &node->notifiers, list,
				 srcu_read_lock_held(&memfile_srcu)) {
		if (notifier->ops->populate)
			notifier->ops->populate(notifier, start, end);
	}
	srcu_read_unlock(&memfile_srcu, id);
}

void memfile_notifier_invalidate(struct memfile_node *node,
				 pgoff_t start, pgoff_t end)
{
	struct memfile_notifier *notifier;
	int id;

	id = srcu_read_lock(&memfile_srcu);
	list_for_each_entry_srcu(notifier, &node->notifiers, list,
				 srcu_read_lock_held(&memfile_srcu)) {
		if (notifier->ops->invalidate)
			notifier->ops->invalidate(notifier, start, end);
	}
	srcu_read_unlock(&memfile_srcu, id);
}

void __init memfile_register_backing_store(struct memfile_backing_store *bs)
{
	spin_lock_init(&bs->lock);
	list_add_tail(&bs->list, &backing_store_list);
}

static void memfile_node_update_flags(struct file *file, unsigned long flags)
{
	struct address_space *mapping = file_inode(file)->i_mapping;
	gfp_t gfp;

	gfp = mapping_gfp_mask(mapping);
	if (flags & MEMFILE_F_UNMOVABLE)
		gfp &= ~__GFP_MOVABLE;
	else
		gfp |= __GFP_MOVABLE;
	mapping_set_gfp_mask(mapping, gfp);

	if (flags & MEMFILE_F_UNRECLAIMABLE)
		mapping_set_unevictable(mapping);
	else
		mapping_clear_unevictable(mapping);
}

int memfile_node_set_flags(struct file *file, unsigned long flags)
{
	struct memfile_backing_store *bs;
	struct memfile_node *node;

	if (flags & ~MEMFILE_F_ALLOWED_MASK)
		return -EINVAL;

	list_for_each_entry(bs, &backing_store_list, list) {
		node = bs->lookup_memfile_node(file);
		if (node) {
			spin_lock(&bs->lock);
			node->flags = flags;
			spin_unlock(&bs->lock);
			memfile_node_update_flags(file, flags);
			return 0;
		}
	}

	return -EOPNOTSUPP;
}

int memfile_register_notifier(struct file *file, unsigned long flags,
			      struct memfile_notifier *notifier)
{
	struct memfile_backing_store *bs;
	struct memfile_node *node;
	struct list_head *list;

	if (!file || !notifier || !notifier->ops)
		return -EINVAL;
	if (flags & ~MEMFILE_F_ALLOWED_MASK)
		return -EINVAL;

	list_for_each_entry(bs, &backing_store_list, list) {
		node = bs->lookup_memfile_node(file);
		if (node) {
			list = &node->notifiers;
			notifier->bs = bs;

			spin_lock(&bs->lock);
			if (list_empty(list))
				node->flags = flags;
			else if (node->flags ^ flags) {
				spin_unlock(&bs->lock);
				return -EINVAL;
			}

			list_add_rcu(&notifier->list, list);
			spin_unlock(&bs->lock);
			memfile_node_update_flags(file, flags);
			return 0;
		}
	}

	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(memfile_register_notifier);

void memfile_unregister_notifier(struct memfile_notifier *notifier)
{
	spin_lock(&notifier->bs->lock);
	list_del_rcu(&notifier->list);
	spin_unlock(&notifier->bs->lock);

	synchronize_srcu(&memfile_srcu);
}
EXPORT_SYMBOL_GPL(memfile_unregister_notifier);
