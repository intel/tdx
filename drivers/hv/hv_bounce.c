// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, Microsoft Corporation.
 *
 * Authors:
 *   Sunil Muthuswamy <sunilmut@microsoft.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "hyperv_vmbus.h"
#include <linux/uio.h>
#include <asm/mshyperv.h>

/*
 * Number of pages a va and size spans. An offset can also be provided
 * instead of a va.
 */
#define BYTE_OFFSET(va) (va & (HV_HYP_PAGE_SIZE - 1))
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(va, size)	\
	((size >> PAGE_SHIFT) +				\
	((BYTE_OFFSET(va) + BYTE_OFFSET(size) + HV_HYP_PAGE_SIZE - 1) >> PAGE_SHIFT))

/* BP == Bounce Pages here */
#define BP_LIST_MAINTENANCE_FREQ (30 * HZ)
#define BP_MIN_TIME_IN_FREE_LIST (30 * HZ)
#define IS_BP_MAINTENANCE_TASK_NEEDED(channel) \
	(channel->bounce_page_alloc_count > \
	 channel->min_bounce_resource_count && \
	 !list_empty(&channel->bounce_page_free_head))
#define BP_QUEUE_MAINTENANCE_WORK(channel) \
	queue_delayed_work(system_unbound_wq,		\
			   &channel->bounce_page_list_maintain, \
			   BP_LIST_MAINTENANCE_FREQ)

#define hv_copy_to_bounce(bounce_pkt) \
		hv_copy_to_from_bounce(bounce_pkt, true)
#define hv_copy_from_bounce(bounce_pkt)	\
		hv_copy_to_from_bounce(bounce_pkt, false)
/*
 * A list of bounce pages, with original va, bounce va and I/O details such as
 * the offset and length.
 */
struct hv_bounce_page_list {
	struct list_head link;
	u32 offset;
	u32 len;
	unsigned long va;
	unsigned long bounce_va;
	unsigned long bounce_original_va;
	unsigned long bounce_extra_pfn;
	unsigned long last_used_jiff;
};

/*
 * This structure can be safely used to iterate over objects of the type
 * 'hv_page_buffer', 'hv_mpb_array' or 'hv_multipage_buffer'. The min array
 * size of 1 is needed to include the size of 'pfn_array' as part of the struct.
 */
struct hv_page_range {
	u32 len;
	u32 offset;
	u64 pfn_array[1];
};

static inline struct hv_bounce_pkt *__hv_bounce_pkt_alloc(
	struct vmbus_channel *channel)
{
	return kmem_cache_alloc(channel->bounce_pkt_cache,
				__GFP_ZERO | GFP_KERNEL);
}

static inline void __hv_bounce_pkt_free(struct vmbus_channel *channel,
					struct hv_bounce_pkt *bounce_pkt)
{
	kmem_cache_free(channel->bounce_pkt_cache, bounce_pkt);
}

static inline void hv_bounce_pkt_list_free(struct vmbus_channel *channel,
					   const struct list_head *head)
{
	struct hv_bounce_pkt *bounce_pkt;
	struct hv_bounce_pkt *tmp;

	list_for_each_entry_safe(bounce_pkt, tmp, head, link) {
		list_del(&bounce_pkt->link);
		__hv_bounce_pkt_free(channel, bounce_pkt);
	}
}

/*
 * Assigns a free bounce packet from the channel, if one is available. Else,
 * allocates one. Use 'hv_bounce_resources_release' to release the bounce packet
 * as it also takes care of releasing the bounce pages within, if any.
 */
static struct hv_bounce_pkt *hv_bounce_pkt_assign(struct vmbus_channel *channel)
{
	if (channel->min_bounce_resource_count) {
		struct hv_bounce_pkt *bounce_pkt = NULL;
		unsigned long flags;

		spin_lock_irqsave(&channel->bp_lock, flags);
		if (!list_empty(&channel->bounce_pkt_free_list_head)) {
			bounce_pkt = list_first_entry(
					&channel->bounce_pkt_free_list_head,
					struct hv_bounce_pkt, link);
			list_del(&bounce_pkt->link);
			channel->bounce_pkt_free_count--;
		}

		spin_unlock_irqrestore(&channel->bp_lock, flags);
		if (bounce_pkt)
			return bounce_pkt;
	}

	return __hv_bounce_pkt_alloc(channel);
}

static void hv_bounce_pkt_release(struct vmbus_channel *channel,
				  struct hv_bounce_pkt *bounce_pkt)
{
	bool free_pkt = true;

	if (channel->min_bounce_resource_count) {
		unsigned long flags;

		spin_lock_irqsave(&channel->bp_lock, flags);
		if (channel->bounce_pkt_free_count <
		    channel->min_bounce_resource_count) {
			list_add(&bounce_pkt->link,
				 &channel->bounce_pkt_free_list_head);
			channel->bounce_pkt_free_count++;
			free_pkt = false;
		}

		spin_unlock_irqrestore(&channel->bp_lock, flags);
	}

	if (free_pkt)
		__hv_bounce_pkt_free(channel, bounce_pkt);
}

/* Frees the list of bounce pages and all of the resources within */
static void hv_bounce_page_list_free(struct vmbus_channel *channel,
				     const struct list_head *head)
{
	u16 count = 0;
	u64 pfn[HV_MIN_BOUNCE_BUFFER_PAGES];
	struct hv_bounce_page_list *bounce_page;
	struct hv_bounce_page_list *tmp;

	BUILD_BUG_ON(HV_MIN_BOUNCE_BUFFER_PAGES > HV_MAX_MODIFY_GPA_REP_COUNT);
	list_for_each_entry(bounce_page, head, link) {
		if (hv_isolation_type_snp())
			pfn[count++] = virt_to_hvpfn((void*)bounce_page->bounce_original_va);
		else
			pfn[count++] = virt_to_hvpfn((void*)bounce_page->bounce_va);

		if (count < HV_MIN_BOUNCE_BUFFER_PAGES &&
		    !list_is_last(&bounce_page->link, head))
			continue;
		hv_mark_gpa_visibility(count, pfn, VMBUS_PAGE_NOT_VISIBLE);
		count = 0;
	}

	/*
	 * Need a second iteration because the page should not be freed until
	 * it is marked not-visible to the host.
	 */
	list_for_each_entry_safe(bounce_page, tmp, head, link) {
		list_del(&bounce_page->link);

		if (hv_isolation_type_snp()) {
			vunmap((void *)bounce_page->bounce_va);
			free_page(bounce_page->bounce_original_va);
		} else
			free_page(bounce_page->bounce_va);

		kmem_cache_free(channel->bounce_page_cache, bounce_page);
	}
}

/* Allocate a list of bounce pages and make them host visible. */
static int hv_bounce_page_list_alloc(struct vmbus_channel *channel, u32 count)
{
	unsigned long flags;
	struct list_head head;
	u32 p;
	u64 pfn[HV_MIN_BOUNCE_BUFFER_PAGES];
	u32 pfn_count = 0;
	bool queue_work = false;
	int ret = -ENOSPC;
	unsigned long va = 0;

	INIT_LIST_HEAD(&head);
	for (p = 0; p < count; p++) {
		struct hv_bounce_page_list *bounce_page;

		/*
		 * get_free_pages is not used to avoid the unnecessary overhead
		 * of allocating physically contiguous memory.
		 */
		va = __get_free_page(__GFP_ZERO | GFP_KERNEL);
		if (unlikely(!va))
			goto err_free;
		bounce_page = kmem_cache_alloc(channel->bounce_page_cache,
					       __GFP_ZERO | GFP_KERNEL);
		if (unlikely(!bounce_page))
			goto err_free;

		if (hv_isolation_type_snp()) {
			bounce_page->bounce_extra_pfn = virt_to_hvpfn((void*)va)
				+ (ms_hyperv.shared_gpa_boundary >> HV_HYP_PAGE_SHIFT);
			bounce_page->bounce_original_va = va;
			bounce_page->bounce_va = (u64)ioremap_cache(
				bounce_page->bounce_extra_pfn << PAGE_SHIFT,
				HV_HYP_PAGE_SIZE);
			if (!bounce_page->bounce_va)
				goto err_free;
		} else {
			bounce_page->bounce_va = va;
		}

		pfn[pfn_count++] = virt_to_hvpfn((void*)va);
		bounce_page->last_used_jiff = jiffies;

		/* Add to the tail to maintain LRU sorting */
		list_add_tail(&bounce_page->link, &head);
		va = 0;
		if (pfn_count == HV_MIN_BOUNCE_BUFFER_PAGES || p == count - 1) {
			ret = hv_mark_gpa_visibility(pfn_count, pfn,
					VMBUS_PAGE_VISIBLE_READ_WRITE);
			if (hv_isolation_type_snp())
				list_for_each_entry(bounce_page, &head, link)
					memset((u64*)bounce_page->bounce_va, 0x00,
					       HV_HYP_PAGE_SIZE);

			if (unlikely(ret < 0))
				goto err_free;
			pfn_count = 0;
		}
	}

	/*
	 * Merge the newly allocated list with the channel's free list. It's
	 * done here instead of in the loop above to avoid the spinlock
	 * overhead within a loop.
	 */
	spin_lock_irqsave(&channel->bp_lock, flags);
	list_splice_tail(&head, &channel->bounce_page_free_head);
	channel->bounce_page_alloc_count += count;
	queue_work = IS_BP_MAINTENANCE_TASK_NEEDED(channel);
	spin_unlock_irqrestore(&channel->bp_lock, flags);
	if (queue_work)
		BP_QUEUE_MAINTENANCE_WORK(channel);
	return 0;
err_free:
	if (va)
		free_page(va);
	hv_bounce_page_list_free(channel, &head);
	return ret;
}

/*
 * Puts the bounce pages in the list back into the channel's free bounce page
 * list and schedules the bounce page maintenance routine.
 */
static void hv_bounce_page_list_release(struct vmbus_channel *channel,
					struct list_head *head)
{
	struct hv_bounce_page_list *bounce_page;
	unsigned long flags;
	bool queue_work;
	struct hv_bounce_page_list *tmp;

	/*
	 * Need to iterate, rather than a direct list merge so that the last
	 * used timestamp can be updated for each page.
	 * Add the page to the tail of the free list to maintain LRU sorting.
	 */
	spin_lock_irqsave(&channel->bp_lock, flags);
	list_for_each_entry_safe(bounce_page, tmp, head, link) {
		list_del(&bounce_page->link);
		bounce_page->last_used_jiff = jiffies;

		/* Maintain LRU */
		list_add_tail(&bounce_page->link,
			      &channel->bounce_page_free_head);
	}

	queue_work = IS_BP_MAINTENANCE_TASK_NEEDED(channel);
	spin_unlock_irqrestore(&channel->bp_lock, flags);
	if (queue_work)
		BP_QUEUE_MAINTENANCE_WORK(channel);
}

/*
 * Maintenance work to prune the vmbus channel's free bounce page list. It runs
 * at every 'BP_LIST_MAINTENANCE_FREQ' and frees the bounce pages that are in
 * the free list longer than 'BP_MIN_TIME_IN_FREE_LIST' once the min bounce
 * resource reservation requirement is met.
 */
static void hv_bounce_page_list_maintain(struct work_struct *work)
{
	struct vmbus_channel *channel;
	struct delayed_work *dwork = to_delayed_work(work);
	unsigned long flags;
	struct list_head head_to_free;
	bool queue_work;

	channel = container_of(dwork, struct vmbus_channel,
			       bounce_page_list_maintain);
	INIT_LIST_HEAD(&head_to_free);
	spin_lock_irqsave(&channel->bp_lock, flags);
	while (IS_BP_MAINTENANCE_TASK_NEEDED(channel)) {
		struct hv_bounce_page_list *bounce_page = list_first_entry(
				&channel->bounce_page_free_head,
				struct hv_bounce_page_list,
				link);

		/*
		 * Stop on the first entry that fails the check since the
		 * list is expected to be sorted on LRU.
		 */
		if (time_before(jiffies, bounce_page->last_used_jiff +
				BP_MIN_TIME_IN_FREE_LIST))
			break;
		list_del(&bounce_page->link);
		list_add_tail(&bounce_page->link, &head_to_free);
		channel->bounce_page_alloc_count--;
	}

	queue_work = IS_BP_MAINTENANCE_TASK_NEEDED(channel);
	spin_unlock_irqrestore(&channel->bp_lock, flags);
	if (!list_empty(&head_to_free))
		hv_bounce_page_list_free(channel, &head_to_free);
	if (queue_work)
		BP_QUEUE_MAINTENANCE_WORK(channel);
}

/*
 * Assigns a free bounce page from the channel, if one is available. Else,
 * allocates a bunch of bounce pages into the channel and returns one. Use
 * 'hv_bounce_page_list_release' to release the page.
 */
static struct hv_bounce_page_list *hv_bounce_page_assign(
	struct vmbus_channel *channel)
{
	struct hv_bounce_page_list *bounce_page = NULL;
	unsigned long flags;

	spin_lock_irqsave(&channel->bp_lock, flags);
	if (!list_empty(&channel->bounce_page_free_head)) {
		bounce_page = list_first_entry(&channel->bounce_page_free_head,
					       struct hv_bounce_page_list,
					       link);
		list_del(&bounce_page->link);
	}
	spin_unlock_irqrestore(&channel->bp_lock, flags);

	if (likely(bounce_page)) {
		return bounce_page;
	} else {
		pr_warn("Bounce buffer exhausts.\n");
		return NULL;
	}
}

/*
 * Allocate 'count' linked list of bounce packets into the channel. Use
 * 'hv_bounce_pkt_list_free' to free the list.
 */
static int hv_bounce_pkt_list_alloc(struct vmbus_channel *channel, u32 count)
{
	struct list_head bounce_pkt_head;
	unsigned long flags;
	u32 i;

	INIT_LIST_HEAD(&bounce_pkt_head);
	for (i = 0; i < count; i++) {
		struct hv_bounce_pkt *bounce_pkt = __hv_bounce_pkt_alloc(
							channel);

		if (unlikely(!bounce_pkt))
			goto err_free;
		list_add(&bounce_pkt->link, &bounce_pkt_head);
	}

	spin_lock_irqsave(&channel->bp_lock, flags);
	list_splice_tail(&bounce_pkt_head, &channel->bounce_pkt_free_list_head);
	channel->bounce_pkt_free_count += count;
	spin_unlock_irqrestore(&channel->bp_lock, flags);
	return 0;
err_free:
	hv_bounce_pkt_list_free(channel, &bounce_pkt_head);
	return -ENOMEM;
}

/*
 * Allocate and reserve enough bounce resources to be able to handle the min
 * specified bytes. This routine should be called prior to starting the I/O on
 * the channel, else the channel will end up not reserving any bounce resources.
 */
int hv_bounce_resources_reserve(struct vmbus_channel *channel,
				u32 min_bounce_bytes)
{
	unsigned long flags;
	u32 round_up_count;
	int ret;

	if (!hv_partition_is_isolated())
		return 0;

	/* Resize operation is currently not supported */
	if (unlikely((!min_bounce_bytes || channel->min_bounce_resource_count)))
		return -EINVAL;

	/*
	 * Get the page count and round it up to the min bounce pages supported
	 */
	round_up_count = round_up(min_bounce_bytes, HV_HYP_PAGE_SIZE) >> PAGE_SHIFT;
	round_up_count = round_up(round_up_count, HV_MIN_BOUNCE_BUFFER_PAGES);
	spin_lock_irqsave(&channel->bp_lock, flags);
	channel->min_bounce_resource_count = round_up_count;
	spin_unlock_irqrestore(&channel->bp_lock, flags);
	ret = hv_bounce_pkt_list_alloc(channel, round_up_count);
	if (ret < 0)
		return ret;
	return hv_bounce_page_list_alloc(channel, round_up_count);
}
EXPORT_SYMBOL_GPL(hv_bounce_resources_reserve);

static void hv_bounce_resources_release(struct vmbus_channel *channel,
					struct hv_bounce_pkt *bounce_pkt)
{
	if (unlikely(!bounce_pkt))
		return;
	hv_bounce_page_list_release(channel, &bounce_pkt->bounce_page_head);
	hv_bounce_pkt_release(channel, bounce_pkt);
}

static void hv_copy_to_from_bounce(const struct hv_bounce_pkt *bounce_pkt,
				   bool copy_to_bounce)
{
	struct hv_bounce_page_list *bounce_page;

	if ((copy_to_bounce && (bounce_pkt->flags != IO_TYPE_WRITE)) ||
	    (!copy_to_bounce && (bounce_pkt->flags != IO_TYPE_READ)))
		return;

	list_for_each_entry(bounce_page, &bounce_pkt->bounce_page_head, link) {
		u32 offset = bounce_page->offset;
		u32 len = bounce_page->len;
		u8 *bounce_buffer = (u8 *)bounce_page->bounce_va;
		u8 *buffer = (u8 *)bounce_page->va;

		BUG_ON(offset + len > HV_HYP_PAGE_SIZE);

		if (copy_to_bounce)
			memcpy(bounce_buffer + offset, buffer + offset, len);
		else
			memcpy(buffer + offset, bounce_buffer + offset, len);
	}
}

/*
 * Assigns the bounce resources needed to handle the PFNs within the range and
 * updates the range accordingly. Uses resources from the pre-allocated pool if
 * previously reserved, else allocates memory. Use 'hv_bounce_resources_release'
 * to release.
 */
static struct hv_bounce_pkt *hv_bounce_resources_assign(
	struct vmbus_channel *channel,
	u32 rangecount,
	struct hv_page_range *range,
	u8 io_type)
{
	struct hv_bounce_pkt *bounce_pkt;
	u32 r;

	bounce_pkt = hv_bounce_pkt_assign(channel);
	if (unlikely(!bounce_pkt))
		return NULL;
	bounce_pkt->flags = io_type;
	INIT_LIST_HEAD(&bounce_pkt->bounce_page_head);
	for (r = 0; r < rangecount; r++) {
		u32 len = range[r].len;
		u32 offset = range[r].offset;
		u32 p;
		u32 pfn_count;

		BUG_ON(offset >= HV_HYP_PAGE_SIZE);
		pfn_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(offset, len);
		for (p = 0; p < pfn_count; p++) {
			struct hv_bounce_page_list *bounce_page;
			u32 copy_len = min(len, ((u32)HV_HYP_PAGE_SIZE - offset));

			bounce_page  = hv_bounce_page_assign(channel);
			if (unlikely(!bounce_page))
				goto err_free;
			bounce_page->va = (unsigned long)
				__va(range[r].pfn_array[p] << PAGE_SHIFT);
			bounce_page->offset = offset;
			bounce_page->len = copy_len;
			list_add_tail(&bounce_page->link,
				      &bounce_pkt->bounce_page_head);

			if (hv_isolation_type_snp()) {
				range[r].pfn_array[p] =
					bounce_page->bounce_extra_pfn;
			} else {
				range[r].pfn_array[p] =
					virt_to_hvpfn((void*)bounce_page->bounce_va);
			}
			offset = 0;
			len -= copy_len;
		}
	}

	/* Copy data from original buffer to bounce buffer, if needed */
	hv_copy_to_bounce(bounce_pkt);
	return bounce_pkt;
err_free:
	/* This will also reclaim any allocated bounce pages */
	hv_bounce_resources_release(channel, bounce_pkt);
	return NULL;
}

int vmbus_sendpacket_pagebuffer_bounce(
	struct vmbus_channel *channel,
	struct vmbus_channel_packet_page_buffer *desc,
	u32 desc_size, struct kvec *bufferlist,
	u64 requestid,
	u8 io_type, struct hv_bounce_pkt **pbounce_pkt)
{
	struct hv_bounce_pkt *bounce_pkt;
	int ret;

	if (channel->primary_channel)
		channel = channel->primary_channel;

	BUILD_BUG_ON(sizeof(struct hv_page_range) !=
		     sizeof(struct hv_page_buffer));
	bounce_pkt = hv_bounce_resources_assign(channel, desc->rangecount,
			(struct hv_page_range *)desc->range, io_type);
	if (unlikely(!bounce_pkt))
		return -ENOSPC;
	ret = hv_ringbuffer_write(channel, bufferlist, 3, requestid);
	if (unlikely(ret < 0))
		hv_bounce_resources_release(channel, bounce_pkt);
	else
		*pbounce_pkt = bounce_pkt;

	return ret;
}

int vmbus_sendpacket_mpb_desc_bounce(
	struct vmbus_channel *channel,
	struct vmbus_packet_mpb_array *desc,
	u32 desc_size,
	struct kvec *bufferlist,
	u64 requestid,
	u8 io_type, struct hv_bounce_pkt **pbounce_pkt)
{
	struct hv_bounce_pkt *bounce_pkt;
	struct vmbus_packet_mpb_array *desc_bounce;
	struct hv_mpb_array *range;
	int ret = -ENOSPC;

	/*
	 * As an optiization to avoid further memory allocation in this path,
	 * an in-place update can be done to the PFN list as the only vmbus
	 * client to use this routine is the storvsc and it doesn't use the
	 * PFNs once passed here, but that would be a violation of the
	 * layering. Another option is to to include a flag indicating that
	 * the descriptor PFN range is dispensable.
	 */
	desc_bounce = kzalloc(desc_size, GFP_ATOMIC);
	if (unlikely(!desc_bounce))
		return ret;

	if (channel->primary_channel)
		channel = channel->primary_channel;

	memcpy(desc_bounce, desc, desc_size);
	range = &desc_bounce->range;
	bounce_pkt = hv_bounce_resources_assign(channel, desc->rangecount,
			(struct hv_page_range *)range, io_type);
	if (unlikely(!bounce_pkt))
		goto free;
	bufferlist[0].iov_base = desc_bounce;
	ret = hv_ringbuffer_write(channel, bufferlist, 3, requestid);
free:
	kfree(desc_bounce);
	if (unlikely(ret < 0))
		hv_bounce_resources_release(channel, bounce_pkt);
	else
		*pbounce_pkt = bounce_pkt;
	return ret;
}

void hv_pkt_bounce(struct vmbus_channel *channel,
		   struct hv_bounce_pkt *bounce_pkt)
{
	if (!bounce_pkt)
		return;

	if (channel->primary_channel)
		channel = channel->primary_channel;

	hv_copy_from_bounce(bounce_pkt);
	hv_bounce_resources_release(channel, bounce_pkt);
}
EXPORT_SYMBOL_GPL(hv_pkt_bounce);

int hv_init_channel_ivm(struct vmbus_channel *channel)
{
	if (!hv_partition_is_isolated())
		return 0;

	/*
	 * Now bounce bufferes are allocated in the primary
	 * channel. Will change to per-channel allocation when
	 * IVM SMP support is available.
	 */
	if (channel->primary_channel)
		return 0;

	INIT_DELAYED_WORK(&channel->bounce_page_list_maintain,
			  hv_bounce_page_list_maintain);

	INIT_LIST_HEAD(&channel->bounce_page_free_head);
	INIT_LIST_HEAD(&channel->bounce_pkt_free_list_head);

	channel->bounce_pkt_cache = KMEM_CACHE(hv_bounce_pkt, 0);
	if (unlikely(!channel->bounce_pkt_cache))
		return -ENOMEM;
	channel->bounce_page_cache = KMEM_CACHE(hv_bounce_page_list, 0);
	if (unlikely(!channel->bounce_page_cache))
		return -ENOMEM;
	/* By default, no bounce resources are allocated */
	BUILD_BUG_ON(HV_DEFAULT_BOUNCE_BUFFER_PAGES);
	return 0;
}

void hv_free_channel_ivm(struct vmbus_channel *channel)
{
	if (!hv_partition_is_isolated())
		return;

	cancel_delayed_work_sync(&channel->bounce_page_list_maintain);

	if (channel->primary_channel)
		return;

	hv_bounce_pkt_list_free(channel, &channel->bounce_pkt_free_list_head);
	hv_bounce_page_list_free(channel, &channel->bounce_page_free_head);
	kmem_cache_destroy(channel->bounce_pkt_cache);
	kmem_cache_destroy(channel->bounce_page_cache);
}
