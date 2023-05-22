// SPDX-License-Identifier: GPL-2.0
#include <linux/anon_inodes.h>
#include <linux/kvm_host.h>

struct tdx_mig_mbmd_data {
	__u16 size;
	__u16 mig_version;
	__u16 migs_index;
	__u8  mb_type;
	__u8  rsvd0;
	__u32 mb_counter;
	__u32 mig_epoch;
	__u64 iv_counter;
	__u8  type_specific_info[];
} __packed;

struct tdx_mig_mbmd {
	struct tdx_mig_mbmd_data *data;
	uint64_t addr_and_size;
};

#define TDX_MIG_EPOCH_START_TOKEN 0xffffffff

/*
 * The buffer list specifies a list of 4KB pages to be used by TDH_EXPORT_MEM
 * and TDH_IMPORT_MEM to export and import guest memory pages. Each entry
 * is 64-bit and points to a physical address of a 4KB page used as buffer. The
 * list itself is a 4KB page, so it can hold up to 512 entries.
 */
union tdx_mig_buf_list_entry {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 12;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 11;
		uint64_t invalid	: 1;
	};
};

struct tdx_mig_buf_list {
	union tdx_mig_buf_list_entry *entries;
	hpa_t hpa;
};

/*
 * The page list specifies a list of 4KB pages to be used by the non-memory
 * states export and import, i.e. TDH_EXPORT_STATE_* and TDH_IMPORT_STATE_*.
 * Each entry is 64-bit and specifies the physical address of a 4KB buffer.
 * The list itself is a 4KB page, so it can hold up to 512 entries.
 */
union tdx_mig_page_list_info {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 12;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 3;
		uint64_t last_entry	: 9;
	};
};

struct tdx_mig_page_list {
	hpa_t *entries;
	union tdx_mig_page_list_info info;
};

/* TODO: check physical_mask */
#define TDX_SPTE_PFN_MASK 0xffffffffff000

union tdx_mig_gpa_list_entry {
	uint64_t val;
	struct{
		uint64_t level          : 2;   // Bits 1:0  :  Mapping level
		uint64_t pending        : 1;   // Bit 2     :  Page is pending
		uint64_t reserved_0     : 4;   // Bits 6:3
		uint64_t l2_map         : 3;   // Bits 9:7  :  L2 mapping flags
		uint64_t mig_type       : 2;   // Bits 11:10:  Migration type
		uint64_t gfn            : 40;  // Bits 51:12
#define GPA_LIST_OP_NOP		0
#define GPA_LIST_OP_EXPORT	1
#define GPA_LIST_OP_CANCEL	2
		uint64_t operation      : 2;   // Bits 53:52
		uint64_t reserved_1     : 2;   // Bits 55:54
#define GPA_LIST_S_SUCCESS	0
		uint64_t status         : 5;   // Bits 56:52
		uint64_t reserved_2     : 3;   // Bits 63:61
	};
};

#define TDX_MIG_GPA_LIST_MAX_ENTRIES \
	(PAGE_SIZE / sizeof(union tdx_mig_gpa_list_entry))

/*
 * The GPA list specifies a list of GPAs to be used by TDH_EXPORT_MEM and
 * TDH_IMPORT_MEM, TDH_EXPORT_BLOCKW, and TDH_EXPORT_RESTORE. The list itself
 * is 4KB, so it can hold up to 512 such 64-bit entries.
 */
union tdx_mig_gpa_list_info {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 3;
		uint64_t first_entry	: 9;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 3;
		uint64_t last_entry	: 9;
	};
};

struct tdx_mig_gpa_list {
	union tdx_mig_gpa_list_entry *entries;
	union tdx_mig_gpa_list_info info;
};

/*
 * A MAC list specifies a list of MACs over 4KB migrated pages and their GPA
 * entries. It is used by TDH_EXPORT_MEM and TDH_IMPORT_MEM. Each entry is
 * 128-bit containing a single AES-GMAC-256 of a migrated page. The list itself
 * is a 4KB page, so it can hold up to 256 entries. To support the export and
 * import of 512 pages, two such MAC lists are needed to be passed to the TDX
 * module.
 */
struct tdx_mig_mac_list {
	void *entries;
	hpa_t hpa;
};

/* Secure EPT mapping info used by TDH_EXPORT_UNBLOCKW */
union tdx_mig_ept_info {
	uint64_t val;
	struct {
		uint64_t level	: 3;
		uint64_t rsvd1	: 9;
		uint64_t gfn	: 40;
		uint64_t rsvd2	: 12;
	};
};

union tdx_mig_stream_info {
	uint64_t val;
	struct {
		uint64_t index	: 16;
		uint64_t rsvd	: 47;
		uint64_t resume	: 1;
	};
	struct {
		uint64_t rsvd1	  : 63;
		uint64_t in_order : 1;
	};
};

struct tdx_mig_stream {
	uint16_t idx;
	uint32_t buf_list_pages;
	struct tdx_mig_mbmd mbmd;
	/* List of buffers to export/import the TD private memory data */
	struct tdx_mig_buf_list mem_buf_list;
	/* List of buffers to export/miport the TD non-memory state data */
	struct tdx_mig_page_list page_list;
	/* List of GPA entries used when export/import the TD private memory */
	struct tdx_mig_gpa_list gpa_list;
	/* List of MACs used when export/import the TD private memory */
	struct tdx_mig_mac_list mac_list[2];
	/* List of TD private pages */
	struct tdx_mig_buf_list td_buf_list;
	/*
	 * List of buffers grabbed either from the private_fd allocated pages
	 * for in-place import or from mem_buf_list for non-in-place import.
	 */
	struct tdx_mig_buf_list import_mem_buf_list;
	gfn_t import_gfns[TDX_MIG_GPA_LIST_MAX_ENTRIES];
	uint64_t import_sptes[TDX_MIG_GPA_LIST_MAX_ENTRIES];
	/*
	 * Bitmap to get if a gpa in the gpa_list to import needs first-time
	 * import, i.e. the leaf entry has not been set up in sept tables.
	 * Support up to 512 pages in a batch.
	 */
	uint64_t first_time_import_bitmap[8];
};

struct tdx_mig_state {
	/* Number of streams created */
	atomic_t streams_created;
	/*
	 * Array to store physical addresses of the migration stream context
	 * pages that have been added to the TDX module. The pages can be
	 * reclaimed from TDX when TD is torn down.
	 */
	hpa_t *migsc_paddrs;
	struct tdx_mig_gpa_list blockw_gpa_list;
	struct tdx_mig_stream *default_stream;
	/* Backward stream used on migration abort during post-copy */
	struct tdx_mig_stream backward_stream;
	hpa_t backward_migsc_paddr;
	bool bugged;
	/* Index of the next vCPU to export the state */
	uint32_t vcpu_export_next_idx;
};

struct tdx_mig_capabilities {
	uint32_t max_migs;
	uint32_t nonmem_state_pages;
};

static struct tdx_mig_capabilities tdx_mig_caps;

static void tdx_reclaim_td_page(unsigned long td_page_pa);
static void tdx_track(struct kvm *kvm);
static int tdx_td_post_init(struct kvm_tdx *kvm_tdx);
static void tdx_flush_vp_on_cpu(struct kvm_vcpu *vcpu);
static void tdx_add_vcpu_association(struct vcpu_tdx *tdx, int cpu);
static int tdx_td_vcpu_setup(struct kvm_vcpu *vcpu);
static void tdx_td_vcpu_post_init(struct vcpu_tdx *tdx);

static bool tdx_is_migration_source(struct kvm_tdx *kvm_tdx);

static int tdx_mig_capabilities_setup(void)
{
	struct tdx_module_args out;
	uint32_t immutable_state_pages, td_state_pages, vp_state_pages;
	uint64_t err;

	err = tdh_sys_rd(TDX_MD_FID_MAX_MIGS, &out);
	if (err)
		return -EIO;
	tdx_mig_caps.max_migs = out.r8;
	/*
	 * At least two migration streams (forward stream + backward stream)
	 * are required to be created.
	 */
	if (unlikely(tdx_mig_caps.max_migs < 2))
		return -EOPNOTSUPP;

	err = tdh_sys_rd(TDX_MD_FID_IMMUTABLE_STATE_PAGES, &out);
	if (err)
		return -EIO;
	immutable_state_pages = out.r8;

	err = tdh_sys_rd(TDX_MD_FID_TD_STATE_PAGES, &out);
	if (err)
		return -EIO;
	td_state_pages = out.r8;

	err = tdh_sys_rd(TDX_MD_FID_VP_STATE_PAGES, &out);
	if (err)
		return -EIO;
	vp_state_pages = out.r8;

	/*
	 * The minimal number of pages required. It hould be large enough to
	 * store all the non-memory states.
	 */
	tdx_mig_caps.nonmem_state_pages = max3(immutable_state_pages,
					       td_state_pages, vp_state_pages);

	return 0;
}

static void tdx_mig_gpa_list_init(struct tdx_mig_gpa_list *gpa_list,
				  gfn_t *gfns, uint32_t num)
{
	uint32_t i;

	memset(gpa_list->entries, 0, PAGE_SIZE);
	for (i = 0; i < num; i++) {
		gpa_list->entries[i].gfn = gfns[i];
		/*
		 * 0 is noop.
		 * 1 is to perform an operation on the GPA, e.g. BLOCKW for
		 * TDH_EXPORT_BLOCKW, RESTORE for TDH_EXPORT_RESTORE.
		 */
		gpa_list->entries[i].operation = 1;
	}

	gpa_list->info.first_entry = 0;
	gpa_list->info.last_entry = num - 1;
}

static void tdx_write_block_private_pages(struct kvm *kvm, gfn_t *gfns,
					  uint32_t num)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_mig_gpa_list *gpa_list = &kvm_tdx->mig_state->blockw_gpa_list;
	uint32_t max_num = PAGE_SIZE / sizeof(union tdx_mig_gpa_list_entry);
	uint32_t start, blockw_num = 0;
	struct tdx_module_args out;
	uint64_t err;

	for (start = 0; start < num; start += blockw_num) {
		if (num > max_num)
			blockw_num = max_num;
		else
			blockw_num = num;

		tdx_mig_gpa_list_init(gpa_list, gfns + start, blockw_num);
		do {
			err = tdh_export_blockw(kvm_tdx->tdr_pa,
						gpa_list->info.val, &out);
			if (seamcall_masked_status(err) ==
						TDX_INTERRUPTED_RESUMABLE)
				gpa_list->info.val = out.rcx;
		} while (seamcall_masked_status(err) ==
						TDX_INTERRUPTED_RESUMABLE);

		if (seamcall_masked_status(err) != TDX_SUCCESS) {
			kvm_tdx->mig_state->bugged = true;
			pr_err("%s failed, err=%llx, gfn=%lx\n",
				__func__, err, (long)gpa_list->entries[0].gfn);
			return;
		}
	}

	/* Request for tdx_track as the W bit gets removed */
	smp_store_release(&kvm_tdx->has_range_blocked, true);
}

static void tdx_write_unblock_private_page(struct kvm *kvm,
					  gfn_t gfn, int level)
{
	struct tdx_module_args out;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	union tdx_mig_ept_info ept_info = {
		/*
		 * TDX treats level 0 as the leaf level, while Linux treats
		 * level 1 (PG_LEVEL_4K) as the level.
		 */
		.level = pg_level_to_tdx_sept_level(level),
		.rsvd1 = 0,
		.gfn = gfn,
		.rsvd2 = 0,
	};
	uint64_t err;

	tdx_track(kvm);

	err = tdh_export_unblockw(kvm_tdx->tdr_pa, ept_info.val, &out);
	if (err != TDX_SUCCESS) {
		kvm_tdx->mig_state->bugged = true;
		pr_err("%s failed, err=%llx, gfn=%llx\n", __func__, err, gfn);
	}
}

static void tdx_mig_stream_get_tdx_mig_attr(struct tdx_mig_stream *stream,
					    struct kvm_dev_tdx_mig_attr *attr)
{
	attr->version = KVM_DEV_TDX_MIG_ATTR_VERSION;
	attr->max_migs = tdx_mig_caps.max_migs;
	attr->buf_list_pages = stream->buf_list_pages;
}

static int tdx_mig_stream_get_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	struct tdx_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;

	switch (attr->group) {
	case KVM_DEV_TDX_MIG_ATTR: {
		struct kvm_dev_tdx_mig_attr tdx_mig_attr;

		if (attr->attr != sizeof(struct kvm_dev_tdx_mig_attr)) {
			pr_err("Incompatible kvm_dev_get_tdx_mig_attr\n");
			return -EINVAL;
		}

		tdx_mig_stream_get_tdx_mig_attr(stream, &tdx_mig_attr);
		if (copy_to_user(uaddr, &tdx_mig_attr, sizeof(tdx_mig_attr)))
			return -EFAULT;
		break;
	}
	default:
		return -EINVAL;
	}

	return 0;
}

static int tdx_mig_stream_set_tdx_mig_attr(struct tdx_mig_stream *stream,
					   struct kvm_dev_tdx_mig_attr *attr)
{
	uint32_t req_pages = attr->buf_list_pages;
	uint32_t min_pages = tdx_mig_caps.nonmem_state_pages;

	if (req_pages > TDX_MIG_BUF_LIST_PAGES_MAX) {
		stream->buf_list_pages = TDX_MIG_BUF_LIST_PAGES_MAX;
		pr_warn("Cut the buf_list_npages to the max supported num\n");
	} else if (req_pages < min_pages) {
		stream->buf_list_pages = min_pages;
	} else {
		stream->buf_list_pages = req_pages;
	}

	return 0;
}

static int tdx_mig_stream_mbmd_setup(struct tdx_mig_mbmd *mbmd)
{
	struct page *page;
	unsigned long mbmd_size = PAGE_SIZE;
	int order = get_order(mbmd_size);

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, order);
	if (!page)
		return -ENOMEM;

	mbmd->data = page_address(page);
	/*
	 * MBMD address and size format defined in TDX module ABI spec:
	 * Bits 63:52 - size of the MBMD buffer
	 * Bits 51:0  - host physical page frame number of the MBMD buffer
	 */
	mbmd->addr_and_size = page_to_phys(page) | (mbmd_size - 1) << 52;

	return 0;
}

static void tdx_mig_stream_buf_list_cleanup(struct tdx_mig_buf_list *buf_list)
{
	int i;
	kvm_pfn_t pfn;
	struct page *page;

	if (!buf_list->entries)
		return;

	for (i = 0; i < 512; i++) {
		pfn = buf_list->entries[i].pfn;
		if (!pfn)
			break;
		page = pfn_to_page(pfn);
		__free_page(page);
	}
	free_page((unsigned long)buf_list->entries);
}

static int tdx_mig_stream_buf_list_alloc(struct tdx_mig_buf_list *buf_list)
{
	struct page *page;

	/*
	 * Allocate the buf list page, which has 512 entries pointing to up to
	 * 512 pages used as buffers to export/import migration data.
	 */
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	buf_list->entries = page_address(page);
	buf_list->hpa = page_to_phys(page);

	return 0;
}

static int tdx_mig_stream_buf_list_setup(struct tdx_mig_buf_list *buf_list,
					 uint32_t npages)
{
	int i;
	struct page *page;

	if (!npages) {
		pr_err("Userspace should set_attr on the device first\n");
		return -EINVAL;
	}

	if (tdx_mig_stream_buf_list_alloc(buf_list))
		return -ENOMEM;

	for (i = 0; i < npages; i++) {
		page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!page) {
			tdx_mig_stream_buf_list_cleanup(buf_list);
			return -ENOMEM;
		}
		buf_list->entries[i].pfn = page_to_pfn(page);
	}

	/* Mark unused entries as invalid */
	for (i = npages; i < 512; i++)
		buf_list->entries[i].invalid = true;

	return 0;
}

static int
tdx_mig_stream_page_list_setup(struct tdx_mig_page_list *page_list,
			       struct tdx_mig_buf_list *buf_list,
			       uint32_t npages)
{
	struct page *page;
	uint32_t i;

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, 0);
	if (!page)
		return -ENOMEM;

	page_list->entries = page_address(page);
	page_list->info.pfn = page_to_pfn(page);

	/* Reuse the buffers from the buffer list for pages list */
	for (i = 0; i < npages; i++)
		page_list->entries[i] = PFN_PHYS(buf_list->entries[i].pfn);

	page_list->info.last_entry = npages - 1;

	return 0;
}

static int tdx_mig_stream_gpa_list_setup(struct tdx_mig_gpa_list *gpa_list)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	gpa_list->info.pfn = page_to_pfn(page);
	gpa_list->entries = page_address(page);

	return 0;
}

static int tdx_mig_stream_mac_list_setup(struct tdx_mig_mac_list *mac_list)
{
	struct page *page;

	page = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, 0);
	if (!page)
		return -ENOMEM;

	mac_list->entries = page_address(page);
	mac_list->hpa = page_to_phys(page);

	return 0;
}

static int tdx_mig_stream_setup(struct tdx_mig_stream *stream, bool is_src)
{
	int ret;

	ret = tdx_mig_stream_mbmd_setup(&stream->mbmd);
	if (ret)
		goto err_mbmd;

	ret = tdx_mig_stream_buf_list_setup(&stream->mem_buf_list,
					    stream->buf_list_pages);
	if (ret)
		goto err_mem_buf_list;

	ret = tdx_mig_stream_page_list_setup(&stream->page_list,
					     &stream->mem_buf_list,
					     stream->buf_list_pages);
	if (ret)
		goto err_page_list;

	ret = tdx_mig_stream_gpa_list_setup(&stream->gpa_list);
	if (ret)
		goto err_gpa_list;

	ret = tdx_mig_stream_mac_list_setup(&stream->mac_list[0]);
	if (ret)
		goto err_mac_list0;
	/*
	 * The 2nd mac list is needed only when the buf list uses more than
	 * 256 entries
	 */
	if (stream->buf_list_pages > 256) {
		ret = tdx_mig_stream_mac_list_setup(&stream->mac_list[1]);
		if (ret)
			goto err_mac_list1;
	}

	/* The lists used by the destination TD only */
	if (!is_src) {
		ret = tdx_mig_stream_buf_list_alloc(&stream->td_buf_list);
		if (ret)
			goto err_td_buf_list;
		ret = tdx_mig_stream_buf_list_alloc(&stream->import_mem_buf_list);
		if (ret)
			goto err_import_mem_buf_list;
	}

	return 0;
err_import_mem_buf_list:
	free_page((unsigned long)stream->td_buf_list.entries);
err_td_buf_list:
	if (stream->mac_list[1].entries)
		free_page((unsigned long)stream->mac_list[1].entries);
err_mac_list1:
	free_page((unsigned long)stream->mac_list[0].entries);
err_mac_list0:
	free_page((unsigned long)stream->gpa_list.entries);
err_gpa_list:
	free_page((unsigned long)stream->page_list.entries);
err_page_list:
	tdx_mig_stream_buf_list_cleanup(&stream->mem_buf_list);
err_mem_buf_list:
	free_page((unsigned long)stream->mbmd.data);
err_mbmd:
	pr_err("%s failed\n", __func__);
	return ret;
}

static int tdx_mig_stream_set_attr(struct kvm_device *dev,
				   struct kvm_device_attr *attr)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_stream *stream = dev->private;
	u64 __user *uaddr = (u64 __user *)(long)attr->addr;
	int ret;

	switch (attr->group) {
	case KVM_DEV_TDX_MIG_ATTR: {
		struct kvm_dev_tdx_mig_attr tdx_mig_attr;

		if (copy_from_user(&tdx_mig_attr, uaddr, sizeof(tdx_mig_attr)))
			return -EFAULT;

		if (tdx_mig_attr.version != KVM_DEV_TDX_MIG_ATTR_VERSION)
			return -EINVAL;

		ret = tdx_mig_stream_set_tdx_mig_attr(stream, &tdx_mig_attr);
		if (ret)
			break;

		ret = tdx_mig_stream_setup(stream,
					   tdx_is_migration_source(kvm_tdx));
		break;
	}
	default:
		return -EINVAL;
	}

	return ret;
}

static bool tdx_mig_stream_in_mig_buf_list(uint32_t i, uint32_t max_pages)
{
	if (i >= TDX_MIG_STREAM_BUF_LIST_MAP_OFFSET &&
	    i < TDX_MIG_STREAM_BUF_LIST_MAP_OFFSET + max_pages)
		return true;

	return false;
}

static vm_fault_t tdx_mig_stream_fault(struct vm_fault *vmf)
{
	struct kvm_device *dev = vmf->vma->vm_file->private_data;
	struct tdx_mig_stream *stream = dev->private;
	struct page *page;
	kvm_pfn_t pfn;
	uint32_t i;

	/* See linear_page_index for pgoff */
	if (vmf->pgoff == TDX_MIG_STREAM_MBMD_MAP_OFFSET) {
		page = virt_to_page(stream->mbmd.data);
	} else if (vmf->pgoff == TDX_MIG_STREAM_GPA_LIST_MAP_OFFSET) {
		page = virt_to_page(stream->gpa_list.entries);
	} else if (vmf->pgoff == TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET ||
		   vmf->pgoff == TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET + 1) {
		i = vmf->pgoff - TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET;
		if (stream->mac_list[i].entries) {
			page = virt_to_page(stream->mac_list[i].entries);
		} else {
			pr_err("%s: mac list page %d not allocated\n",
				__func__, i);
			return VM_FAULT_SIGBUS;
		}
	} else if (tdx_mig_stream_in_mig_buf_list(vmf->pgoff,
						  stream->buf_list_pages)) {
		i = vmf->pgoff - TDX_MIG_STREAM_BUF_LIST_MAP_OFFSET;
		pfn = stream->mem_buf_list.entries[i].pfn;
		page = pfn_to_page(pfn);
	} else {
		pr_err("%s: VM_FAULT_SIGBUS\n", __func__);
		return VM_FAULT_SIGBUS;
	}

	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct tdx_mig_stream_ops = {
	.fault = tdx_mig_stream_fault,
};

static int tdx_mig_stream_mmap(struct kvm_device *dev,
			       struct vm_area_struct *vma)
{
	vma->vm_ops = &tdx_mig_stream_ops;

	return 0;
}

static int tdx_mig_export_state_immutable(struct kvm_tdx *kvm_tdx,
					  struct tdx_mig_stream *stream,
					  uint64_t __user *data)
{
	struct tdx_mig_page_list *page_list = &stream->page_list;
	union tdx_mig_stream_info stream_info = {.val = 0};
	struct tdx_module_args out;
	uint64_t err;

	do {
		err = tdh_export_state_immutable(kvm_tdx->tdr_pa,
						 stream->mbmd.addr_and_size,
						 page_list->info.val,
						 stream_info.val,
						 &out);
		if (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE)
			stream_info.resume = 1;
	} while (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE);

	if (err == TDX_SUCCESS) {
		stream->idx = stream->mbmd.data->migs_index;
		/* Tell userspace the num of exported 4KB pages */
		if (copy_to_user(data, &out.rdx, sizeof(uint64_t)))
			return -EFAULT;
	} else {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_import_state_immutable(struct kvm_tdx *kvm_tdx,
					  struct tdx_mig_stream *stream,
					  uint64_t __user *data)
{
	struct tdx_mig_page_list *page_list = &stream->page_list;
	union tdx_mig_stream_info stream_info = {.val = 0};
	struct tdx_module_args out;
	uint64_t err, npages;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	page_list->info.last_entry = npages - 1;
	do {
		err = tdh_import_state_immutable(kvm_tdx->tdr_pa,
						 stream->mbmd.addr_and_size,
						 page_list->info.val,
						 stream_info.val,
						 &out);
		if (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE)
			stream_info.resume = 1;
	} while (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE);

	if (err == TDX_SUCCESS) {
		stream->idx = stream->mbmd.data->migs_index;
	} else {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	return kvm_prealloc_private_pages(&kvm_tdx->kvm, true);
}

static void tdx_mig_buf_list_set_valid(struct tdx_mig_buf_list *mem_buf_list,
				       uint64_t num)
{
	int i;

	for (i = 0; i < num; i++)
		mem_buf_list->entries[i].invalid = false;

	for (i = num; i < 512; i++) {
		if (!mem_buf_list->entries[i].invalid)
			mem_buf_list->entries[i].invalid = true;
		else
			break;
	}
}

static void tdx_mig_handle_export_mem_error(struct kvm *kvm,
					    struct tdx_mig_gpa_list *gpa_list,
					    uint64_t npages)
{
	union tdx_mig_gpa_list_entry *entry;
	uint64_t i;

	for (i = 0; i < npages; i++) {
		entry = &gpa_list->entries[i];
		/*
		 * Re-migrate the failed entries by putting them back to the
		 * dirty bitmap.
		 */
		if (entry->status != GPA_LIST_S_SUCCESS)
			mark_page_dirty(kvm, (gfn_t)entry->gfn);
	}
}

static int64_t tdx_mig_stream_export_mem(struct kvm_tdx *kvm_tdx,
					 struct tdx_mig_stream *stream,
					 uint64_t __user *data)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	struct tdx_mig_gpa_list *gpa_list = &stream->gpa_list;
	struct tdx_mig_buf_list *mem_buf_list = &stream->mem_buf_list;
	union tdx_mig_stream_info stream_info = {.val = 0};
	struct tdx_module_args out;
	uint64_t npages, err;

	if (mig_state->bugged)
		return -EBADF;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	if (npages > stream->buf_list_pages)
		return -EINVAL;

	/*
	 * The gpa list page is shared to userspace to fill GPAs directly.
	 * Only need to update the gpa_list info fields here.
	 */
	gpa_list->info.first_entry = 0;
	gpa_list->info.last_entry = npages - 1;
	tdx_mig_buf_list_set_valid(&stream->mem_buf_list, npages);

	stream_info.index = stream->idx;
	do {
		err = tdh_export_mem(kvm_tdx->tdr_pa,
				     stream->mbmd.addr_and_size,
				     gpa_list->info.val,
				     mem_buf_list->hpa,
				     stream->mac_list[0].hpa,
				     stream->mac_list[1].hpa,
				     stream_info.val,
				     &out);
		if (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE) {
			stream_info.resume = 1;
			/* Update the gpa_list_info (mainly first_entry) */
			gpa_list->info.val = out.rcx;
		}
	} while (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE);

	if (seamcall_masked_status(err) == TDX_SUCCESS) {
		/* A general success could have some entries failed */
		if (err != TDX_SUCCESS)
			tdx_mig_handle_export_mem_error(&kvm_tdx->kvm,
							gpa_list, npages);
		/*
		 * 1 for GPA list and 1 for MAC list
		 * TODO: Improve by checking GPA list entries
		 */
		out.rdx = out.rdx - 2;
		if (copy_to_user(data, &out.rdx, sizeof(uint64_t)))
			return -EFAULT;
	} else {
		pr_err("%s: err=%llx, gfn=%llx\n",
			__func__, err, (uint64_t)gpa_list->entries[0].gfn);
		return -EIO;
	}

	return 0;
}

static bool gpa_skip_import(union tdx_mig_gpa_list_entry *entry)
{
	return entry->operation == GPA_LIST_OP_NOP;
}

static bool gpa_cancel_import(union tdx_mig_gpa_list_entry *entry)
{
	return entry->operation == GPA_LIST_OP_CANCEL;
}

static void tdx_mig_mem_buf_copy(kvm_pfn_t to_pfn, kvm_pfn_t from_pfn)
{
	void *to_va =  __va(to_pfn << PAGE_SHIFT);
	void *from_va = __va(from_pfn << PAGE_SHIFT);

	memcpy(to_va, from_va, PAGE_SIZE);
}

static int import_mem_buf_init(struct kvm *kvm,
			       uint64_t *sptes,
			       uint64_t npages,
			       struct tdx_mig_gpa_list *gpa_list,
			       struct tdx_mig_buf_list *td_buf_list,
			       struct tdx_mig_buf_list *import_mem_buf_list,
			       struct tdx_mig_buf_list *mem_buf_list,
			       uint64_t *first_time_import_bitmap)
{
	int i;
	kvm_pfn_t pfn;
	union tdx_mig_buf_list_entry *td_buf_entries = td_buf_list->entries;
	union tdx_mig_buf_list_entry *import_mem_buf_entries =
						import_mem_buf_list->entries;
	union tdx_mig_buf_list_entry *mem_buf_entries = mem_buf_list->entries;
	union tdx_mig_gpa_list_entry *gpa_list_entry;

	for (i = 0; i < npages; i++) {
		if (!sptes[i])
			continue;

		gpa_list_entry = &gpa_list->entries[i];
		pfn = (sptes[i] & TDX_SPTE_PFN_MASK) >> PAGE_SHIFT;
		import_mem_buf_entries[i].invalid = false;
		if (test_bit_le(i, first_time_import_bitmap)) {
			if (gpa_list_entry->operation != GPA_LIST_OP_EXPORT) {
				pr_err("%s: unexpected, entry->operation=%d\n",
					__func__, gpa_list_entry->operation);
				return -EINVAL;
			}
			 /*
			  * First time import: copy data from shared memory to
			  * the restricted memory page that will be used as the
			  * TD private page with in-place import. According to
			  * the TDX ABI spec, the restricted mem page's pfn
			  * needs to be set to the related mem_buf_list entry
			  * for in-place import.
			  */
			tdx_mig_mem_buf_copy(pfn,
					(kvm_pfn_t)mem_buf_entries[i].pfn);
			import_mem_buf_entries[i].pfn = pfn;
			td_buf_entries[i].invalid = true;
		} else {
			import_mem_buf_entries[i].pfn = mem_buf_entries[i].pfn;
			td_buf_entries[i].pfn = pfn;
			td_buf_entries[i].invalid = false;
		}
	}

	/*
	 * Pages that skipped to import still need their GPA list entries to imported
	 */
	gpa_list->info.first_entry = 0;
	gpa_list->info.last_entry = npages - 1;

	/*
	 * TODO: remove if not necessary.
	 * TDX module checks GPA list for the end.
	 */
	if (i < TDX_MIG_BUF_LIST_PAGES_MAX) {
		td_buf_entries[i].invalid = true;
		mem_buf_entries[i].invalid = true;
	}

	return 0;
}

static int tdx_mig_stream_import_private_pages(struct kvm *kvm,
					       uint64_t *sptes,
					       uint64_t npages,
					       void *opaque)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_mig_stream *stream = (struct tdx_mig_stream *)opaque;
	struct tdx_mig_gpa_list *gpa_list = &stream->gpa_list;
	union tdx_mig_stream_info stream_info = {.val = 0};
	struct tdx_module_args out;
	uint64_t err;
	int ret;

	ret = import_mem_buf_init(kvm, sptes, npages, gpa_list,
				  &stream->td_buf_list,
				  &stream->import_mem_buf_list,
				  &stream->mem_buf_list,
				  stream->first_time_import_bitmap);
	if (ret)
		return ret;

	stream_info.index = stream->idx;
	do {
		err = tdh_import_mem(kvm_tdx->tdr_pa,
				     stream->mbmd.addr_and_size,
				     gpa_list->info.val,
				     stream->import_mem_buf_list.hpa,
				     stream->mac_list[0].hpa,
				     stream->mac_list[1].hpa,
				     stream->td_buf_list.hpa,
				     stream_info.val,
				     &out);
		if (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE) {
			stream_info.resume = 1;
			gpa_list->info.val = out.rcx;
		}
	} while (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE);

	if (err != TDX_SUCCESS) {
		pr_err("%s failed gfn=%llx, status=%d, err=%llx, npage=%lld\n",
			__func__, (gfn_t)gpa_list->entries[0].gfn,
			gpa_list->entries[0].status, err, npages);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_stream_import_mem(struct kvm_tdx *kvm_tdx,
				     struct tdx_mig_stream *stream,
				     uint64_t __user *data)
{
	int ret;
	uint64_t i, npages;
	gfn_t gfn;
	kvm_pfn_t pfn;
	struct kvm *kvm = &kvm_tdx->kvm;
	struct kvm_vcpu *vcpu = kvm_get_vcpu(kvm, 0);
	union tdx_mig_gpa_list_entry *gpa_list_entries =
						stream->gpa_list.entries;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	memset(stream->import_sptes, 0, npages * sizeof(uint64_t));
	for (i = 0; i < npages; i++) {
		if (gpa_skip_import(&gpa_list_entries[i])) {
			stream->import_gfns[i] = INVALID_GFN;
			continue;
		}

		gfn = (gfn_t)(gpa_list_entries[i].gfn);
		if (!gpa_cancel_import(&gpa_list_entries[i])) {
			ret = kvm_gmem_get_pfn(kvm, gfn_to_memslot(kvm, gfn),
					       gfn, &pfn, NULL);
			if (ret) {
				pr_err("%s: failed, ret=%d, i=%lld, gfn=%llx, npages=%lld\n",
					__func__, ret, i, gfn, npages);
				return -EIO;
			}
			stream->import_sptes[i] = (u64)pfn << PAGE_SHIFT | VMX_EPT_RWX_MASK |
					(MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT) |
					VMX_EPT_IPAT_BIT | VMX_EPT_SUPPRESS_VE_BIT;
		}

		stream->import_gfns[i] = gfn;
	}

	return kvm_mmu_import_private_pages(vcpu, stream->import_gfns,
					    stream->import_sptes, npages,
					    stream->first_time_import_bitmap,
					    stream);
}

static int tdx_mig_export_track(struct kvm_tdx *kvm_tdx,
				struct tdx_mig_stream *stream,
				uint64_t __user *data)
{
	union tdx_mig_stream_info stream_info = {.val = 0};
	uint64_t in_order, err;

	if (copy_from_user(&in_order, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	/*
	 * Set the in_order bit if userspace requests to generate a start
	 * token by sending a non-0 value through tdx_cmd.data.
	 */
	stream_info.in_order = !!in_order;
	err = tdh_export_track(kvm_tdx->tdr_pa,
			       stream->mbmd.addr_and_size, stream_info.val);
	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	return 0;
}

static inline bool
tdx_mig_epoch_is_start_token(struct tdx_mig_mbmd_data *data)
{
	return data->mig_epoch == TDX_MIG_EPOCH_START_TOKEN;
}

static int tdx_mig_import_track(struct kvm_tdx *kvm_tdx,
				struct tdx_mig_stream *stream)
{
	union tdx_mig_stream_info stream_info = {.val = 0};
	uint64_t err;

	err = tdh_import_track(kvm_tdx->tdr_pa,
			       stream->mbmd.addr_and_size, stream_info.val);
	if (err != TDX_SUCCESS) {
		pr_err("tdh_import_track failed, err=%llx\n", err);
		return -EIO;
	}

	if (tdx_mig_epoch_is_start_token(stream->mbmd.data)) {
		err = tdh_import_commit(kvm_tdx->tdr_pa);
		if (err != TDX_SUCCESS) {
			pr_err("tdh_import_commit failed, err=%llx\n", err);
			return -EIO;
		}

		kvm_tdx->finalized = true;
	}

	return 0;
}

static int tdx_mig_export_pause(struct kvm_tdx *kvm_tdx)
{
	uint64_t err;

	err = tdh_export_pasue(kvm_tdx->tdr_pa);
	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_export_state_td(struct kvm_tdx *kvm_tdx,
				   struct tdx_mig_stream *stream,
				   uint64_t __user *data)
{
	union tdx_mig_stream_info stream_info = {.val = 0};
	struct tdx_module_args out;
	uint64_t err;

	do {
		err = tdh_export_state_td(kvm_tdx->tdr_pa,
					  stream->mbmd.addr_and_size,
					  stream->page_list.info.val,
					  stream_info.val,
					  &out);
		if (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE)
			stream_info.resume = 1;
	} while (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE);

	if (err == TDX_SUCCESS) {
		if (copy_to_user(data, &out.rdx, sizeof(uint64_t)))
			return -EFAULT;
	} else {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	return 0;
}

static int tdx_mig_import_state_td(struct kvm_tdx *kvm_tdx,
				   struct tdx_mig_stream *stream,
				   uint64_t __user *data)
{
	struct tdx_mig_page_list *page_list = &stream->page_list;
	union tdx_mig_stream_info stream_info = {.val = 0};
	struct tdx_module_args out;
	uint64_t err, npages;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	page_list->info.last_entry = npages - 1;
	do {
		err = tdh_import_state_td(kvm_tdx->tdr_pa,
					  stream->mbmd.addr_and_size,
					  page_list->info.val,
					  stream_info.val,
					  &out);
		if (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE)
			stream_info.resume = 1;
	} while (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE);

	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	tdx_td_post_init(kvm_tdx);
	return 0;
}

static int tdx_mig_export_state_vp(struct kvm_tdx *kvm_tdx,
				   struct tdx_mig_stream *stream,
				   uint64_t __user *data)
{
	struct kvm *kvm = &kvm_tdx->kvm;
	struct kvm_vcpu *vcpu;
	struct vcpu_tdx *vcpu_tdx;
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	union tdx_mig_stream_info stream_info = {.val = 0};
	struct tdx_module_args out;
	uint64_t err;
	int cpu;

	if (mig_state->vcpu_export_next_idx >=
	    atomic_read(&kvm->online_vcpus)) {
		pr_err("%s: vcpu_export_next_idx %d >= online_vcpus %d\n",
			__func__, mig_state->vcpu_export_next_idx,
			atomic_read(&kvm->online_vcpus));
		return -EINVAL;
	}

	vcpu = kvm_get_vcpu(kvm, mig_state->vcpu_export_next_idx);
	vcpu_tdx = to_tdx(vcpu);
	tdx_flush_vp_on_cpu(vcpu);
	cpu = get_cpu();

	stream_info.index = stream->idx;
	do {
		err = tdh_export_state_vp(vcpu_tdx->tdvpr_pa,
					  stream->mbmd.addr_and_size,
					  stream->page_list.info.val,
					  stream_info.val,
					  &out);
		if (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE)
			stream_info.resume = 1;
	} while (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE);

	if (err == TDX_SUCCESS) {
		mig_state->vcpu_export_next_idx++;
		if (copy_to_user(data, &out.rdx, sizeof(uint64_t)))
			return -EFAULT;
	} else {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}
	tdx_add_vcpu_association(vcpu_tdx, cpu);
	vcpu->cpu = cpu;
	put_cpu();

	return 0;
}

static uint16_t tdx_mig_mbmd_get_vcpu_idx(struct tdx_mig_mbmd_data *data)
{
	return *(uint16_t *)data->type_specific_info;
}

static int tdx_mig_import_state_vp(struct kvm_tdx *kvm_tdx,
				   struct tdx_mig_stream *stream,
				   uint64_t __user *data)
{
	struct tdx_mig_page_list *page_list = &stream->page_list;
	union tdx_mig_stream_info stream_info = {.val = 0};
	struct tdx_module_args out;
	struct vcpu_tdx *vcpu_tdx;
	struct kvm_vcpu *vcpu;
	uint64_t err, npages;
	int cpu, vcpu_idx;

	if (copy_from_user(&npages, (void __user *)data, sizeof(uint64_t)))
		return -EFAULT;

	vcpu_idx = tdx_mig_mbmd_get_vcpu_idx(stream->mbmd.data);
	vcpu = kvm_get_vcpu(&kvm_tdx->kvm, vcpu_idx);
	vcpu_tdx = to_tdx(vcpu);

	page_list->info.last_entry = npages - 1;

	if (tdx_td_vcpu_setup(vcpu) < 0)
		return -EIO;

	tdx_flush_vp_on_cpu(vcpu);
	cpu = get_cpu();
	do {
		err = tdh_import_state_vp(vcpu_tdx->tdvpr_pa,
					  stream->mbmd.addr_and_size,
					  page_list->info.val,
					  stream_info.val,
					  &out);
		if (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE)
			stream_info.resume = 1;
	} while (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE);

	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		put_cpu();
		return -EIO;
	}

	tdx_add_vcpu_association(vcpu_tdx, cpu);
	vcpu->cpu = cpu;
	put_cpu();

	tdx_td_vcpu_post_init(vcpu_tdx);
	return 0;
}

static int tdx_restore_private_page(struct kvm *kvm, gfn_t gfn)
{
	uint64_t err;
	struct tdx_module_args out;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_mig_stream *stream = kvm_tdx->mig_state->default_stream;
	struct tdx_mig_gpa_list *gpa_list = &stream->gpa_list;

	tdx_mig_gpa_list_init(gpa_list, &gfn, 1);
	do {
		err = tdh_export_restore(kvm_tdx->tdr_pa,
					 gpa_list->info.val, &out);
		if (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE)
			gpa_list->info.val = out.rcx;
	} while (seamcall_masked_status(err) == TDX_INTERRUPTED_RESUMABLE);

	if (seamcall_masked_status(err) != TDX_SUCCESS) {
		pr_err("%s failed, err=%llx, gfn=%lx\n",
			__func__, err, (long)gpa_list->entries[0].gfn);
		return -EIO;
	} else if (gpa_list->entries[0].status != GPA_LIST_S_SUCCESS) {
		return -EPERM;
	}

	return 0;
}

static int tdx_mig_export_abort(struct kvm_tdx *kvm_tdx,
				struct tdx_mig_stream *stream,
				uint64_t __user *data)
{
	uint64_t err;

	err = tdh_export_abort(kvm_tdx->tdr_pa, 0, 0);
	if (err != TDX_SUCCESS)
		pr_err("%s: export abort failed, err=%llx\n", __func__, err);

	return kvm_tdp_mmu_restore_private_pages(&kvm_tdx->kvm);
}

static int tdx_mig_import_end(struct kvm_tdx *kvm_tdx)
{
	uint64_t err;

	err = tdh_import_end(kvm_tdx->tdr_pa);
	if (err != TDX_SUCCESS) {
		pr_err("%s: failed, err=%llx\n", __func__, err);
		return -EIO;
	}

	pr_info("migration flow is done, userspace pid %d\n",
		kvm_tdx->kvm.userspace_pid);

	return 0;
}

static long tdx_mig_stream_ioctl(struct kvm_device *dev, unsigned int ioctl,
				 unsigned long arg)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_stream *stream = dev->private;
	void __user *argp = (void __user *)arg;
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	switch (tdx_cmd.id) {
	case KVM_TDX_MIG_EXPORT_STATE_IMMUTABLE:
		r = tdx_mig_export_state_immutable(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_STATE_IMMUTABLE:
		r = tdx_mig_import_state_immutable(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_EXPORT_MEM:
		r = tdx_mig_stream_export_mem(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_MEM:
		r = tdx_mig_stream_import_mem(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_EXPORT_TRACK:
		r = tdx_mig_export_track(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_TRACK:
		r = tdx_mig_import_track(kvm_tdx, stream);
		break;
	case KVM_TDX_MIG_EXPORT_PAUSE:
		r = tdx_mig_export_pause(kvm_tdx);
		break;
	case KVM_TDX_MIG_EXPORT_STATE_TD:
		r = tdx_mig_export_state_td(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_STATE_TD:
		r = tdx_mig_import_state_td(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_EXPORT_STATE_VP:
		r = tdx_mig_export_state_vp(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_STATE_VP:
		r = tdx_mig_import_state_vp(kvm_tdx, stream,
					(uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_EXPORT_ABORT:
		r = tdx_mig_export_abort(kvm_tdx, stream,
					 (uint64_t __user *)tdx_cmd.data);
		break;
	case KVM_TDX_MIG_IMPORT_END:
		r = tdx_mig_import_end(kvm_tdx);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

static int tdx_mig_do_stream_create(struct kvm_tdx *kvm_tdx,
				    struct tdx_mig_stream *stream,
				    hpa_t *migsc_addr)
{
	struct tdx_module_args out;
	hpa_t migsc_va, migsc_pa;
	uint64_t err;

	/*
	 * This migration stream has been created, e.g. the previous migration
	 * session is aborted and the migration stream is retained during the
	 * TD guest lifecycle (required by the TDX migration architecture for
	 * later re-migration). No need to proceed to the creation in this
	 * case.
	 */
	if (*migsc_addr)
		return 0;

	migsc_va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!migsc_va)
		return -ENOMEM;
	migsc_pa = __pa(migsc_va);

	err = tdh_mig_stream_create(kvm_tdx->tdr_pa, migsc_pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MIG_STREAM_CREATE, err, &out);
		free_page(migsc_va);
		return -EIO;
	}

	*migsc_addr = migsc_pa;
	return 0;
}

static int tdx_mig_session_init(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	struct tdx_mig_gpa_list *blockw_gpa_list = &mig_state->blockw_gpa_list;
	int ret = 0;

	if (tdx_mig_do_stream_create(kvm_tdx, &mig_state->backward_stream,
				     &mig_state->backward_migsc_paddr))
		return -EIO;

	if (tdx_is_migration_source(kvm_tdx))
		ret = tdx_mig_stream_gpa_list_setup(blockw_gpa_list);

	return ret;
}

static void tdx_mig_session_exit(struct tdx_mig_state *mig_state)
{
	if (mig_state->blockw_gpa_list.entries)
		free_page((unsigned long)mig_state->blockw_gpa_list.entries);

	mig_state->default_stream = NULL;
}

static int tdx_mig_stream_create(struct kvm_device *dev, u32 type)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	struct tdx_mig_stream *stream;
	int ret;

	stream = kzalloc(sizeof(struct tdx_mig_stream), GFP_KERNEL_ACCOUNT);
	if (!stream)
		return -ENOMEM;

	dev->private = stream;
	stream->idx = atomic_inc_return(&mig_state->streams_created) - 1;

	if (!stream->idx) {
		ret = tdx_mig_session_init(kvm_tdx);
		if (ret)
			goto err_mig_session_init;

		WARN_ON_ONCE(mig_state->default_stream);
		mig_state->default_stream = stream;
	}

	ret = tdx_mig_do_stream_create(kvm_tdx, stream,
				       &mig_state->migsc_paddrs[stream->idx]);
	if (ret)
		goto err_stream_create;

	return 0;
err_stream_create:
	tdx_mig_session_exit(mig_state);
err_mig_session_init:
	atomic_dec(&mig_state->streams_created);
	kfree(stream);
	return ret;
}

static void tdx_mig_stream_release(struct kvm_device *dev)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(dev->kvm);
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	struct tdx_mig_stream *stream = dev->private;

	atomic_dec(&mig_state->streams_created);
	free_page((unsigned long)stream->mbmd.data);
	tdx_mig_stream_buf_list_cleanup(&stream->mem_buf_list);
	free_page((unsigned long)stream->page_list.entries);
	free_page((unsigned long)stream->gpa_list.entries);
	free_page((unsigned long)stream->mac_list[0].entries);
	/*
	 * The 2nd mac list page is allocated conditionally when
	 * stream->buf_list_pages is larger than 256.
	 */
	if (stream->mac_list[1].entries)
		free_page((unsigned long)stream->mac_list[1].entries);
	if (stream->td_buf_list.entries)
		free_page((unsigned long)stream->td_buf_list.entries);
	if (stream->import_mem_buf_list.entries)
		free_page((unsigned long)stream->import_mem_buf_list.entries);

	kfree(stream);

	if (!atomic_read(&mig_state->streams_created))
		tdx_mig_session_exit(mig_state);
}

static int tdx_mig_state_create(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	hpa_t *migsc_paddrs;

	mig_state = kzalloc(sizeof(struct tdx_mig_state), GFP_KERNEL_ACCOUNT);
	if (!mig_state)
		return -ENOMEM;

	migsc_paddrs = kcalloc(tdx_mig_caps.max_migs, sizeof(hpa_t),
			       GFP_KERNEL_ACCOUNT);
	if (!migsc_paddrs) {
		kfree(mig_state);
		return -ENOMEM;
	}

	mig_state->migsc_paddrs = migsc_paddrs;
	kvm_tdx->mig_state = mig_state;
	return 0;
}

static void tdx_mig_state_destroy(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	uint32_t i;

	if (!mig_state)
		return;

	/* All the streams should have been destroyed */
	WARN_ON_ONCE(atomic_read(&mig_state->streams_created));
	for (i = 0; i < tdx_mig_caps.max_migs; i++) {
		if (!mig_state->migsc_paddrs[i])
			break;

		tdx_reclaim_td_page(mig_state->migsc_paddrs[i]);
	}

	if (mig_state->backward_migsc_paddr)
		tdx_reclaim_td_page(mig_state->backward_migsc_paddr);

	kfree(mig_state);
	kvm_tdx->mig_state = NULL;
}

static struct kvm_device_ops kvm_tdx_mig_stream_ops = {
	.name = "kvm-tdx-mig",
	.get_attr = tdx_mig_stream_get_attr,
	.set_attr = tdx_mig_stream_set_attr,
	.mmap = tdx_mig_stream_mmap,
	.ioctl = tdx_mig_stream_ioctl,
	.create = tdx_mig_stream_create,
	.release = tdx_mig_stream_release,
};

static int kvm_tdx_mig_stream_ops_init(void)
{
	return kvm_register_device_ops(&kvm_tdx_mig_stream_ops,
				       KVM_DEV_TYPE_TDX_MIG_STREAM);
}

static void kvm_tdx_mig_stream_ops_exit(void)
{
	kvm_unregister_device_ops(KVM_DEV_TYPE_TDX_MIG_STREAM);
}
