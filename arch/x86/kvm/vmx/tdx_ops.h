/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Constants/data definitions for TDX SEAMCALLs
 *
 * This file is included by "tdx.h" after declarations of 'struct
 * kvm_tdx' and 'struct vcpu_tdx'.  C file should never include
 * this header directly.
 */

#ifndef __KVM_X86_TDX_OPS_H
#define __KVM_X86_TDX_OPS_H

#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/tdx.h>

#include "x86.h"

#ifdef CONFIG_INTEL_TDX_HOST
void pr_tdx_error(u64 op, u64 error_code, const struct tdx_module_args *out);
#endif

static inline u64 tdh_mng_addcx(struct kvm_tdx *kvm_tdx, hpa_t addr)
{
	struct tdx_module_args in = {
		.rcx = addr,
		.rdx = kvm_tdx->tdr_pa,
	};

	clflush_cache_range(__va(addr), PAGE_SIZE);
	return seamcall(TDH_MNG_ADDCX, &in);
}

static inline u64 tdh_mem_page_add(struct kvm_tdx *kvm_tdx, gpa_t gpa,
				   hpa_t hpa, hpa_t source,
				   u64 *rcx, u64 *rdx)
{
	struct tdx_module_args in = {
		.rcx = gpa,
		.rdx = kvm_tdx->tdr_pa,
		.r8 = hpa,
		.r9 = source,
	};
	u64 ret;

	clflush_cache_range(__va(hpa), PAGE_SIZE);
	ret = seamcall_ret(TDH_MEM_PAGE_ADD, &in);

	*rcx = in.rcx;
	*rdx = in.rdx;

	return ret;
}

static inline u64 tdh_mem_sept_add(struct kvm_tdx *kvm_tdx, gpa_t gpa,
				   int level, hpa_t page,
				   u64 *rcx, u64 *rdx)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = kvm_tdx->tdr_pa,
		.r8 = page,
	};
	u64 ret;

	clflush_cache_range(__va(page), PAGE_SIZE);

	ret = seamcall_ret(TDH_MEM_SEPT_ADD, &in);

	*rcx = in.rcx;
	*rdx = in.rdx;

	return ret;
}

static inline u64 tdh_mem_sept_remove(struct kvm_tdx *kvm_tdx, gpa_t gpa,
				      int level, u64 *rcx, u64 *rdx)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = kvm_tdx->tdr_pa,
	};
	u64 ret;

	ret = seamcall_ret(TDH_MEM_SEPT_REMOVE, &in);

	*rcx = in.rcx;
	*rdx = in.rdx;

	return ret;
}

static inline u64 tdh_vp_addcx(struct vcpu_tdx *tdx, hpa_t addr)
{
	struct tdx_module_args in = {
		.rcx = addr,
		.rdx = tdx->tdvpr_pa,
	};

	clflush_cache_range(__va(addr), PAGE_SIZE);
	return seamcall(TDH_VP_ADDCX, &in);
}

static inline u64 tdh_mem_page_aug(struct kvm_tdx *kvm_tdx, gpa_t gpa, hpa_t hpa,
				   u64 *rcx, u64 *rdx)
{
	struct tdx_module_args in = {
		.rcx = gpa,
		.rdx = kvm_tdx->tdr_pa,
		.r8 = hpa,
	};
	u64 ret;

	clflush_cache_range(__va(hpa), PAGE_SIZE);
	ret = seamcall_ret(TDH_MEM_PAGE_AUG, &in);

	*rcx = in.rcx;
	*rdx = in.rdx;

	return ret;
}

static inline u64 tdh_mem_range_block(struct kvm_tdx *kvm_tdx, gpa_t gpa,
				      int level, u64 *rcx, u64 *rdx)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = kvm_tdx->tdr_pa,
	};
	u64 ret;

	ret = seamcall_ret(TDH_MEM_RANGE_BLOCK, &in);

	*rcx = in.rcx;
	*rdx = in.rdx;

	return ret;
}

static inline u64 tdh_mng_key_config(struct kvm_tdx *kvm_tdx)
{
	struct tdx_module_args in = {
		.rcx = kvm_tdx->tdr_pa,
	};

	return seamcall(TDH_MNG_KEY_CONFIG, &in);
}

static inline u64 tdh_mng_create(struct kvm_tdx *kvm_tdx, int hkid)
{
	struct tdx_module_args in = {
		.rcx = kvm_tdx->tdr_pa,
		.rdx = hkid,
	};

	clflush_cache_range(__va(kvm_tdx->tdr_pa), PAGE_SIZE);
	return seamcall(TDH_MNG_CREATE, &in);
}

static inline u64 tdh_vp_create(struct vcpu_tdx *tdx)
{
	struct tdx_module_args in = {
		.rcx = tdx->tdvpr_pa,
		.rdx = to_kvm_tdx(tdx->vcpu.kvm)->tdr_pa,
	};

	clflush_cache_range(__va(tdx->tdvpr_pa), PAGE_SIZE);
	return seamcall(TDH_VP_CREATE, &in);
}

static inline u64 tdh_mng_rd(struct kvm_tdx *kvm_tdx, u64 field, u64 *data)
{
	struct tdx_module_args in = {
		.rcx = kvm_tdx->tdr_pa,
		.rdx = field,
	};
	u64 ret;

	ret = seamcall_ret(TDH_MNG_RD, &in);

	*data = in.r8;

	return ret;
}

static inline u64 tdh_mr_extend(struct kvm_tdx *kvm_tdx, gpa_t gpa,
				u64 *rcx, u64 *rdx)
{
	struct tdx_module_args in = {
		.rcx = gpa,
		.rdx = kvm_tdx->tdr_pa,
	};
	u64 ret;

	ret = seamcall_ret(TDH_MR_EXTEND, &in);

	*rcx = in.rcx;
	*rdx = in.rdx;

	return ret;
}

static inline u64 tdh_mr_finalize(struct kvm_tdx *kvm_tdx)
{
	struct tdx_module_args in = {
		.rcx = kvm_tdx->tdr_pa,
	};

	return seamcall(TDH_MR_FINALIZE, &in);
}

static inline u64 tdh_vp_flush(struct vcpu_tdx *tdx)
{
	struct tdx_module_args in = {
		.rcx = tdx->tdvpr_pa,
	};

	return seamcall(TDH_VP_FLUSH, &in);
}

static inline u64 tdh_mng_vpflushdone(struct kvm_tdx *kvm_tdx)
{
	struct tdx_module_args in = {
		.rcx = kvm_tdx->tdr_pa,
	};

	return seamcall(TDH_MNG_VPFLUSHDONE, &in);
}

static inline u64 tdh_mng_key_freeid(struct kvm_tdx *kvm_tdx)
{
	struct tdx_module_args in = {
		.rcx = kvm_tdx->tdr_pa,
	};

	return seamcall(TDH_MNG_KEY_FREEID, &in);
}

static inline u64 tdh_mng_init(struct kvm_tdx *kvm_tdx, hpa_t td_params,
			       u64 *rcx)
{
	struct tdx_module_args in = {
		.rcx = kvm_tdx->tdr_pa,
		.rdx = td_params,
	};
	u64 ret;

	ret = seamcall_ret(TDH_MNG_INIT, &in);

	*rcx = in.rcx;

	return ret;
}

static inline u64 tdh_vp_init(struct vcpu_tdx *tdx, u64 rcx)
{
	struct tdx_module_args in = {
		.rcx = tdx->tdvpr_pa,
		.rdx = rcx,
	};

	return seamcall(TDH_VP_INIT, &in);
}

static inline u64 tdh_vp_init_apicid(struct vcpu_tdx *tdx, u64 rcx, u32 x2apicid)
{
	struct tdx_module_args in = {
		.rcx = tdx->tdvpr_pa,
		.rdx = rcx,
		.r8 = x2apicid,
	};

	/* apicid requires version == 1. */
	return seamcall(TDH_VP_INIT | (1ULL << TDX_VERSION_SHIFT), &in);
}

static inline u64 tdh_vp_rd(struct vcpu_tdx *tdx, u64 field, u64 *data)
{
	struct tdx_module_args in = {
		.rcx = tdx->tdvpr_pa,
		.rdx = field,
	};
	u64 ret;

	ret = seamcall_ret(TDH_VP_RD, &in);

	*data = in.r8;

	return ret;
}

static inline u64 tdh_mng_key_reclaimid(struct kvm_tdx *kvm_tdx)
{
	struct tdx_module_args in = {
		.rcx = kvm_tdx->tdr_pa,
	};

	return seamcall(TDH_MNG_KEY_RECLAIMID, &in);
}

static inline u64 tdh_phymem_page_reclaim(hpa_t page, u64 *rcx, u64 *rdx,
					  u64 *r8)
{
	struct tdx_module_args in = {
		.rcx = page,
	};
	u64 ret;

	ret = seamcall_ret(TDH_PHYMEM_PAGE_RECLAIM, &in);

	*rcx = in.rcx;
	*rdx = in.rdx;
	*r8 = in.r8;

	return ret;
}

static inline u64 tdh_mem_page_remove(struct kvm_tdx *kvm_tdx, gpa_t gpa,
				      int level, u64 *rcx, u64 *rdx)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = kvm_tdx->tdr_pa,
	};
	u64 ret;

	ret = seamcall_ret(TDH_MEM_PAGE_REMOVE, &in);

	*rcx = in.rcx;
	*rdx = in.rdx;

	return ret;
}

static inline u64 tdh_mem_track(struct kvm_tdx *kvm_tdx)
{
	struct tdx_module_args in = {
		.rcx = kvm_tdx->tdr_pa,
	};

	return seamcall(TDH_MEM_TRACK, &in);
}

static inline u64 tdh_mem_range_unblock(struct kvm_tdx *kvm_tdx, gpa_t gpa,
					int level, u64 *rcx, u64 *rdx)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = kvm_tdx->tdr_pa,
	};
	u64 ret;

	ret = seamcall_ret(TDH_MEM_RANGE_UNBLOCK, &in);

	*rcx = in.rcx;
	*rdx = in.rdx;

	return ret;
}

static inline u64 tdh_phymem_cache_wb(bool resume)
{
	struct tdx_module_args in = {
		.rcx = resume ? 1 : 0,
	};

	return seamcall(TDH_PHYMEM_CACHE_WB, &in);
}

static inline u64 tdh_phymem_page_wbinvd(hpa_t page)
{
	struct tdx_module_args in = {
		.rcx = page,
	};

	return seamcall(TDH_PHYMEM_PAGE_WBINVD, &in);
}

static inline u64 tdh_vp_wr(struct vcpu_tdx *tdx, u64 field, u64 val, u64 mask)
{
	struct tdx_module_args in = {
		.rcx = tdx->tdvpr_pa,
		.rdx = field,
		.r8 = val,
		.r9 = mask,
	};

	return seamcall(TDH_VP_WR, &in);
}

#endif /* __KVM_X86_TDX_OPS_H */
