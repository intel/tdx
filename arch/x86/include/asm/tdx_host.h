/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_TDX_HOST_H
#define _ASM_X86_TDX_HOST_H

#ifdef CONFIG_INTEL_TDX_HOST
bool is_tdx_module_enabled(void);

struct tdx_ex_ret;

const char *tdx_seamcall_error_name(u64 error_code);
void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
			     const struct tdx_ex_ret *ex_ret);

struct tdsysinfo_struct;
const struct tdsysinfo_struct *tdx_get_sysinfo(void);

int tdx_seamcall_on_each_pkg(int (*fn)(void *), void *param);

extern u32 tdx_keyids_start __read_mostly;
extern u32 tdx_nr_keyids __read_mostly;
extern u32 tdx_seam_keyid __read_mostly;

bool range_is_tdx_memory(phys_addr_t start, phys_addr_t end);
#else
static inline bool is_tdx_module_enabled(void)
{
	return false;
}

static inline const char *tdx_seamcall_error_name(u64 error_code)
{
	return NULL;
}

struct tdx_ex_ret;
static inline void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
					   const struct tdx_ex_ret *ex_ret)
{
}

struct tdsysinfo_struct;
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	return NULL;
}

static inline int tdx_seamcall_on_each_pkg(int (*fn)(void *), void *param)
{
	return 0;
}
#endif

#endif /* _ASM_X86_TDX_HOST_H */
