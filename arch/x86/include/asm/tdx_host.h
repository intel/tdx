/* SPDX-License-Identifier: GPL-2.0 */
/* constants/data definitions for TDX host */

#ifndef __ASM_X86_TDX_HOST_H
#define __ASM_X86_TDX_HOST_H

#ifdef CONFIG_INTEL_TDX_HOST

void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
			const struct tdx_ex_ret *ex_ret);
void pr_seamcall_error(u64 op, u64 error_code, const struct tdx_ex_ret *ex_ret);
#else
struct tdx_ex_ret;
static inline void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
					const struct tdx_ex_ret *ex_ret)
{
}

static inline void pr_seamcall_error(u64 op, u64 error_code,
				const struct tdx_ex_ret *ex_ret)
{
}
#endif

#endif /* __ASM_X86_TDX_HOST_H */
