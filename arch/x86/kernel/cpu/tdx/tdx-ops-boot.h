/* SPDX-License-Identifier: GPL-2.0-only */
/* C-wrapper function for TDX SEAMCALL */
#ifndef __TDX_OPS_BOOT_H
#define __TDX_OPS_BOOT_H

static inline u64 tdh_sys_key_config(void)
{
	return seamcall_boot(SEAMCALL_TDH_SYS_KEY_CONFIG, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_sys_info(u64 tdsysinfo, int nr_bytes, u64 cmr_info,
			       int nr_cmr_entries, struct tdx_ex_ret *ex)
{
	return seamcall_boot(SEAMCALL_TDH_SYS_INFO, tdsysinfo, nr_bytes,
			     cmr_info, nr_cmr_entries, ex);
}

static inline u64 tdh_sys_init(u64 attributes, struct tdx_ex_ret *ex)
{
	return seamcall_boot(SEAMCALL_TDH_SYS_INIT, attributes, 0, 0, 0, ex);
}

static inline u64 tdh_sys_lp_init(struct tdx_ex_ret *ex)
{
	return seamcall_boot(SEAMCALL_TDH_SYS_LP_INIT, 0, 0, 0, 0, ex);
}

static inline u64 tdh_sys_tdmr_init(u64 tdmr, struct tdx_ex_ret *ex)
{
	return seamcall_boot(SEAMCALL_TDH_SYS_TDMR_INIT, tdmr, 0, 0, 0, ex);
}

/*
 * Rename TDH_SYS_CONFIG that is defined in TDX module spec to
 * tdh_sys_tdmr_config because the original name is misleading.  It configures
 * TDMRs to use and global private HKID.
 */
static inline u64 tdh_sys_tdmr_config(hpa_t tdmr, int nr_entries, int hkid)
{
	return seamcall_boot(SEAMCALL_TDH_SYS_CONFIG, tdmr, nr_entries, hkid, 0,
			     NULL);
}

static inline u64 tdh_trace_seamcalls_boot(u64 level)
{
	u64 err = 0;

	if (is_debug_seamcall_available) {
		err = seamcall_boot(SEAMCALL_TDDEBUGCONFIG,
				    DEBUGCONFIG_SET_TRACE_LEVEL, level, 0, 0,
				    NULL);
		if (err == TDX_OPERAND_INVALID) {
			pr_warn("TDX module doesn't support DEBUG TRACE SEAMCALL API\n");
			is_debug_seamcall_available = false;
		} else if (err) {
			pr_err_ratelimited("SEAMCALL[TDDBUTCONFIG] failed on cpu %d: %s (0x%llx)\n",
					   smp_processor_id(),
					   tdx_seamcall_error_name(err), err);
		}
	}

	return err;
}

static inline void tdxmode_boot(bool intercept_vmexits, u64 intercept_bitmap)
{
	u64 err;

	if (is_nonarch_seamcall_available) {
		err = seamcall_boot(SEAMCALL_TDXMODE, intercept_vmexits,
				    intercept_bitmap, 0, 0, NULL);
		if (err == TDX_OPERAND_INVALID) {
			pr_warn("TDX module doesn't support NON-ARCH SEAMCALL API\n");
			is_nonarch_seamcall_available = false;
		} else if (err) {
			pr_err_ratelimited("SEAMCALL[TDXMODE] failed on cpu %d: %s (0x%llx)\n",
					   smp_processor_id(),
					   tdx_seamcall_error_name(err), err);
		}
	}
}

#endif /* __TDX_OPS_BOOT_H */
