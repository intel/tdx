/* SPDX-License-Identifier: GPL-2.0 */
/* constants/data definitions for TDX host */

#ifndef __ASM_X86_TDX_HOST_H
#define __ASM_X86_TDX_HOST_H

#include <linux/notifier.h>

/*
 * Events that may happen to TDX module
 *
 * TDX_MODULE_LOAD_DONE event is sent to notifiers when TDX module becomes
 * ready to function. After receiving this event, users of TDX module can
 * start to interact with TDX module.
 * TDX_MODULE_LOAD_BEGIN event is sent to notifiers when TDX module driver
 * attempts to update TDX module. Users of TDX module can either return an
 * error in notifier callbacks to indicate that TDX module is in use, or
 * stop using TDX module until next TDX_MODULE_LOAD_DONE event.
 */
#define TDX_MODULE_LOAD_BEGIN	0 /* TDX module is about to go down */
#define TDX_MODULE_LOAD_DONE	1 /* TDX module is ready */

#ifdef CONFIG_INTEL_TDX_HOST
/*
 * TDX extended return:
 * Some of The "TDX module" SEAMCALLs return extended values (which are function
 * leaf specific) in registers in addition to the completion status code in
 * %rax.  For example, in the error case of TDH.SYS.INIT, the registers hold
 * more detailed information about the error in addition to an error code.  Note
 * that some registers may be unused depending on SEAMCALL functions.
 */
struct tdx_ex_ret {
	union {
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
			u64 r11;
		} regs;
		/*
		 * TDH_SYS_INFO returns the buffer address and its size, and the
		 * CMR_INFO address and its number of entries.
		 */
		struct {
			u64 buffer;
			u64 nr_bytes;
			u64 cmr_info;
			u64 nr_cmr_entries;
		} sys_info;
		/* TDH_SYS_TDMR_INIT returns the input PA and next PA. */
		struct {
			u64 prev;
			u64 next;
		} sys_tdmr_init;
		/* TDH_SYS_INIT returns CPUID info on error. */
		struct {
			u32 leaf;
			u32 subleaf;
			u32 eax_mask;
			u32 ebx_mask;
			u32 ecx_mask;
			u32 edx_mask;
			u32 eax_val;
			u32 ebx_val;
			u32 ecx_val;
			u32 edx_val;
		} sys_init;
		/* TDH_MNG_INIT returns CPUID info on error. */
		struct {
			u32 leaf;
			u32 subleaf;
		} mng_init;
		/* Functions that walk SEPT */
		struct {
			u64 septe;
			struct {
				u64 level		:3;
				u64 sept_reserved_0	:5;
				u64 state		:8;
				u64 sept_reserved_1	:48;
			};
		} sept_walk;
		/* TDH_MNG_{RD,WR} return the field value. */
		struct {
			u64 field_val;
		} mng_rdwr;
		/* TDH_MEM_{RD,WR} return the error info and value. */
		struct {
			u64 ext_err_info_1;
			u64 ext_err_info_2;
			u64 mem_val;
		} mem_rdwr;
		/* TDH_PHYMEM_PAGE_RDMD and TDH_PHYMEM_PAGE_RECLAIM return page metadata. */
		struct {
			u64 page_type;
			u64 owner;
			u64 page_size;
		} phymem_page_md;
	};
};

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

/* Debug configuration SEAMCALLs */
extern bool is_debug_seamcall_available __read_mostly;

/* Non-architectural configuration SEAMCALLs */
extern bool is_nonarch_seamcall_available __read_mostly;

int register_tdx_notifier(struct notifier_block *n);
int unregister_tdx_notifier(struct notifier_block *n);
#else
static inline const char *tdx_seamcall_error_name(u64 error_code)
{
	return "";
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

static inline bool range_is_tdx_memory(phys_addr_t start, phys_addr_t end)
{
	return false;
}

static inline int register_tdx_notifier(struct notifier_block *n)
{
	return -EOPNOTSUPP;
}
static inline int unregister_tdx_notifier(struct notifier_block *n)
{
	return -EOPNOTSUPP;
}
#endif

#endif /* __ASM_X86_TDX_HOST_H */
