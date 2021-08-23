// SPDX-License-Identifier: GPL-2.0
/* Load and initialize TDX-module. */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/platform_device.h>
#include <linux/earlycpio.h>
#include <linux/kvm_types.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/init.h>

#include <asm/trace/seam.h>
#include <asm/cpufeature.h>
#include <asm/tdx_arch.h>
#include <asm/tdx_errno.h>
#include <asm/tdx_host.h>
#include <asm/virtext.h>
#include <asm/vmx.h>

#include "p-seamldr.h"
#include "tdmr-sysmem.h"
#include "seamcall-boot.h"
#include "tdx-ops-boot.h"
#include "p-seamldr.h"
#include "seam.h"
#include "tdx-tdmr.h"

/* ex is a pointer to struct tdx_ex_ret or NULL. */
#define TDX_ERR(err, op, ex)						\
({									\
	u64 __ret_warn_on = WARN_ON_ONCE(err);				\
									\
	if (unlikely(__ret_warn_on)) {					\
		/* TODO: print error info */;				\
	}								\
	__ret_warn_on;							\
})

static char tdx_module_name[128] __initdata = "intel-seam/libtdx.so";
static char tdx_sigstruct_name[128] __initdata = "intel-seam/libtdx.so.sigstruct";

static int __init setup_tdx_module(char *str)
{
	strscpy(tdx_module_name, str, sizeof(tdx_module_name));
	return 1;
}
__setup("tdx_module", setup_tdx_module);

static int __init setup_tdx_sigstruct(char *str)
{
	strscpy(tdx_sigstruct_name, str, sizeof(tdx_sigstruct_name));
	return 1;
}
__setup("tdx_sigstruct", setup_tdx_sigstruct);

/*
 * runtime update of TDX module is future task.  Track state of TDX module as
 * preliminary and export the state via sysfs for admin.
 */
enum TDX_MODULE_STATE {
	TDX_MODULE_NOT_LOADED = 0,
	/*
	 * TDX module is loaded into SEAM region.  Not functional yet until
	 * initialization is done.
	 */
	TDX_MODULE_LOADED,
	/* Initialization is done so that TDX module is functional. */
	TDX_MODULE_INITIALIZED,
	/*
	 * No SEAMCALLs are allowed so that TDX module is not functional.  It's
	 * ready for P-SEAMLDR to update TDX module.
	 */
	TDX_MODULE_SHUTDOWN,
	/* Something went wrong.  System reboot would be needed to fix it. */
	TDX_MODULE_ERROR,
};

static enum TDX_MODULE_STATE tdx_module_state __ro_after_init;

/*
 * is_tdx_module_enabled - check if TDX module is loaded and initialized so that
 *                         it's functional.
 * @return: true if TDX module is loaded and initialized.  false otherwise.
 */
bool is_tdx_module_enabled(void)
{
	return tdx_module_state == TDX_MODULE_INITIALIZED;
}
EXPORT_SYMBOL_GPL(is_tdx_module_enabled);	/* kvm_intel will use this. */

/* TDX system information returned by TDH_SYS_INFO. */
static struct tdsysinfo_struct *tdx_tdsysinfo;

/*
 * Return pointer to TDX system info (TDSYSINFO_STRUCT) if TDX has been
 * successfully initialized, or NULL.
 */
const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	return tdx_tdsysinfo;
}
EXPORT_SYMBOL_GPL(tdx_get_sysinfo);	/* kvm_intel will use this. */

/* CMR info array returned by TDH_SYS_INFO. */
static struct cmr_info *tdx_cmrs __initdata;
static int tdx_nr_cmrs __initdata;

/* KeyID range reserved to TDX by BIOS */
u32 tdx_keyids_start __read_mostly;
EXPORT_SYMBOL_GPL(tdx_keyids_start);	/* kvm_intel will use this. */
u32 tdx_nr_keyids __read_mostly;
EXPORT_SYMBOL_GPL(tdx_nr_keyids);	/* kvm_intel will use this. */
u32 tdx_seam_keyid __read_mostly;
EXPORT_SYMBOL_GPL(tdx_seam_keyid);	/* kvm_intel will use this. */

static void __init tdx_get_keyids(u32 *keyids_start, u32 *nr_keyids)
{
	u32 nr_mktme_ids;

	rdmsr(MSR_IA32_MKTME_KEYID_PART, nr_mktme_ids, *nr_keyids);

	/* KeyID 0 is reserved, i.e. KeyIDs are 1-based. */
	*keyids_start = nr_mktme_ids + 1;
}

/*
 * TDH_SYS_CONFIG requires that struct tdsysinfo_struct and the array of struct
 * cmr_info have the alignment of TDX_TDSYSINFO_STRUCT_ALIGNEMNT(1024) and
 * TDX_CMR_INFO_ARRAY_ALIGNMENT(512).
 * sizeof(struct tdsysinfo_struct) = 1024
 * sizeof(struct cmr_info) * TDX_MAX_NR_CMRS = 512
 *
 * NOTE: kmalloc() returns size-aligned when size of power of 2.
 */
static int __init tdx_sys_info_alloc(struct tdsysinfo_struct **tdsysinfo,
				     struct cmr_info **cmrs)
{
	BUILD_BUG_ON(!is_power_of_2(sizeof(**tdsysinfo)));
	BUILD_BUG_ON(!IS_ALIGNED(sizeof(**tdsysinfo),
				 TDX_TDSYSINFO_STRUCT_ALIGNEMNT));
	BUILD_BUG_ON(!is_power_of_2(sizeof(**cmrs) * TDX_MAX_NR_CMRS));
	BUILD_BUG_ON(!IS_ALIGNED(sizeof(**cmrs) * TDX_MAX_NR_CMRS,
				 TDX_CMR_INFO_ARRAY_ALIGNMENT));

	*tdsysinfo = kzalloc(sizeof(**tdsysinfo), GFP_KERNEL);
	*cmrs = kzalloc(sizeof(**cmrs) * TDX_MAX_NR_CMRS,
			GFP_KERNEL | __GFP_ZERO);
	if (!*tdsysinfo || !*cmrs) {
		kfree(*tdsysinfo);
		kfree(*cmrs);
		*tdsysinfo = NULL;
		*cmrs = NULL;
		return -ENOMEM;
	}
	return 0;
}

/*
 * free_seamldr_params - free allocated for seamldr_params including referenced
 *			 pages by params.
 * @params: virtual address of struct seamldr_params to free
 */
static void __init free_seamldr_params(struct seamldr_params *params)
{
	int i;

	for (i = 0; i < params->num_module_pages; i++)
		free_page((unsigned long)__va(params->mod_pages_pa_list[i]));
	free_page((unsigned long)__va(params->sigstruct_pa));
	free_page((unsigned long)params);
}

/*
 * alloc_seamldr_params - initialize parameters for P-SEAMLDR to load TDX module.
 * @module: virtual address of TDX module.
 * @module_size: size of module.
 * @sigstruct: virtual address of sigstruct of TDX module.
 * @sigstruct_size: size of sigstruct of TDX module.
 * @scenario: SEAMLDR_SCENARIO_LOAD or SEAMLDR_SCENARIO_UPDATE.
 * @return: pointer to struct seamldr_params on success, error code on failure.
 *
 * Allocate and initialize struct seamldr_params for P-SEAMLDR to load TDX
 * module.  Memory for seamldr_params and members is required to be 4K
 * page-aligned.  Use free_seamldr_params() to free allocated pages including
 * referenced by params.
 */
static struct seamldr_params * __init alloc_seamldr_params(
	const void *module, unsigned long module_size, const void *sigstruct,
	unsigned long sigstruct_size, u64 scenario)
{
	struct seamldr_params *params = NULL;
	void *sigstruct_page = NULL;
	void *module_page = NULL;
	int i;

	/*
	 * SEAM module must be equal or less than
	 * SEAMLDR_MAX_NR_MODULE_PAGES(496) pages.
	 */
	if (!module_size ||
	    module_size > SEAMLDR_MAX_NR_MODULE_PAGES * PAGE_SIZE) {
		pr_err("Invalid SEAM module size 0x%lx\n", module_size);
		return ERR_PTR(-EINVAL);
	}
	/*
	 * SEAM signature structure must be SEAMLDR_SIGSTRUCT_SIZE(2048) bytes.
	 */
	if (sigstruct_size != SEAMLDR_SIGSTRUCT_SIZE) {
		pr_err("Invalid SEAM signature structure size 0x%lx\n",
		       sigstruct_size);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * Allocate and initialize the SEAMLDR params.  Pages are passed in as
	 * a list of physical addresses.
	 */
	params = (struct seamldr_params *)__get_free_page(GFP_KERNEL |
							  __GFP_ZERO);
	if (!params) {
		pr_err("Unable to allocate memory for SEAMLDR_PARAMS\n");
		goto out;
	}
	params->scenario = scenario;

	/* SEAMLDR requires the sigstruct to be 4K aligned. */
	BUILD_BUG_ON(SEAMLDR_SIGSTRUCT_SIZE > PAGE_SIZE);
	sigstruct_page = (void *)__get_free_page(GFP_KERNEL);
	if (!sigstruct_page) {
		pr_err("Unable to allocate memory to copy sigstruct\n");
		goto out;
	}
	memcpy(sigstruct_page, sigstruct, sigstruct_size);
	params->sigstruct_pa = __pa(sigstruct_page);

	params->num_module_pages = PFN_UP(module_size);
	for (i = 0; i < params->num_module_pages; i++) {
		module_page = (void *)__get_free_page(GFP_KERNEL);
		if (!module_page) {
			pr_err("Unable to allocate memory to copy SEAM module\n");
			goto out;
		}
		params->mod_pages_pa_list[i] = __pa(module_page);
		memcpy(module_page, module + i * PAGE_SIZE,
		       min(module_size, PAGE_SIZE));
		if (module_size < PAGE_SIZE)
			memset(module_page + module_size, 0,
			       PAGE_SIZE - module_size);
		module_size -= PAGE_SIZE;
	}

	return params;

out:
	free_seamldr_params(params);
	return ERR_PTR(-ENOMEM);
}

struct tdx_load_module_data {
	struct seamldr_params *params;
	atomic_t error;
};

/* Load seam module on one CPU */
static void __init tdx_load_module_cpu(void *data)
{
	struct tdx_load_module_data *load_module = data;
	int ret = seamldr_install(__pa(load_module->params));

	if (ret)
		atomic_set(&load_module->error, ret);
}

/*
 * tdx_get_system_info - early system wide initialization of TDX module to store
 *                       TDX system information into the following variables.
 *                       tdx_keyid_start, tdx_nr_keyids, tdx_tdsysinfo,
 *                       tdx_cmrs and tdx_nr_cmrs.
 *
 * @return: 0 on success, error code on failure.
 *
 * Does system wide initialization of TDX module and get info about system. i.e.
 * info about TDX module and Convertible Memory Regions(CMRs).
 */
static int __init tdx_get_system_info(void)
{
	struct tdx_ex_ret ex_ret;
	int err;
	int i;

	/*
	 * Ensure one cpu calls tdx_get_system_info().  Thread migration may lead to
	 * a CPU tries to initialize TDX module twice and another CPU does
	 * nothing.
	 */
	get_cpu();

	/*
	 * Detect HKID for TDX if initialization was successful.
	 *
	 * TDX provides core-scoped MSR for us to simply read out TDX start
	 * keyID and number of keyIDs.
	 */
	tdx_get_keyids(&tdx_keyids_start, &tdx_nr_keyids);
	if (!tdx_nr_keyids) {
		err = -EOPNOTSUPP;
		goto out;
	}

	/* tdh_sys_info() requires special alignment. */
	if (!IS_ALIGNED((unsigned long)tdx_tdsysinfo,
			TDX_TDSYSINFO_STRUCT_ALIGNEMNT) ||
	    !IS_ALIGNED((unsigned long)tdx_cmrs, TDX_CMR_INFO_ARRAY_ALIGNMENT)) {
		err = -EINVAL;
		goto out;
	}

	/* System wide initialization for TDX module. */
	err = tdh_sys_init(0, &ex_ret);
	if (TDX_ERR(err, TDH_SYS_INIT, &ex_ret)) {
		err = -EIO;
		goto out;
	}

	/*
	 * tdh_sys_info() below requires that LP is initialized for TDX module.
	 * Otherwise it results in an error, TDX_SYSINITLP_NOT_DONE.
	 */
	err = tdh_sys_lp_init(&ex_ret);
	if (TDX_ERR(err, TDH_SYS_LP_INIT, &ex_ret)) {
		err = -EIO;
		goto out;
	}

	/*
	 * Invoke TDH_SYS_INFO to collect the information needed to construct
	 * TDMRs.
	 */
	err = tdh_sys_info(__pa(tdx_tdsysinfo), sizeof(*tdx_tdsysinfo),
			   __pa(tdx_cmrs), TDX_MAX_NR_CMRS, &ex_ret);
	if (TDX_ERR(err, TDH_SYS_INFO, &ex_ret)) {
		err = -EIO;
		goto out;
	}

	/*
	 * ex_ret.nr_cmr_entries is how many entries TDX module writes.  It may
	 * contain 0-size entries at the end.  Count non 0-size entries.
	 */
	tdx_nr_cmrs = 0;
	for (i = 0; i < ex_ret.nr_cmr_entries; i++) {
		if (!tdx_cmrs[i].size)
			break;
		tdx_nr_cmrs++;
	}

	/*
	 * Sanity check TDSYSINFO.  TDX module should have the architectural
	 * values in TDX spec.
	 */
	if (((tdx_tdsysinfo->max_reserved_per_tdmr != TDX_MAX_NR_RSVD_AREAS) ||
		(tdx_tdsysinfo->max_tdmrs != TDX_MAX_NR_TDMRS) ||
		(tdx_tdsysinfo->pamt_entry_size != TDX_PAMT_ENTRY_SIZE))) {
		pr_err("Invalid TDSYSINFO.  Disable TDX.\n");
		err = -EINVAL;
		goto out;
	}

	pr_info("TDX SEAM module: attributes 0x%x vendor_id 0x%x build_date %d "
		"build_num 0x%x minor_version 0x%x major_version 0x%x.\n",
		tdx_tdsysinfo->attributes, tdx_tdsysinfo->vendor_id,
		tdx_tdsysinfo->build_date, tdx_tdsysinfo->build_num,
		tdx_tdsysinfo->minor_version, tdx_tdsysinfo->major_version);

out:
	put_cpu();
	return err;
}

/*
 * tdx_load_module - load TDX module by P-SEAMLDR seam_install call.
 * @module: virtual address of TDX module.
 * @module_size: size of TDX module.
 * @sigstruct: virtual address of sigstruct of TDX module.
 * @sigstruct_size: size of sigstruct of TDX module.
 * @scenario: SEAMLDR_SCENARIO_LOAD or SEAMLDR_SCENARIO_UPDATE.
 * @return: 0 on success, error code on failure.
 *
 * load TDX module on all CPUs through P-SEAMLDR and does get system info about
 * TDX module.
 */
static int __init tdx_load_module(
	const void *module, unsigned long module_size, const void *sigstruct,
	unsigned long sigstruct_size, u64 scenario)
{
	struct seamldr_params *params;
	struct tdx_load_module_data load_module;
	int cpu;
	int ret = 0;

	params = alloc_seamldr_params(module, module_size, sigstruct,
				      sigstruct_size, scenario);
	if (IS_ERR(params))
		return -ENOMEM;

	/*
	 * Loading TDX module needs to involve seamldr_install() on all CPUs.
	 * Ensure all CPUs are online.  CPU lock isn't needed because it's not
	 * possible to offline CPUs while during kernel boot.  If this doesn't
	 * hold true in future, add cpu_maps_update_begin/done() and
	 * cpus_read_lock/unlock().
	 */
	if (!cpumask_equal(cpu_present_mask, cpu_online_mask)) {
		ret = -EINVAL;
		goto out;
	}

	load_module.params = params;
	atomic_set(&load_module.error, 0);
	/*
	 * Call the function on each CPUs one by one to avoid NMI watchdog.  If
	 * there are many CPUs, tdx_load_module_cpu() may contend with the
	 * spinlock of seamldr_install() for long time to trigger NMI watchdog.
	 */
	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, tdx_load_module_cpu,
					 &load_module, 1);
		ret = atomic_read(&load_module.error);
		if (ret)
			goto out;
	}

	ret = tdx_get_system_info();

out:
	free_seamldr_params(params);
	return ret;
}

/*
 * Look for seam module binary in built-in firmware and initrd, and load it on
 * all CPUs through P-SEAMLDR.
 * KASAN thinks memcpy from initrd image via cpio image invalid access.
 */
static int __init __no_sanitize_address tdx_init(void)
{
	struct cpio_data module, sigstruct;
	int ret = 0;
	int vmxoff;

	if (!boot_cpu_has(X86_FEATURE_SEAM))
		return 0;

	pr_info("Loading TDX module via P-SEAMLDR.\n");

	ret = -EINVAL;
	if (!seam_get_firmware(&module, tdx_module_name) ||
	    !seam_get_firmware(&sigstruct, tdx_sigstruct_name))
		goto out_free;

	ret = tdx_sys_info_alloc(&tdx_tdsysinfo, &tdx_cmrs);
	if (ret)
		goto out_free;

	cpu_maps_update_begin();
	cpus_read_lock();

	/*
	 * If P-SEAMLDR is not loaded, seamldr_install() will fail.  Don't check
	 * whether P-SEAMLDR is loaded before.
	 */
	WARN_ON(tdx_module_state != TDX_MODULE_NOT_LOADED);

	/* SEAMCALL requires to enable VMXON on CPUs. */
	ret = seam_alloc_vmcs();
	if (ret)
		goto out;
	ret = seam_init_vmcs();
	if (ret)
		goto out;
	ret = seam_vmxon();
	if (ret)
		goto out;

	/*
	 * Initialization of TDX module needs to involve all CPUs.  Ensure all
	 * CPUs are online.  All CPUs are required to be initialized by
	 * TDH.SYS.LP.INIT otherwise TDH.SYS.CONFIG fails.
	 */
	if (!cpumask_equal(cpu_present_mask, cpu_online_mask)) {
		ret = -EINVAL;
		goto out;
	}

	ret = tdx_load_module(module.data, module.size,
			      sigstruct.data, sigstruct.size,
			      SEAMLDR_SCENARIO_LOAD);
	if (ret) {
		pr_info("Failed to load TDX module.\n");
		goto out;
	}
	pr_info("Loaded TDX module via P-SEAMLDR.\n");
	tdx_module_state = TDX_MODULE_LOADED;

out:
	if (ret)
		tdx_module_state = TDX_MODULE_ERROR;

	vmxoff = seam_vmxoff();
	if (vmxoff) {
		pr_info("Failed to VMXOFF.\n");
		if (!ret)
			ret = vmxoff;
	}
	if (ret)
		tdx_module_state = TDX_MODULE_ERROR;
	cpus_read_unlock();
	cpu_maps_update_done();

out_free:
	seam_free_vmcs();
	return ret;
}
/*
 * sybsys_initcall_sync() is chosen to satisfy the following conditions.
 * - After P-SEAMLDR is loaded.
 * - After iomem_resouce is populated with System RAM including regions
 *   specified by memmap=nn[KMG]!ss[KMG].  which is done by
 *   e820_reserve_resources() called by setup_arch().  Because
 *   tdx_construct_tdmr() walks iomem resources looking for legacy pmem region.
 * - After build_sysmem_tdx_memory() by early_initcall().
 * - After reserved memory region is polulated in iomem_resource by
 *   e820__reserve_resources_late().  which is called by
 *   subsys_initcall(pci_subsys_init).
 * - After numa node is initialized by pgdata_init() and alloc_contig_pages() is
 *   available.
 * - Before kvm_intel.  module_init() which is mapped to device_initcall() when
 *   it's built into kernel.
 */
subsys_initcall_sync(tdx_init);

static int __init tdx_early_init(void)
{
	int ret;

	ret = load_p_seamldr();
	if (ret)
		return ret;

	ret = tdx_sysmem_build();

	return ret;
}
early_initcall(tdx_early_init);
