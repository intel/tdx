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

static inline void pr_seamcall_error(u64 op, const char *op_str,
				       u64 err, struct tdx_ex_ret *ex)
{
	pr_err_ratelimited("SEAMCALL[%s] failed on cpu %d: %s (0x%llx)\n",
			   op_str, smp_processor_id(),
			   tdx_seamcall_error_name(err), err);
	if (ex)
		pr_seamcall_ex_ret_info(op, err, ex);
}

/* ex is a pointer to struct tdx_ex_ret or NULL. */
#define TDX_ERR(err, op, ex)						\
({									\
	u64 __ret_warn_on = WARN_ON_ONCE(err);				\
									\
	if (unlikely(__ret_warn_on))					\
		pr_seamcall_error(SEAMCALL_##op, #op, (err), (ex));	\
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

static bool trace_boot_seamcalls;

static int __init trace_seamcalls(char *s)
{
	trace_boot_seamcalls = true;
	return 1;
}
__setup("trace_boot_seamcalls", trace_seamcalls);

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

bool is_debug_seamcall_available __read_mostly = true;
EXPORT_SYMBOL_GPL(is_debug_seamcall_available);

bool is_nonarch_seamcall_available __read_mostly = true;
EXPORT_SYMBOL_GPL(is_nonarch_seamcall_available);

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

static DEFINE_MUTEX(tdx_module_mutex);

/*
 * tdx_module_lock - lock to protect state of seam module related stuff.
 *
 * Locking order is
 * cpu_maps_update_begin() -> cpus_read/write_lock() -> tdx_module_lock().
 * Note tdx_module_lock() can be gained by cpuhp callback which is triggered
 * under cpu lock.
 */
static void tdx_module_lock(void)
{
	mutex_lock(&tdx_module_mutex);
}

static void tdx_module_unlock(void)
{
	mutex_unlock(&tdx_module_mutex);
}

/* Array of all TDMR info array. */
static struct tdmr_info *tdmr_info_alloc __initdata;   /* pointer for kfree. */
static struct tdmr_info *tdmr_info __initdata; /* aligned to TDX_TDMR_INFO_ALIGNMENT. */
/* Number of actual TDMRs */
static int tdx_nr_tdmrs __initdata;

static int *tdx_package_masters __read_mostly;

static enum cpuhp_state cpuhp_state __read_mostly = CPUHP_INVALID;

static int tdx_starting_cpu(unsigned int cpu)
{
	int pkg = topology_physical_package_id(cpu);

	tdx_module_lock();
	/*
	 * If this package doesn't have a master CPU for IPI operation, use this
	 * CPU as package master.
	 */
	if (tdx_package_masters && tdx_package_masters[pkg] == -1)
		tdx_package_masters[pkg] = cpu;
	tdx_module_unlock();

	return 0;
}

static int tdx_dying_cpu(unsigned int cpu)
{
	int pkg = topology_physical_package_id(cpu);
	int other;

	tdx_module_lock();
	if (!tdx_package_masters || tdx_package_masters[pkg] != cpu)
		goto out;

	/*
	 * If offlining cpu that is used as package master, find other online
	 * cpu on this package.
	 */
	tdx_package_masters[pkg] = -1;
	for_each_online_cpu(other) {
		if (other == cpu)
			continue;
		if (topology_physical_package_id(other) != pkg)
			continue;

		tdx_package_masters[pkg] = other;
		break;
	}

out:
	wbinvd();
	tdx_module_unlock();
	return 0;
}

static int __init tdx_init_cpuhp(void)
{
	int ret;

	/* first initialization is done by init_package_masters later. */
	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "tdx/cpu:starting",
					tdx_starting_cpu, tdx_dying_cpu);
	if (ret >= 0)
		cpuhp_state = ret;
	return ret;
}

/*
 * Setup one-cpu-per-pkg array to do package-scoped SEAMCALLs. The array is
 * only necessary if there are multiple packages.
 */
static int __init init_package_masters(void)
{
	int cpu, pkg, nr_filled, nr_pkgs;

	nr_pkgs = topology_max_packages();
	if (nr_pkgs == 1)
		return 0;

	/* Already initialized. */
	if (tdx_package_masters)
		return 0;

	tdx_package_masters = kcalloc(nr_pkgs, sizeof(int), GFP_KERNEL);
	if (!tdx_package_masters)
		return -ENOMEM;

	memset(tdx_package_masters, -1, nr_pkgs * sizeof(int));

	nr_filled = 0;
	for_each_online_cpu(cpu) {
		pkg = topology_physical_package_id(cpu);
		if (tdx_package_masters[pkg] >= 0)
			continue;

		tdx_package_masters[pkg] = cpu;
		if (++nr_filled == nr_pkgs)
			break;
	}

	if (WARN_ON(nr_filled != nr_pkgs)) {
		kfree(tdx_package_masters);
		tdx_package_masters = NULL;
		return -EIO;
	}

	return 0;
}

/*
 * tdx_seamcall_on_each_pkg - run function on each packages.
 * @fn: function to be called on each packages in blocking manner.
 * @param: parameter for fn
 *
 * fn is called by workqueue context so that fn can block with mutex.
 * some TDX SEAMCALLs are required to run on all packages, not all CPUs.
 * e.g. tdh_sys_key_config, tdh_phymem_cache_wb.
 */
int tdx_seamcall_on_each_pkg(int (*fn)(void *), void *param)
{
	int ret, i;

	tdx_module_lock();
	if (!tdx_package_masters) {
		tdx_module_unlock();
		return fn(param);
	}

	ret = 0;
	for (i = 0; i < topology_max_packages(); i++) {
		if (tdx_package_masters[i] < 0)
			continue;

		ret = smp_call_on_cpu(tdx_package_masters[i], fn, param, 1);
		if (ret)
			break;
	}

	tdx_module_unlock();
	return ret;
}
/* kvm_intel will use this function to invoke SEAMCALL on each package. */
EXPORT_SYMBOL_GPL(tdx_seamcall_on_each_pkg);

static int __init tdx_init_lp(void)
{
	u32 keyids_start, nr_keyids;
	struct tdx_ex_ret ex_ret;
	u64 err;

	WARN_ON(!irqs_disabled());

	/*
	 * MSR_IA32_MKTME_KEYID_PART is core-scoped, disable TDX if this CPU's
	 * partitioning doesn't match the BSP's partitioning.
	 */
	tdx_get_keyids(&keyids_start, &nr_keyids);
	if (keyids_start != tdx_keyids_start || nr_keyids != tdx_nr_keyids) {
		pr_err("MKTME KeyID partioning inconsistent on CPU %u\n",
		       smp_processor_id());
		return -EIO;
	}

	err = tdh_sys_lp_init(&ex_ret);
	/*
	 * Because tdh_init_system() called tdh_sys_lp_init() already, it's
	 * possible that LP is already initialized.
	 */
	if (err != TDX_SYSINITLP_DONE && TDX_ERR(err, TDH_SYS_LP_INIT, &ex_ret))
		return err;

	return 0;
}

static void __init tdx_init_cpu(void *data)
{
	atomic_t *error = data;
	int ret = tdx_init_lp();

	if (ret)
		atomic_set(error, ret);
}

/*
 * Invoke TDH.SYS.LP.INIT on all CPUs to perform processor-wide initialization.
 */
static int __init tdx_init_cpus(void)
{
	atomic_t error;

	/* Call per-CPU initialization function on all CPUs. */
	atomic_set(&error, 0);
	on_each_cpu(tdx_init_cpu, &error, 1);
	return atomic_read(&error);
}

/* data structure for tdx_init_tdmrs() */
struct tdx_tdmr_init_data {
	struct mutex lock;
	int next_tdmr_index;
	int nr_initialized_tdmrs;
	int failed;
	int nr_completed;
	int nr_works;
	struct completion completion;
};

struct tdx_tdmr_init_request {
	struct work_struct work;
	struct tdx_tdmr_init_data *data;
};

/*
 * __tdx_init_tdmrs - worker to initialize TDMRs
 * @work: work_struct to work queue which embedded in tdx_tdmr_init_request.
 *
 * Get an uninitialized TDMR, initialize it and loop until all TDMRs are
 * initialized.
 */
static void __init __tdx_init_tdmrs(struct work_struct *work)
{
	struct tdx_tdmr_init_request *req = container_of(
		work, struct tdx_tdmr_init_request, work);
	struct tdx_tdmr_init_data *data = req->data;
	int i;
	u64 base, size;
	struct tdx_ex_ret ex_ret;
	u64 err = 0;
	bool completed;

	mutex_lock(&data->lock);
again:
	i = data->next_tdmr_index;
	while (i < tdx_nr_tdmrs) {
		data->next_tdmr_index++;
		base = tdmr_info[i].base;
		size = tdmr_info[i].size;

		do {
			/* Abort if a different CPU failed. */
			if (data->failed)
				goto out;

			mutex_unlock(&data->lock);
			err = tdh_sys_tdmr_init(base, &ex_ret);
			if (TDX_ERR(err, TDH_SYS_TDMR_INIT, &ex_ret)) {
				mutex_lock(&data->lock);
				err = -EIO;
				goto out;
			}
			cond_resched();
			mutex_lock(&data->lock);

			/*
			 * Note, "next" is simply an indicator, base is passed
			 * to TDH.SYS.TDMR.INIT on every iteration.
			 */
		} while (ex_ret.next < (base + size));

		data->nr_initialized_tdmrs++;
		goto again;
	}

out:
	if (err)
		data->failed++;
	data->nr_completed++;
	completed = (data->nr_completed == data->nr_works);
	mutex_unlock(&data->lock);

	if (completed)
		complete(&data->completion);
}

/*
 * tdx_init_tdmrs - Initializes TDMRs in parallel way.
 * @return: 0 on success, error code on failure.
 *
 * It may take long time to initialize TDMRs by TDH.SYS.TDMR.INIT that clears
 * Physical Address Metadata Table(PAMT) which is something similar to Linux
 * struct page.  Parallelize it to shorten boot time by work queue.
 */
static int __init tdx_init_tdmrs(void)
{
	int i;
	/*
	 * One TDMR can be initialized only by one thread.  No point to have
	 * threads more than the number of TDMRs.
	 */
	int nr_works = min_t(int, num_online_cpus(), tdx_nr_tdmrs);
	struct tdx_tdmr_init_data data = {
		.lock = __MUTEX_INITIALIZER(data.lock),
		.next_tdmr_index = 0,
		.nr_initialized_tdmrs = 0,
		.failed = 0,
		.nr_completed = 0,
		.nr_works = nr_works,
		.completion = COMPLETION_INITIALIZER_ONSTACK(data.completion),
	};

	struct tdx_tdmr_init_request *reqs = kcalloc(nr_works, sizeof(*reqs),
						     GFP_KERNEL);
	if (!reqs)
		return -ENOMEM;

	for (i = 0; i < nr_works; i++) {
		reqs[i].data = &data;
		INIT_WORK(&reqs[i].work, __tdx_init_tdmrs);
		queue_work(system_unbound_wq, &reqs[i].work);
	}
	wait_for_completion(&data.completion);

	kfree(reqs);
	mutex_lock(&data.lock);
	if (data.failed || data.nr_initialized_tdmrs < tdx_nr_tdmrs) {
		mutex_unlock(&data.lock);
		return -EIO;
	}
	mutex_unlock(&data.lock);
	return 0;
}

static int __init do_tdh_sys_key_config(void *param)
{
	u64 err;

	do {
		err = tdh_sys_key_config();
	} while (err == TDX_KEY_GENERATION_FAILED);
	if (TDX_ERR(err, TDH_SYS_KEY_CONFIG, NULL))
		return -EIO;

	return 0;
}

/*
 * __tdx_init_module - finial initialization of TDX module so that it can be
 *                     workable.
 */
static int __init __tdx_init_module(void)
{
	u64 *tdmr_addrs;
	u64 err;
	int ret = 0;
	int i;

	/*
	 * tdmr_addrs must be aligned to TDX_TDMR_ADDR_ALIGNMENT(512).
	 * kmalloc() returns size-aligned when size is power of 2.
	 */
	BUILD_BUG_ON(!is_power_of_2(sizeof(*tdmr_addrs) * TDX_MAX_NR_TDMRS));
	BUILD_BUG_ON(!IS_ALIGNED(sizeof(*tdmr_addrs) * TDX_MAX_NR_TDMRS,
				 TDX_TDMR_ADDR_ALIGNMENT));
	tdmr_addrs = kmalloc(sizeof(*tdmr_addrs) * TDX_MAX_NR_TDMRS, GFP_KERNEL);
	if (!tdmr_addrs)
		return -ENOMEM;

	for (i = 0; i < tdx_nr_tdmrs; i++)
		tdmr_addrs[i] = __pa(&tdmr_info[i]);

	/*
	 * tdh_sys_tdmr_config() calls TDH.SYS.CONFIG to tell TDX module about
	 * TDMRs, PAMTs and HKID for TDX module to use.  Use the first keyID as
	 * TDX-SEAM's global key.
	 */
	err = tdh_sys_tdmr_config(__pa(tdmr_addrs), tdx_nr_tdmrs,
				  tdx_keyids_start);
	if (TDX_ERR(err, TDH_SYS_CONFIG, NULL)) {
		ret = -EIO;
		goto out;
	}
	tdx_seam_keyid = tdx_keyids_start;

	/*
	 * Cache Flush is required as
	 * TDX module spec: Chapter 12 Intel TDX Module Lifecycle Table 12.1
	 */
	wbinvd_on_all_cpus();

	ret = tdx_seamcall_on_each_pkg(do_tdh_sys_key_config, NULL);
	if (ret)
		goto out;

	/*
	 * Detect if debug and non-arch seamcall available.
	 *
	 * Even though tracing level is ALL level by default, it needs to set
	 * it explicitly to check if debug seamcall available.
	 */
	if (trace_boot_seamcalls)
		tdh_trace_seamcalls_boot(DEBUGCONFIG_TRACE_ALL);
	else
		/*
		 * Tracing is on by default, disable it before INITTDMR which
		 * causes too many debug messages to take long time.
		 */
		tdh_trace_seamcalls_boot(DEBUGCONFIG_TRACE_CUSTOM);

	tdxmode_boot(false, 0);

	ret = tdx_init_tdmrs();
out:
	kfree(tdmr_addrs);
	return ret;
}

static int __init tdx_init_module(void)
{
	struct tdx_module_descriptor desc;
	size_t tdmr_info_size;
	int ret = 0;

	ret = tdx_init_cpuhp();
	if (ret < 0)
		goto out;

	ret = init_package_masters();
	if (ret)
		goto out;

	tdx_legacy_pmem_build();
	/*
	 * TDX memory for system memory has been built after loading P-SEAMLDR.
	 * All sub-types TDX memory are ready.  Built the final TDX memory.
	 */
	build_final_tdx_memory();

	/*
	 * tdmr_info must be aligned to TDX_TDMR_INFO_ALIGNMENT(512).
	 * NOTE: kmalloc() returns size-aligned when size of power of 2.
	 */
	tdmr_info_size = sizeof(*tdmr_info) * tdx_tdsysinfo->max_tdmrs;
	if (!is_power_of_2(tdmr_info_size) ||
	    !IS_ALIGNED(tdmr_info_size, TDX_TDMR_INFO_ALIGNMENT))
		tdmr_info_size += TDX_TDMR_INFO_ALIGNMENT;
	tdmr_info_alloc = kmalloc(tdmr_info_size, GFP_KERNEL);
	if (!tdmr_info_alloc) {
		ret = -ENOMEM;
		goto out;
	}
	tdmr_info = PTR_ALIGN(tdmr_info_alloc, TDX_TDMR_INFO_ALIGNMENT);

	/* clear the TDMR array */
	memset(tdmr_info, 0, tdmr_info_size);

	/* construct all TDMRs */
	desc.max_tdmr_num = tdx_tdsysinfo->max_tdmrs;
	desc.pamt_entry_size[TDX_PG_4K] = tdx_tdsysinfo->pamt_entry_size;
	desc.pamt_entry_size[TDX_PG_2M] = tdx_tdsysinfo->pamt_entry_size;
	desc.pamt_entry_size[TDX_PG_1G] = tdx_tdsysinfo->pamt_entry_size;
	desc.max_tdmr_rsvd_area_num = tdx_tdsysinfo->max_reserved_per_tdmr;

	ret = construct_tdx_tdmrs(tdx_cmrs, tdx_nr_cmrs, &desc, tdmr_info,
			&tdx_nr_tdmrs);
	if (ret)
		goto out;

	/* per-CPU initialization. */
	ret = tdx_init_cpus();
	if (ret)
		goto out;

	/* finial initialization to make TDX module workable. */
	ret = __tdx_init_module();
	if (ret)
		goto out;

out:
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
	int cpu;
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

	pr_info("Initializing TDX module.\n");
	ret = tdx_init_module();
	if (ret) {
		pr_info("Failed to initialize TDX module.\n");
		goto out;
	}
	pr_info("Initialized TDX module\n");
	tdx_module_state = TDX_MODULE_INITIALIZED;

out:
	vmxoff = seam_vmxoff();
	if (vmxoff) {
		pr_info("Failed to VMXOFF.\n");
		if (!ret)
			ret = vmxoff;
	}
	if (ret)
		tdx_module_state = TDX_MODULE_ERROR;
	if (tdx_module_state == TDX_MODULE_INITIALIZED) {
		setup_force_cpu_cap(X86_FEATURE_TDX);
		for_each_online_cpu(cpu)
			set_cpu_cap(&cpu_data(cpu), X86_FEATURE_TDX);
	}
	cpus_read_unlock();
	cpu_maps_update_done();

out_free:
	seam_free_vmcs();
	if (ret && cpuhp_state != CPUHP_INVALID) {
		cpuhp_remove_state_nocalls(cpuhp_state);
		cpuhp_state = CPUHP_INVALID;
	}
	kfree(tdmr_info_alloc);
	kfree(tdx_cmrs);
	cleanup_subtype_tdx_memory();
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

#ifdef CONFIG_SYSFS

static struct kobject *tdx_module_kobj;

static ssize_t tdx_module_state_show(
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	static const char * const names[] = {
		[TDX_MODULE_NOT_LOADED] = "not-loaded",
		[TDX_MODULE_LOADED] = "loaded",
		[TDX_MODULE_INITIALIZED] = "initialized",
		[TDX_MODULE_SHUTDOWN] = "shutdown",
		[TDX_MODULE_ERROR] = "error"
	};
	const char *state = "unknown";

	if (tdx_module_state < ARRAY_SIZE(names))
		state = names[tdx_module_state];

	return sprintf(buf, "%s", state);
}

static struct kobj_attribute tdx_module_state_attr = __ATTR_RO(tdx_module_state);

static struct attribute *tdx_module_states[] = {
	&tdx_module_state_attr.attr,
	NULL,
};

static const struct attribute_group tdx_module_state_group = {
	.attrs = tdx_module_states,
};

#define TDX_MODULE_ATTR_SHOW_FMT(name, fmt)				\
static ssize_t tdx_ ## name ## _show(					\
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)	\
{									\
	if (!tdx_tdsysinfo)						\
		return 0;						\
	return sprintf(buf, fmt, tdx_tdsysinfo->name);			\
}									\
static struct kobj_attribute tdx_module_##name = __ATTR_RO(tdx_ ## name)

#define TDX_MODULE_ATTR_SHOW_DEC(name)	TDX_MODULE_ATTR_SHOW_FMT(name, "%d\n")
#define TDX_MODULE_ATTR_SHOW_HEX(name)	TDX_MODULE_ATTR_SHOW_FMT(name, "0x%x\n")
#define TDX_MODULE_ATTR_SHOW_U64(name)	TDX_MODULE_ATTR_SHOW_FMT(name, "0x%llx\n")

TDX_MODULE_ATTR_SHOW_HEX(attributes);
TDX_MODULE_ATTR_SHOW_HEX(vendor_id);
TDX_MODULE_ATTR_SHOW_DEC(build_date);
TDX_MODULE_ATTR_SHOW_HEX(build_num);
TDX_MODULE_ATTR_SHOW_HEX(minor_version);
TDX_MODULE_ATTR_SHOW_HEX(major_version);
TDX_MODULE_ATTR_SHOW_HEX(max_tdmrs);
TDX_MODULE_ATTR_SHOW_HEX(max_reserved_per_tdmr);
TDX_MODULE_ATTR_SHOW_HEX(pamt_entry_size);
TDX_MODULE_ATTR_SHOW_HEX(tdcs_base_size);
TDX_MODULE_ATTR_SHOW_HEX(tdvps_base_size);
TDX_MODULE_ATTR_SHOW_HEX(tdvps_xfam_dependent_size);
TDX_MODULE_ATTR_SHOW_U64(attributes_fixed0);
TDX_MODULE_ATTR_SHOW_U64(attributes_fixed1);
TDX_MODULE_ATTR_SHOW_U64(xfam_fixed0);
TDX_MODULE_ATTR_SHOW_U64(xfam_fixed1);
TDX_MODULE_ATTR_SHOW_HEX(num_cpuid_config);

static struct attribute *tdx_module_attrs[] = {
	&tdx_module_attributes.attr,
	&tdx_module_vendor_id.attr,
	&tdx_module_build_date.attr,
	&tdx_module_build_num.attr,
	&tdx_module_minor_version.attr,
	&tdx_module_major_version.attr,
	&tdx_module_max_tdmrs.attr,
	&tdx_module_max_reserved_per_tdmr.attr,
	&tdx_module_pamt_entry_size.attr,
	&tdx_module_tdcs_base_size.attr,
	&tdx_module_tdvps_base_size.attr,
	&tdx_module_tdvps_xfam_dependent_size.attr,
	&tdx_module_attributes_fixed0.attr,
	&tdx_module_attributes_fixed1.attr,
	&tdx_module_xfam_fixed0.attr,
	&tdx_module_xfam_fixed1.attr,
	&tdx_module_num_cpuid_config.attr,
	NULL,
};

static const struct attribute_group tdx_module_attr_group = {
	.attrs = tdx_module_attrs,
};

static int __init tdx_module_sysfs_init(void)
{
	int ret = 0;

	if (!boot_cpu_has(X86_FEATURE_SEAM))
		return 0;

	tdx_module_kobj = kobject_create_and_add("tdx_module", firmware_kobj);
	if (!tdx_module_kobj) {
		pr_err("kobject_create_and_add tdx_module failed\n");
		ret = -EINVAL;
		goto err_kobj;
	}

	ret = sysfs_create_group(tdx_module_kobj, &tdx_module_state_group);
	if (ret) {
		pr_err("Sysfs exporting tdx module state failed %d\n", ret);
		goto err;
	}

	if (tdx_tdsysinfo) {
		ret = sysfs_create_group(tdx_module_kobj,
					 &tdx_module_attr_group);
		if (ret) {
			pr_err("Sysfs exporting tdx module attributes failed %d\n",
			       ret);
			goto err;
		}
	}

	return 0;

err:
	sysfs_remove_group(tdx_module_kobj, &tdx_module_state_group);
err_kobj:
	kobject_put(tdx_module_kobj);
	return ret;
}
device_initcall(tdx_module_sysfs_init);
#endif
