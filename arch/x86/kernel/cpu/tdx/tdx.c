// SPDX-License-Identifier: GPL-2.0
/* Load and initialize TDX-module. */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/cpu.h>

#include <asm/irq_vectors.h>
#include <asm/tdx_errno.h>
#include <asm/tdx_arch.h>
#include <asm/tdx_host.h>
#include <asm/cmdline.h>
#include <asm/virtext.h>

#include "tdx-tdmr.h"
#include "seamcall.h"
#include "tdx-ops.h"
#include "p-seamldr.h"
#include "seam.h"
#include "tdx.h"

enum TDX_HOST_OPTION {
	TDX_HOST_OFF,
	TDX_HOST_ON,
};

static enum TDX_HOST_OPTION tdx_host __initdata;

static int __init tdx_host_setup(char *s)
{
	if (!strcmp(s, "on"))
		tdx_host = TDX_HOST_ON;
	return 0;
}
__setup("tdx_host=", tdx_host_setup);

static bool trace_boot_seamcalls;

static int __init trace_seamcalls(char *s)
{
	trace_boot_seamcalls = true;
	return 1;
}
__setup("trace_boot_seamcalls", trace_seamcalls);

enum TDX_MODULE_STATE {
	/* The TDX firmware module is not found. */
	TDX_MODULE_NOT_FOUND = 0,
	/* The TDX module is found and usable. */
	TDX_MODULE_FOUND,
	/* Initialization is done so that the TDX module is functional. */
	TDX_MODULE_INITIALIZED,
	/* Something went wrong.  No SEAMCALLs to the TDX module are allowed. */
	TDX_MODULE_ERROR,
};

static enum TDX_MODULE_STATE tdx_module_state __ro_after_init;

bool is_debug_seamcall_available __read_mostly = true;

bool is_nonarch_seamcall_available __read_mostly = true;

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
EXPORT_SYMBOL_GPL(tdx_get_sysinfo);	/* kvm_intel needs this. */

/* CMR info array returned by TDH_SYS_INFO. */
static struct cmr_info *tdx_cmrs __initdata;
static int tdx_nr_cmrs __initdata;

/* KeyID range reserved to TDX by BIOS */
static u32 tdx_keyids_start __initdata;
static u32 tdx_nr_keyids __initdata;
static u32 tdx_seam_keyid __initdata;

static void __init tdx_get_keyids(u32 *keyids_start, u32 *nr_keyids)
{
	u32 nr_mktme_ids;

	rdmsr(MSR_IA32_MKTME_KEYID_PART, nr_mktme_ids, *nr_keyids);

	/* KeyID 0 is reserved, i.e. KeyIDs are 1-based. */
	*keyids_start = nr_mktme_ids + 1;
}

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
	if (WARN_ON_ONCE(err)) {
		pr_seamcall_error(SEAMCALL_TDH_SYS_LP_INIT, err, &ex_ret);
		return -EIO;
	}

	return 0;
}

static void __init tdx_init_cpu(void *data)
{
	atomic_t *error = data;
	int ret = tdx_init_lp();

	/* Don't care what exact errors occurred on which cpus. */
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
	/* Don't care what exact errors occurred on which cpus. */
	return atomic_read(&error);
}

/*
 * tdx_init_system - early system wide initialization of TDX module.
 * @return: 0 on success, error code on failure.
 *
 * Does system wide initialization of TDX module.
 */
static int __init tdx_init_system(void)
{
	struct tdx_ex_ret ex_ret;
	u64 err;

	/*
	 * Detect HKID for TDX if initialization was successful.
	 *
	 * TDX provides core-scoped MSR for us to simply read out TDX start
	 * keyID and number of keyIDs.
	 */
	tdx_get_keyids(&tdx_keyids_start, &tdx_nr_keyids);
	if (!tdx_nr_keyids)
		return -EOPNOTSUPP;

	/* System wide early initialization for TDX module. */
	err = tdh_sys_init(0, &ex_ret);
	if (err) {
		if (err == TDX_SEAMCALL_VMFAILINVALID)
			pr_info("No TDX module loaded by BIOS, skip TDX initialization\n");
		else
			pr_seamcall_error(SEAMCALL_TDH_SYS_INIT, err, &ex_ret);
		return -EIO;
	}

	/*
	 * Per-CPU early initialization.  tdh_sys_info() below requires that LP
	 * is initialized for TDX module.  Otherwise it results in an error,
	 * TDX_SYSINITLP_NOT_DONE.
	 */
	return tdx_init_cpus();
}

static void __init tdx_sys_info_free(struct tdsysinfo_struct **tdsysinfo,
				struct cmr_info **cmrs)
{
	/* kfree() is NULL-safe. */
	kfree(*tdsysinfo);
	kfree(*cmrs);
	*tdsysinfo = NULL;
	*cmrs = NULL;
}

/*
 * TDH_SYS_CONFIG requires that struct tdsysinfo_struct and the array of struct
 * cmr_info have the alignment of TDX_TDSYSINFO_STRUCT_ALIGNMENT(1024) and
 * TDX_CMR_INFO_ARRAY_ALIGNMENT(512).
 * sizeof(struct tdsysinfo_struct) = 1024
 * sizeof(struct cmr_info) * TDX_MAX_NR_CMRS = 512
 *
 * NOTE: kmalloc() returns size-aligned when size of power of 2.
 */
static int __init tdx_sys_info_alloc(struct tdsysinfo_struct **tdsysinfo,
				     struct cmr_info **cmrs)
{
	/* tdh_sys_info() requires special alignment. */
	BUILD_BUG_ON(sizeof(struct tdsysinfo_struct) != 1024);
	BUILD_BUG_ON(!is_power_of_2(sizeof(**tdsysinfo)));
	BUILD_BUG_ON(!IS_ALIGNED(sizeof(**tdsysinfo),
				 TDX_TDSYSINFO_STRUCT_ALIGNMENT));
	BUILD_BUG_ON(!is_power_of_2(sizeof(**cmrs) * TDX_MAX_NR_CMRS));
	BUILD_BUG_ON(!IS_ALIGNED(sizeof(**cmrs) * TDX_MAX_NR_CMRS,
				 TDX_CMR_INFO_ARRAY_ALIGNMENT));

	*tdsysinfo = kzalloc(sizeof(**tdsysinfo), GFP_KERNEL);
	*cmrs = kcalloc(TDX_MAX_NR_CMRS, sizeof(**cmrs), GFP_KERNEL);
	if (!*tdsysinfo || !*cmrs) {
		tdx_sys_info_free(tdsysinfo, cmrs);
		return -ENOMEM;
	}
	return 0;
}

/*
 * tdx_get_system_info - store TDX system information into the following
 *                       variables. tdx_keyid_start, tdx_nr_keyids,
 *                       tdx_tdsysinfo, tdx_cmrs and tdx_nr_cmrs.
 *
 * @return: 0 on success, error code on failure.
 *
 * get info about system. i.e. info about TDX module and Convertible Memory
 * Regions(CMRs).
 */
static int __init tdx_get_system_info(void)
{
	struct tdx_ex_ret ex_ret;
	u64 err;
	int ret;
	int i;

	ret = tdx_sys_info_alloc(&tdx_tdsysinfo, &tdx_cmrs);
	if (ret)
		return ret;

	/* Collect the system wide information needed to construct TDMRs. */
	err = tdh_sys_info(__pa(tdx_tdsysinfo), sizeof(*tdx_tdsysinfo),
			   __pa(tdx_cmrs), TDX_MAX_NR_CMRS, &ex_ret);
	if (WARN_ON(err)) {
		pr_seamcall_error(SEAMCALL_TDH_SYS_INFO, err, &ex_ret);
		ret = -EIO;
		goto out;
	}

	/*
	 * ex_ret.nr_cmr_entries is how many entries TDX module writes.  It may
	 * contain 0-size entries at the end.  Exclude 0-size entries.
	 */
	tdx_nr_cmrs = 0;
	for (i = 0; i < ex_ret.sys_info.nr_cmr_entries; i++) {
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
		ret = -EINVAL;
		goto out;
	}

	pr_info("TDX SEAM module: attributes 0x%x vendor_id 0x%x build_date %d "
		"build_num 0x%x minor_version 0x%x major_version 0x%x.\n",
		tdx_tdsysinfo->attributes, tdx_tdsysinfo->vendor_id,
		tdx_tdsysinfo->build_date, tdx_tdsysinfo->build_num,
		tdx_tdsysinfo->minor_version, tdx_tdsysinfo->major_version);

	for (i = 0; i < tdx_nr_cmrs; i++)
		pr_info("TDX CMR[%2d]: base 0x%016llx size 0x%016llx\n",
			i, tdx_cmrs[i].base, tdx_cmrs[i].size);

out:
	if (ret)
		tdx_sys_info_free(&tdx_tdsysinfo, &tdx_cmrs);
	return ret;
}

/*
 * Early system wide initialization of the TDX module. Check if the TDX firmware
 * loader and the TDX firmware module are available and log their version.
 */
static int __init tdx_arch_init(void)
{
	int vmxoff_err;
	int ret = 0;

	/* Avoid TDX overhead when opt-in is not present. */
	if (tdx_host != TDX_HOST_ON)
		return 0;

	/* TDX requires SEAM mode. */
	if (!is_seamrr_enabled())
		return -EOPNOTSUPP;

	/* TDX requires VMX. */
	ret = seam_init_vmx_early();
	if (ret)
		return ret;

	/*
	 * Check if P-SEAMLDR is available and log its version information for
	 * the administrator of the machine.  Although the kernel don't use
	 * P-SEAMLDR at the moment, it's a part of TCB.  It's worthwhile to
	 * tell it to the administrator of the machine.
	 */
	ret = p_seamldr_get_info();
	if (ret) {
		pr_info("No P-SEAMLDR is available.\n");
		return ret;
	}
	setup_force_cpu_cap(X86_FEATURE_SEAM);

	/*
	 * Prevent potential concurrent CPU online/offline because smp is
	 * enabled.
	 * - Make seam_vmx{on, off}_on_each_cpu() work.  Otherwise concurrently
	 *   onlined CPU has VMX disabled and the SEAM operation on that CPU
	 *   fails.
	 * - Ensure all present CPUs are online during this initialization after
	 *   the check.
	 */
	cpus_read_lock();

	/*
	 * Initialization of TDX module needs to involve all CPUs.  Ensure all
	 * CPUs are online.  All CPUs are required to be initialized by
	 * TDH.SYS.LP.INIT otherwise TDH.SYS.CONFIG fails.
	 */
	if (!cpumask_equal(cpu_present_mask, cpu_online_mask)) {
		ret = -EINVAL;
		goto out_err;
	}

	/* SEAMCALL requires to enable VMX on CPUs. */
	ret = seam_alloc_init_vmcs_tmp_set();
	if (ret)
		goto out_err;
	ret = seam_vmxon_on_each_cpu();
	if (ret)
		goto out;

	ret = tdx_init_system();
	if (ret)
		goto out;

	ret = tdx_get_system_info();
	if (ret)
		goto out;

	pr_info("Successfully get information about the TDX module.\n");
	tdx_module_state = TDX_MODULE_FOUND;

out:
	/*
	 * Other codes (especially kvm_intel) expect that they're the first to
	 * use VMX.  That is, VMX is off on their initialization as a reset
	 * state.  Maintain the assumption to keep them working.
	 */
	vmxoff_err = seam_vmxoff_on_each_cpu();
	if (vmxoff_err) {
		pr_info("Failed to VMXOFF.\n");
		if (!ret)
			ret = vmxoff_err;
	}
	seam_free_vmcs_tmp_set();

out_err:
	if (ret)
		tdx_module_state = TDX_MODULE_ERROR;
	cpus_read_unlock();

	if (ret)
		pr_err("Failed to find the TDX module. %d\n", ret);

	return ret;
}

/*
 * arch_initcall() is chosen to satisfy the following conditions.
 * - After SMP initialization.
 */
arch_initcall(tdx_arch_init);

/*
 * Array of all TDMR info array.  TDX_TDMR_INFO_ALIGNMENT-alignment is needed.
 */
static struct tdmr_info *tdmr_info __initdata;
/* Number of actual TDMRs */
static int tdx_nr_tdmrs __initdata;

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
	struct tdx_ex_ret ex_ret;
	bool completed;
	u64 base, size;
	u64 err = 0;
	int i;

	mutex_lock(&data->lock);
	while (data->next_tdmr_index < tdx_nr_tdmrs) {
		i = data->next_tdmr_index++;
		base = tdmr_info[i].base;
		size = tdmr_info[i].size;

		while (true) {
			/* Abort if a different CPU failed. */
			if (data->failed)
				goto out;

			mutex_unlock(&data->lock);
			err = tdh_sys_tdmr_init(base, &ex_ret);
			if (WARN_ON_ONCE(err)) {
				pr_seamcall_error(SEAMCALL_TDH_SYS_TDMR_INIT,
						err, &ex_ret);
				err = -EIO;
				mutex_lock(&data->lock);
				goto out;
			}
			cond_resched();
			mutex_lock(&data->lock);

			/*
			 * Note, "next" is simply an indicator, base is passed
			 * to TDH.SYS.TDMR.INIT on every iteration.
			 */
			if (!(ex_ret.sys_tdmr_init.next < (base + size)))
				break;
		}

		data->nr_initialized_tdmrs++;
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
 * It may take long time to initialize TDMRs by TDH.SYS.TDMR.INIT that
 * initializes Physical Address Metadata Table(PAMT) which is something similar
 * to Linux struct page.  Parallelize it to shorten boot time by work queue.
 */
static int __init tdx_init_tdmrs(void)
{
	/*
	 * Because multiple threads can not initialize one TDMR simultaneously,
	 * no point to have threads more than the number of TDMRs.
	 */
	int nr_works = min_t(int, num_online_cpus(), tdx_nr_tdmrs);
	struct tdx_tdmr_init_data data = {
		.next_tdmr_index = 0,
		.nr_initialized_tdmrs = 0,
		.failed = 0,
		.nr_completed = 0,
		.nr_works = nr_works,
		.completion = COMPLETION_INITIALIZER_ONSTACK(data.completion),
	};
	int i;

	struct tdx_tdmr_init_request *reqs = kcalloc(nr_works, sizeof(*reqs),
						     GFP_KERNEL);
	if (!reqs)
		return -ENOMEM;

	mutex_init(&data.lock);
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

static int __init tdx_sys_key_config_cpu(void *unused)
{
	u64 err;
	static int count = 0;

	do {
		err = tdh_sys_key_config();
	} while (err == TDX_KEY_GENERATION_FAILED);
	/* Entropy is lacking.  Retry. */

	/*
	 * Because key configuration is per-memory controller, other CPUs on the
	 * same package may have already configured it.  Ignore such case.
	 */
	if (err == TDX_KEY_CONFIGURED)
		err = 0;

	/*
	 * TDX module bug work around.  If all the memory controllers are
	 * configured,  tdh_sys_key_config() should return TDX_KEY_CONFIGURED.
	 * However, it returns TDX_SYSCONFIG_NOT_DONE wrongly.
	 */
	if (err == 0)
		count++;
	if (err == TDX_SYSCONFIG_NOT_DONE && count > 0)
		err = 0;

	if (WARN_ON_ONCE(err)) {
		pr_seamcall_error(SEAMCALL_TDH_SYS_KEY_CONFIG, err, NULL);
		return -EIO;
	}

	return 0;
}

static int __init tdx_sys_key_config(void)
{
	int ret = 0;
	int cpu;

	/*
	 * TDX SEAMCALL operations require serialization between CPUs.
	 * Invoke the callback one by one to avoid watchdog timer by the
	 * contention with a spin lock.
	 */
	for_each_online_cpu(cpu) {
		ret = smp_call_on_cpu(cpu, tdx_sys_key_config_cpu, NULL, 1);
		if (ret)
			break;
	}

	return ret;
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
	tdmr_addrs = kcalloc(TDX_MAX_NR_TDMRS, sizeof(*tdmr_addrs), GFP_KERNEL);
	if (!tdmr_addrs)
		return -ENOMEM;

	for (i = 0; i < tdx_nr_tdmrs; i++)
		tdmr_addrs[i] = __pa(&tdmr_info[i]);

	/*
	 * tdh_sys_tdmr_config() calls TDH.SYS.CONFIG to tell TDX module about
	 * TDMRs, PAMTs and HKID for TDX module to use.  Use the first keyID as
	 * TDX-SEAM's global key.  Give the memory regions for PAMTs to the TDX
	 * module.
	 */
	err = tdh_sys_tdmr_config(__pa(tdmr_addrs), tdx_nr_tdmrs,
				  tdx_keyids_start);
	if (WARN_ON_ONCE(err)) {
		pr_seamcall_error(SEAMCALL_TDH_SYS_CONFIG, err, NULL);
		ret = -EIO;
		goto out;
	}
	tdx_seam_keyid = tdx_keyids_start;

	/*
	 * Flush any MODIFIED cache lines that may exist for the PAMT ranges
	 * before the TDX module initializes the PAMT ranges with the encryption
	 * key.
	 */
	wbinvd_on_all_cpus();

	/* Configure memory encryption key. */
	ret = tdx_sys_key_config();
	if (ret)
		goto out;

	/*
	 * Detect if debug and non-arch seamcall available.
	 *
	 * Even though tracing level is ALL level by default, it needs to set
	 * it explicitly to check if debug seamcall available.
	 */
	if (trace_boot_seamcalls)
		tdh_trace_seamcalls(DEBUGCONFIG_TRACE_ALL);
	else
		/*
		 * Tracing is on by default, disable it before INITTDMR which
		 * causes too many debug messages to take long time.
		 */
		tdh_trace_seamcalls(DEBUGCONFIG_TRACE_CUSTOM);
	tdxmode(false, 0);

	ret = tdx_init_tdmrs();
out:
	kfree(tdmr_addrs);
	return ret;
}

static int __init tdx_init_module(void)
{
	struct tdx_module_descriptor desc;
	int ret = 0;

	/*
	 * tdmr_info must be aligned to TDX_TDMR_INFO_ALIGNMENT(512).
	 * NOTE: kmalloc() returns size-aligned when size of power of 2.
	 */
	BUILD_BUG_ON(sizeof(*tdmr_info) != 512);
	BUILD_BUG_ON((sizeof(*tdmr_info) % TDX_TDMR_INFO_ALIGNMENT) != 0);
	tdmr_info = kcalloc(tdx_tdsysinfo->max_tdmrs, sizeof(*tdmr_info),
			GFP_KERNEL);
	if (!tdmr_info) {
		ret = -ENOMEM;
		goto out;
	}

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

	/* final initialization to make TDX module workable. */
	ret = __tdx_init_module();
	if (ret)
		goto out;

out:
	return ret;
}

/*
 * The final initialization of the TDX module and make it ready to use.
 */
static int __init tdx_late_init(void)
{
	int vmxoff_err;
	int ret = 0;

	if (tdx_module_state != TDX_MODULE_FOUND)
		return -ENODEV;

	pr_info("Initializing TDX module.\n");

	ret = build_tdx_memory();
	if (ret)
		goto out_err;

	/*
	 * Since other subsystem(for example, ACPI subsystem) is initialized,
	 * prevent potential concurrent CPU online/offline.
	 *
	 * - Make seam_vmxon_on_each_cpu() work.  Otherwise concurrently onlined
	 *   CPU has VMX disabled and the SEAM operation on that CPU fails.
	 * - Make seam_vmx{on, off}_on_each_cpu() work.  Otherwise concurrently
	 *   onlined CPU has VMX disabled and the SEAM operation on that CPU
	 *   fails.
	 */
	cpus_read_lock();

	/* SEAMCALL requires to enable VMXON on CPUs. */
	ret = seam_alloc_init_vmcs_tmp_set();
	if (ret)
		goto out_unlock;
	ret = seam_vmxon_on_each_cpu();
	if (ret)
		goto out;

	ret = tdx_init_module();
	if (ret)
		goto out;

	pr_info("Successfully initialized TDX module\n");
	tdx_module_state = TDX_MODULE_INITIALIZED;

out:
	vmxoff_err = seam_vmxoff_on_each_cpu();
	if (vmxoff_err) {
		pr_info("Failed to VMXOFF.\n");
		if (!ret)
			ret = vmxoff_err;
	}
	if (tdx_module_state == TDX_MODULE_INITIALIZED) {
		int cpu;

		setup_force_cpu_cap(X86_FEATURE_TDX);
		for_each_online_cpu(cpu)
			set_cpu_cap(&cpu_data(cpu), X86_FEATURE_TDX);
	}
	seam_free_vmcs_tmp_set();
out_unlock:
	cpus_read_unlock();

	kfree(tdmr_info);
	kfree(tdx_cmrs);

out_err:
	if (ret) {
		pr_info("Failed to initialize TDX module %d\n", ret);
		tdx_module_state = TDX_MODULE_ERROR;
	}
	cleanup_subtype_tdx_memory();

	return ret;
}
/*
 * subsys_initcall_sync() is chosen to satisfy the following conditions.
 *   e820_reserve_resources() called by setup_arch().  Because
 *   tdx_construct_tdmr() walks iomem resources looking for legacy pmem region.
 * - After reserved memory region is polulated in iomem_resource by
 *   e820__reserve_resources_late(), which is called by
 *   subsys_initcall(pci_subsys_init).
 * - After numa node is initialized by pgdata_init() and alloc_contig_pages() is
 *   available.
 * - Before kvm_intel.  module_init() is mapped to device_initcall() when
 *   it's built into the kernel.
 */
subsys_initcall_sync(tdx_late_init);

#ifdef CONFIG_SYSFS

struct kobject *tdx_kobj;

int __init tdx_sysfs_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_SEAM))
		return 0;

	if (tdx_kobj)
		return 0;

	tdx_kobj = kobject_create_and_add("tdx", firmware_kobj);
	if (!tdx_kobj) {
		pr_err("kobject_create_and_add tdx failed\n");
		return -EINVAL;
	}

	return 0;
}

static struct kobject *tdx_module_kobj;

static ssize_t state_show(
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	static const char * const names[] = {
		[TDX_MODULE_NOT_FOUND] = "not-found",
		[TDX_MODULE_FOUND] = "found",
		[TDX_MODULE_INITIALIZED] = "initialized",
		[TDX_MODULE_ERROR] = "error"
	};
	const char *state = "unknown";

	if (tdx_module_state < ARRAY_SIZE(names))
		state = names[tdx_module_state];

	return sprintf(buf, "%s\n", state);
}

static struct kobj_attribute tdx_module_state_attr = __ATTR_RO(state);

static struct attribute *tdx_module_states[] = {
	&tdx_module_state_attr.attr,
	NULL,
};

static const struct attribute_group tdx_module_state_group = {
	.attrs = tdx_module_states,
};

#define TDX_MODULE_ATTR_SHOW_FMT(name, fmt)				\
static ssize_t name ## _show(						\
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)	\
{									\
	if (!tdx_tdsysinfo)						\
		return 0;						\
	return sprintf(buf, fmt, tdx_tdsysinfo->name);			\
}									\
static struct kobj_attribute tdx_module_##name = __ATTR_RO(name)

#define TDX_MODULE_ATTR_SHOW_DEC(name)	TDX_MODULE_ATTR_SHOW_FMT(name, "%d\n")
#define TDX_MODULE_ATTR_SHOW_HEX(name)	TDX_MODULE_ATTR_SHOW_FMT(name, "0x%x\n")
#define TDX_MODULE_ATTR_SHOW_U64(name)	TDX_MODULE_ATTR_SHOW_FMT(name, "0x%016llx\n")

TDX_MODULE_ATTR_SHOW_FMT(attributes, "0x%08x\n");
TDX_MODULE_ATTR_SHOW_HEX(vendor_id);
TDX_MODULE_ATTR_SHOW_DEC(build_date);
TDX_MODULE_ATTR_SHOW_HEX(build_num);
TDX_MODULE_ATTR_SHOW_HEX(minor_version);
TDX_MODULE_ATTR_SHOW_HEX(major_version);
TDX_MODULE_ATTR_SHOW_U64(attributes_fixed0);
TDX_MODULE_ATTR_SHOW_U64(attributes_fixed1);
TDX_MODULE_ATTR_SHOW_U64(xfam_fixed0);
TDX_MODULE_ATTR_SHOW_U64(xfam_fixed1);

static struct attribute *tdx_module_attrs[] = {
	&tdx_module_attributes.attr,
	&tdx_module_vendor_id.attr,
	&tdx_module_build_date.attr,
	&tdx_module_build_num.attr,
	&tdx_module_minor_version.attr,
	&tdx_module_major_version.attr,
	&tdx_module_attributes_fixed0.attr,
	&tdx_module_attributes_fixed1.attr,
	&tdx_module_xfam_fixed0.attr,
	&tdx_module_xfam_fixed1.attr,
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

	ret = tdx_sysfs_init();
	if (ret)
		return ret;

	tdx_module_kobj = kobject_create_and_add("tdx_module", tdx_kobj);
	if (!tdx_module_kobj) {
		pr_err("kobject_create_and_add tdx_module failed\n");
		return -EINVAL;
	}

	ret = sysfs_create_group(tdx_module_kobj, &tdx_module_state_group);
	if (ret) {
		pr_err("Sysfs exporting tdx module state failed %d\n", ret);
		goto err_kobj;
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
	tdx_module_kobj = NULL;
	return ret;
}
device_initcall(tdx_module_sysfs_init);
#endif
