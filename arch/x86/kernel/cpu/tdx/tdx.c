// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) host kernel support
 */

#define	pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/cpu.h>
#include <linux/bug.h>
#include <linux/slab.h>
#include <asm/cpufeatures.h>
#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/tdx_host.h>
#include <asm/seam.h>
#include "p-seamldr.h"
#include "tdx_seamcall.h"
#include "tdx_arch.h"
#include "tdmr.h"

/*
 * TDX module status during initialization
 */
enum tdx_module_status_t {
	/* TDX module status is unknown */
	TDX_MODULE_UNKNOWN,
	/* TDX module is not loaded */
	TDX_MODULE_NONE,
	/* TDX module is loaded, but not initialized */
	TDX_MODULE_LOADED,
	/* TDX module is fully initialized */
	TDX_MODULE_INITIALIZED,
	/* TDX module is shutdown due to error during initialization */
	TDX_MODULE_SHUTDOWN,
};

static enum tdx_module_status_t tdx_module_status;

/* Prevent concurrent attempts on TDX detection and initialization */
static DEFINE_MUTEX(tdx_module_lock);

/* Base address of CMR array needs to be 512 bytes aligned. */
struct cmr_info tdx_cmr_array[MAX_CMRS] __aligned(CMR_INFO_ARRAY_ALIGNMENT);
int tdx_cmr_num;
struct tdsysinfo_struct tdx_sysinfo;

/* Array of pointer of TDMRs (TDMR_INFO) */
static struct tdmr_info **tdx_tdmr_array;
/* Actual number of TDMRs */
static int tdx_tdmr_num;
/* Array of physical address of TDMR_INFO.  Used as input to TDH.SYS.CONFIG. */
static u64 *tdx_tdmr_pa_array;
/* TDX global KeyID to protect TDX metadata */
static u32 tdx_global_keyid;

/*
 * Intel Trusted Domain CPU Architecture Extension spec:
 *
 * IA32_MKTME_KEYID_PARTIONING:
 *
 *   Bit [31:0]: number of MKTME KeyIDs.
 *   Bit [63:32]: number of TDX private KeyIDs.
 *
 * TDX private KeyIDs start with the last MKTME KeyID.
 */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

#define TDX_KEYID_START(_keyid_part)	\
		((u32)(((_keyid_part) & 0xffffffffull) + 1))
#define TDX_KEYID_NUM(_keyid_part)	((u32)((_keyid_part) >> 32))

static u32 tdx_keyid_start;
static u32 tdx_keyid_num;

static void detect_tdx_keyids_bsp(struct cpuinfo_x86 *c)
{
	u64 keyid_part;

	/* TDX is built on MKTME, which is based on TME */
	if (!boot_cpu_has(X86_FEATURE_TME))
		return;

	if (rdmsrl_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &keyid_part))
		return;

	/* If MSR value is 0, TDX is not enabled by BIOS. */
	if (!keyid_part)
		return;

	tdx_keyid_num = TDX_KEYID_NUM(keyid_part);
	if (!tdx_keyid_num)
		return;

	tdx_keyid_start = TDX_KEYID_START(keyid_part);
}

static void detect_tdx_keyids_ap(struct cpuinfo_x86 *c)
{
	u64 keyid_part;

	/*
	 * Don't bother to detect this AP if TDX KeyIDs are
	 * not detected or cleared after earlier detections.
	 */
	if (!tdx_keyid_num)
		return;
	/*
	 * Check potential BIOS bug that TDX KeyIDs are not
	 * configured consistently among packages.
	 */
	rdmsrl(MSR_IA32_MKTME_KEYID_PARTITIONING, keyid_part);

	if ((tdx_keyid_start == TDX_KEYID_START(keyid_part)) &&
			(tdx_keyid_num == TDX_KEYID_NUM(keyid_part)))
		return;

	pr_err("Inconsistent TDX KeyID configuration among packages by BIOS\n");
	tdx_keyid_start = 0;
	tdx_keyid_num = 0;
}

void detect_tdx_keyids(struct cpuinfo_x86 *c)
{
	if (c == &boot_cpu_data)
		detect_tdx_keyids_bsp(c);
	else
		detect_tdx_keyids_ap(c);
}

/*
 * Call the requested function on all online cpus concurrently.
 * Any SEAMCALL invoked in the requested function must allow
 * concurrent execution.
 *
 * Return error if requested function fails on any cpu.
 */
static int tdx_on_each_cpu(smp_call_func_t func)
{
	atomic_t err;

	atomic_set(&err, 0);
	on_each_cpu(func, &err, 1);

	/* Don't care about exactly what error happened on which cpu */
	return atomic_read(&err) ? -EFAULT : 0;
}

/*
 * Call the requested function on each online in turn.  It is intended
 * for SEAMCALLs which don't support concurrent invocations.
 */
static int tdx_on_each_cpu_serialized(smp_call_func_t func)
{
	int cpu, ret, err = 0;

	for_each_online_cpu(cpu) {
		ret = smp_call_function_single(cpu, func, &err, 1);
		/*
		 * Don't care about exactly what error happened
		 * on which cpu.
		 */
		if (ret || err)
			return -EFAULT;
	}

	return 0;
}

static int init_tdx_module_global(void)
{
	/*
	 * Platform global initialization requires calling
	 * TDH.SYS.INIT on any cpu once.
	 */
	return tdh_sys_init();
}

/* SMP call function to run TDH.SYS.LP.INIT */
static void smp_call_tdx_cpu_init(void *data)
{
	atomic_t *err = (atomic_t *)err;

	if (tdh_sys_lp_init())
		atomic_set(err, -1);
}

static int init_tdx_module_cpus(void)
{
	/*
	 * Logical cpu level initialization requires call
	 * TDH.SYS.LP.INIT on all cpus reported by BIOS,
	 * otherwise SEAMCALL of next step will fail.
	 *
	 * Caller to guarantee all cpus reported by BIOS
	 * are online.
	 */
	return tdx_on_each_cpu(smp_call_tdx_cpu_init);
}

static inline bool is_valid_cmr(struct cmr_info *cmr)
{
	return !!cmr->size;
}

static void print_cmrs(struct cmr_info *cmr_array, int cmr_num)
{
	int i;

	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		pr_info("CMR[%d]: [0x%llx, 0x%llx)\n", i,
				cmr->base, cmr->base + cmr->size);
	}
}

static int sanitize_cmrs(void)
{
	int i, j;

	/*
	 * Intel TDX module spec, 20.7.3 CMR_INFO:
	 *
	 *   TDH.SYS.INFO leaf function returns a MAX_CMRS (32) entry
	 *   array of CMR_INFO entries. The CMRs are sorted from the
	 *   lowest base address to the highest base address, and they
	 *   are non-overlapping.
	 *
	 * This implies that BIOS may generate empty entries if total
	 * CMRs are less than 32.  Skip them manually.
	 */
	for (i = 0; i < tdx_cmr_num; i++) {
		struct cmr_info *cmr = &tdx_cmr_array[i];
		struct cmr_info *prev_cmr = NULL;

		/* Skip further empty CMRs */
		if (!is_valid_cmr(cmr))
			break;

		if (i > 0)
			prev_cmr = &tdx_cmr_array[i - 1];

		/*
		 * It is a TDX firmware bug if CMRs are not
		 * in address ascending order.
		 */
		if (prev_cmr && ((prev_cmr->base + prev_cmr->size) >
					cmr->base)) {
			pr_err("TDX firmware bug: CMRs not in address ascending order\n");
			return -EFAULT;
		}
	}

	/*
	 * Also a sane BIOS should never generate invalid CMR(s) between
	 * two valid CMRs.  Sanity check this and simply return error in
	 * this case.
	 */
	for (j = i; j < tdx_cmr_num; j++)
		if (is_valid_cmr(&tdx_cmr_array[j])) {
			pr_err("TDX firmware bug: invalid CMR(s) among valid CMRs.\n");
			return -EFAULT;
		}

	/*
	 * Trim all tail empty CMRs.  BIOS should generate at least one
	 * valid CMR, otherwise it's a TDX firmware bug.
	 */
	tdx_cmr_num = i;
	if (!tdx_cmr_num) {
		pr_err("TDX firmware bug: No valid CMRs generated.\n");
		return -EFAULT;
	}

	print_cmrs(tdx_cmr_array, tdx_cmr_num);

	return 0;
}

static int get_tdx_sysinfo(void)
{
	u64 tdsysinfo_sz, cmr_num;
	int ret;

	ret = tdh_sys_info(&tdx_sysinfo, tdx_cmr_array,
			&tdsysinfo_sz, &cmr_num);
	if (ret)
		return ret;

	if (WARN_ON(tdsysinfo_sz > sizeof(tdx_sysinfo)) ||
		WARN_ON(cmr_num > MAX_CMRS))
		return -EFAULT;

	tdx_cmr_num = (int)cmr_num;

	pr_info("TDX module: vendor_id 0x%x, major_version %u, minor_version %u, build_date %u, build_num %u",
			tdx_sysinfo.vendor_id, tdx_sysinfo.major_version,
			tdx_sysinfo.minor_version, tdx_sysinfo.build_date,
			tdx_sysinfo.build_num);

	return sanitize_cmrs();
}

/* Construct TDMRs to use all system RAM entries in e820 as TDX memory */
static int build_tdx_memory(void)
{
	/* Allocate the array of pointer to TDMRs. */
	tdx_tdmr_array = kcalloc(tdx_sysinfo.max_tdmrs,
			sizeof(struct tdmr_info *), GFP_KERNEL);

	if (!tdx_tdmr_array)
		return -ENOMEM;

	return construct_tdmrs(tdx_tdmr_array, &tdx_tdmr_num);
}

static void build_tdx_memory_cleanup(void)
{
	if (tdx_tdmr_array) {
		destroy_tdmrs(tdx_tdmr_array, tdx_tdmr_num);
		kfree(tdx_tdmr_array);
	}
}

/* Configure TDX module with TDMRs and global KeyID info */
static int config_tdx_module(void)
{
	int tdmr_pa_array_sz, i;
	int ret;

	/*
	 * TDX requires the array of physical address of TDMR_INFO being
	 * TDMR_INFO_PA_ARRAY_ALIGNMENT aligned (which is power of two).
	 * Align up the array size to TDMR_INFO_PA_ARRAY_ALIGNMENT so
	 * that memory allocated by kmalloc() meets the alignment.
	 */
	tdmr_pa_array_sz = ALIGN(tdx_tdmr_num * sizeof(u64),
			TDMR_INFO_PA_ARRAY_ALIGNMENT);
	tdx_tdmr_pa_array = kzalloc(tdmr_pa_array_sz, GFP_KERNEL);
	if (!tdx_tdmr_pa_array)
		return -ENOMEM;

	/*
	 * TDH.SYS.CONFIG uses the array of physical address of TDMRs
	 * as input to configure the TDX module.
	 */
	for (i = 0; i < tdx_tdmr_num; i++) {
		tdx_tdmr_pa_array[i] = __pa(tdx_tdmr_array[i]);
		WARN_ON(!IS_ALIGNED(tdx_tdmr_pa_array[i], TDMR_INFO_ALIGNMENT));
	}

	ret = tdh_sys_config(tdx_tdmr_pa_array, tdx_tdmr_num,
			tdx_global_keyid);
	/*
	 * The physical address array is only used by TDH.SYS.CONFIG.
	 * Free it as it is not required anymore.
	 */
	kfree(tdx_tdmr_pa_array);

	return ret;
}

/* SMP call function to run TDH.SYS.KEY.CONFIG */
static void smp_call_tdh_sys_key_config(void *data)
{
	int *err = (int *)data;
	u64 seamcall_ret;

	/*
	 * Some TDH.SYS.KEY.CONFIG errors are theoretically recoverable.
	 * Assume they are exceedingly rare and WARN() if one is
	 * encountered instead of retrying.
	 */
	if (tdh_sys_key_config(&seamcall_ret)) {
		WARN_ON(seamcall_ret);
		*err = -1;
	}
}

/* Configure the global KeyID on all CPU packages. */
static int config_global_keyid_on_all_pkgs(void)
{
	/*
	 * The same physical address associated with different KeyIDs
	 * has separate cachelines.  Before using the new KeyID to access
	 * some memory, the cachelines associated with the old KeyID must
	 * be flushed, otherwise they may later silently corrupt the data
	 * written with the new KeyID.  After cachelines associated with
	 * the old KeyID are flushed, CPU speculative fetch using the old
	 * KeyID is OK since the prefetched cachelines won't be consumed
	 * by CPU core.
	 *
	 * TDX module initializes PAMTs using the global KeyID to crypto
	 * protect them from malicious host.  Before that, the PAMTs are
	 * used by kernel (with KeyID 0) and the cachelines associated
	 * with the PAMTs must be flushed.  Given PAMTs are potentially
	 * large, just use WBINVD on all cpus to flush the cache.  As
	 * suggested by the TDX specification, do cache flush before
	 * configuring the key for global KeyID.
	 */
	wbinvd_on_all_cpus();

	return tdx_on_each_cpu_serialized(smp_call_tdh_sys_key_config);
}

/* Initialize one TDMR */
static int init_tdmr(struct tdmr_info *tdmr)
{
	u64 next;

	/*
	 * Initializing PAMT entries might be time-consuming (in
	 * proportion to the size of the requested TDMR).  To avoid long
	 * latency in one SEAMCALL, TDH.SYS.TDMR.INIT only initializes
	 * an (implementation-defined) subset of PAMT entries in one
	 * invocation.
	 *
	 * Call TDH.SYS.TDMR.INIT iteratively until all PAMT entries
	 * of the requested TDMR are initialized (if next-to-initialize
	 * address matches the end address of the TDMR).
	 */
	do {
		u64 ret;

		ret = tdh_sys_tdmr_init(tdmr, &next);
		if (ret) {
			WARN(1, "TDH.SYS.TDMR.INIT failed: 0x%llx", ret);
			return -EFAULT;
		}
		if (need_resched())
			cond_resched();
	} while (next < tdmr->base + tdmr->size);

	return 0;
}

/* Initialize all TDMRs */
static int init_tdmrs(void)
{
	int i;

	/*
	 * Initialize TDMRs one-by-one for simplicity, though the TDX
	 * architecture does allow different TDMRs to be initialized in
	 * parallel on multiple CPUs.  Parallel initialization could
	 * be added later when the time spent in the serialized scheme
	 * becomes a real concern.
	 */
	for (i = 0; i < tdx_tdmr_num; i++) {
		int ret;

		ret = init_tdmr(tdx_tdmr_array[i]);
		if (ret)
			return ret;
	}

	return 0;
}

/* Initialize the TDX module. */
static int init_tdx_module(void)
{
	int ret;

	/* Platform global initialization */
	ret = init_tdx_module_global();
	if (ret)
		goto out;

	/* Logical cpu level initialization */
	ret = init_tdx_module_cpus();
	if (ret)
		goto out;

	/* Get the TDX module and CMR info */
	ret = get_tdx_sysinfo();
	if (ret)
		goto out;

	/* Construct TDMRs to build TDX memory */
	ret = build_tdx_memory();
	if (ret)
		goto out;

	/* Reserve the first TDX KeyID as global KeyID. */
	tdx_global_keyid = tdx_keyid_start;

	/* Configure TDX module with TDMRs and global KeyID info */
	ret = config_tdx_module();
	if (ret)
		goto out;

	/* Configure the global KeyID on all cpu packages */
	ret = config_global_keyid_on_all_pkgs();
	if (ret)
		goto out;

	/* Initialize TDMRs to complete the TDX module initialization */
	ret = init_tdmrs();
	if (ret)
		goto out;

	tdx_module_status = TDX_MODULE_INITIALIZED;

	pr_info("TDX module successfully initialized\n");
out:
	/*
	 * TDMRs are not required anymore after TDX module
	 * initialization, no matter successful or not.
	 */
	build_tdx_memory_cleanup();
	return ret;
}

/* SMP call function to run TDH.SYS.LP.SHUTDOWN */
static void smp_call_tdx_cpu_shutdown(void *data)
{
	atomic_t *err = (atomic_t *)data;

	if (tdh_sys_lp_shutdown())
		atomic_set(err, -1);
}

/* Shut down the TDX module */
static void shutdown_tdx_module(void)
{
	tdx_on_each_cpu(smp_call_tdx_cpu_shutdown);

	tdx_module_status = TDX_MODULE_SHUTDOWN;
}

static int __detect_tdx(void)
{
	/*
	 * TDX requires at least two KeyIDs: one global KeyID to protect
	 * the metadata of the TDX module and one or more KeyIDs to
	 * protect VMs.  It's pointless to report TDX module as present
	 * if this condition is not met.
	 */
	if (!(tdx_keyid_num > 1))
		goto no_tdx_module;

	/* P-SEAMLDR reports the presence of the TDX module */
	if (detect_p_seamldr() || !tdx_module_ready())
		goto no_tdx_module;

	tdx_module_status = TDX_MODULE_LOADED;
	return 0;

no_tdx_module:
	tdx_module_status = TDX_MODULE_NONE;
	return -ENODEV;
}

static int __init_tdx(void)
{
	int ret;

	/*
	 * Logical-cpu scope initialization requires calling one SEAMCALL
	 * on all logical cpus reported by BIOS, otherwise the SEAMCALL
	 * of the next step of the initialization fails.  Shutting down
	 * TDX module also has such requirement.  Further more,
	 * configuring the key of the global KeyID requires calling one
	 * SEAMCALL on at least one cpu for each package.
	 *
	 * For simplicity, instead of disabling CPU hotplug separately
	 * for them to prevent any cpu going offline, disable CPU hotplug
	 * during the entire TDX module initialization.
	 *
	 * Initializing TDX module could be time consuming, therefore use
	 * cpu_hotplug_disable() instead of cpus_read_lock(), so that
	 * another thread to run cpu hotplug could return -EBUSY
	 * immediately rather than busy waiting.
	 *
	 * And assume all cpus reported by BIOS are online and depend on
	 * the SEAMCALL failure to detect that this condition doesn't
	 * meet.  Ideally a pre-check could be done before starting the
	 * initialization, and return error early:
	 *
	 *	if (cpu_online_map != bios_enabled_cpu_map)
	 *		return -EFAULT;
	 *
	 * However there is no existing variable (num_processors,
	 * disabled_cpus, total_cpus, etc.) or bitmap (present, possbile,
	 * online, etc.) which describes BIOS-enabled CPUs, while
	 * cpu_online_maps can be easily changed due to various boot
	 * options and cpu hotplug events.
	 */
	cpu_hotplug_disable();

	ret = init_tdx_module();

	/*
	 * Turn off the TDX module in case of any error in the
	 * initialization process.  It's pointless to leave the
	 * module in an intermediate state.
	 */
	if (ret)
		shutdown_tdx_module();

	cpu_hotplug_enable();
	return ret;
}

/**
 * detect_tdx - Detect whether the TDX module has been loaded
 *
 * Detect whether the TDX module has been loaded and ready for
 * initialization.  This function can be called in parallel
 * by multiple callers.
 *
 * Call this function when the local cpu is already in VMX operation.
 *
 * Return: 0 if TDX module has been loaded, otherwise -ENODEV.
 */
int detect_tdx(void)
{
	int ret;

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNKNOWN:
		ret = __detect_tdx();
		break;
	case TDX_MODULE_NONE:
	case TDX_MODULE_SHUTDOWN:
		ret = -ENODEV;
		break;
	case TDX_MODULE_LOADED:
	case TDX_MODULE_INITIALIZED:
		ret = 0;
		break;
	default:
		WARN_ON(1);
		ret = -ENODEV;
	}

	mutex_unlock(&tdx_module_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(detect_tdx);

/**
 * init_tdx - Initialize the TDX module
 *
 * Initialize the TDX module to make it ready to run TD guests.
 * This function can be called in parallel by multiple callers.
 *
 * Call this function when all cpus are online and in VMX operation.
 * CPU hotplug is also temporarily disabled in this function.
 *
 * Return:
 *
 * * -0: The TDX module has been successfully initialized.
 * * -ENODEV: The TDX module is not loaded.
 * * -EFAULT: Fatal error during TDX module initialization.
 */
int init_tdx(void)
{
	int ret;

	mutex_lock(&tdx_module_lock);

	/* Detect the TDX module if it's not done yet */
	if (tdx_module_status == TDX_MODULE_UNKNOWN)
		__detect_tdx();

	switch (tdx_module_status) {
	case TDX_MODULE_NONE:
		ret = -ENODEV;
		break;
	case TDX_MODULE_LOADED:
		ret = __init_tdx();
		break;
	case TDX_MODULE_INITIALIZED:
		ret = 0;
		break;
	default:
		ret = -EFAULT;
		break;
	}
	mutex_unlock(&tdx_module_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(init_tdx);
