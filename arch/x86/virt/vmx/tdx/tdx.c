// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2022 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) support
 */

#define pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <linux/align.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/tdx.h>
#include "tdx.h"

/* TDX module status during initialization */
enum tdx_module_status_t {
	/* TDX module hasn't been detected and initialized */
	TDX_MODULE_UNKNOWN,
	/* TDX module is not loaded */
	TDX_MODULE_NONE,
	/* TDX module is initialized */
	TDX_MODULE_INITIALIZED,
	/* TDX module is shut down due to initialization error */
	TDX_MODULE_SHUTDOWN,
};

static u32 tdx_keyid_start __ro_after_init;
static u32 tdx_keyid_num __ro_after_init;

static enum tdx_module_status_t tdx_module_status;
/* Prevent concurrent attempts on TDX detection and initialization */
static DEFINE_MUTEX(tdx_module_lock);

/* Below two are used in TDH.SYS.INFO SEAMCALL ABI */
static struct tdsysinfo_struct tdx_sysinfo;
static struct cmr_info tdx_cmr_array[MAX_CMRS] __aligned(CMR_INFO_ARRAY_ALIGNMENT);
static int tdx_cmr_num;

/*
 * Detect TDX private KeyIDs to see whether TDX has been enabled by the
 * BIOS.  Both initializing the TDX module and running TDX guest require
 * TDX private KeyID.
 *
 * TDX doesn't trust BIOS.  TDX verifies all configurations from BIOS
 * are correct before enabling TDX on any core.  TDX requires the BIOS
 * to correctly and consistently program TDX private KeyIDs on all CPU
 * packages.  Unless there is a BIOS bug, detecting a valid TDX private
 * KeyID range on BSP indicates TDX has been enabled by the BIOS.  If
 * there's such BIOS bug, it will be caught later when initializing the
 * TDX module.
 */
static int __init detect_tdx(void)
{
	int ret;

	/*
	 * IA32_MKTME_KEYID_PARTIONING:
	 *   Bit [31:0]:	Number of MKTME KeyIDs.
	 *   Bit [63:32]:	Number of TDX private KeyIDs.
	 */
	ret = rdmsr_safe(MSR_IA32_MKTME_KEYID_PARTITIONING, &tdx_keyid_start,
			&tdx_keyid_num);
	if (ret)
		return -ENODEV;

	if (!tdx_keyid_num)
		return -ENODEV;

	/*
	 * KeyID 0 is for TME.  MKTME KeyIDs start from 1.  TDX private
	 * KeyIDs start after the last MKTME KeyID.
	 */
	tdx_keyid_start++;

	pr_info("TDX enabled by BIOS. TDX private KeyID range: [%u, %u)\n",
			tdx_keyid_start, tdx_keyid_start + tdx_keyid_num);

	return 0;
}

static void __init clear_tdx(void)
{
	tdx_keyid_start = tdx_keyid_num = 0;
}

static int __init tdx_init(void)
{
	if (detect_tdx())
		return -ENODEV;

	/*
	 * Initializing the TDX module requires one TDX private KeyID.
	 * If there's only one TDX KeyID then after module initialization
	 * KVM won't be able to run any TDX guest, which makes the whole
	 * thing worthless.  Just disable TDX in this case.
	 */
	if (tdx_keyid_num < 2) {
		pr_info("Disable TDX as there's only one TDX private KeyID available.\n");
		goto no_tdx;
	}

	/*
	 * TDX requires X2APIC being enabled to prevent potential data
	 * leak via APIC MMIO registers.  Just disable TDX if not using
	 * X2APIC.
	 */
	if (!x2apic_enabled()) {
		pr_info("Disable TDX as X2APIC is not enabled.\n");
		goto no_tdx;
	}

	return 0;
no_tdx:
	clear_tdx();
	return -ENODEV;
}
early_initcall(tdx_init);

/* Return whether the BIOS has enabled TDX */
bool platform_tdx_enabled(void)
{
	return !!tdx_keyid_num;
}

/*
 * Data structure to make SEAMCALL on multiple CPUs concurrently.
 * @err is set to -EFAULT when SEAMCALL fails on any cpu.
 */
struct seamcall_ctx {
	u64 fn;
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	atomic_t err;
};

/*
 * Wrapper of __seamcall() to convert SEAMCALL leaf function error code
 * to kernel error code.  @seamcall_ret and @out contain the SEAMCALL
 * leaf function return code and the additional output respectively if
 * not NULL.
 */
static int seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		    u64 *seamcall_ret, struct tdx_module_output *out)
{
	u64 sret;

	sret = __seamcall(fn, rcx, rdx, r8, r9, out);

	/* Save SEAMCALL return code if caller wants it */
	if (seamcall_ret)
		*seamcall_ret = sret;

	/* SEAMCALL was successful */
	if (!sret)
		return 0;

	switch (sret) {
	case TDX_SEAMCALL_GP:
		/*
		 * platform_tdx_enabled() is checked to be true
		 * before making any SEAMCALL.
		 */
		WARN_ON_ONCE(1);
		fallthrough;
	case TDX_SEAMCALL_VMFAILINVALID:
		/* Return -ENODEV if the TDX module is not loaded. */
		return -ENODEV;
	case TDX_SEAMCALL_UD:
		/* Return -EINVAL if CPU isn't in VMX operation. */
		return -EINVAL;
	default:
		/* Return -EIO if the actual SEAMCALL leaf failed. */
		return -EIO;
	}
}

static void seamcall_smp_call_function(void *data)
{
	struct seamcall_ctx *sc = data;
	int ret;

	ret = seamcall(sc->fn, sc->rcx, sc->rdx, sc->r8, sc->r9, NULL, NULL);
	if (ret)
		atomic_set(&sc->err, -EFAULT);
}

/*
 * Call the SEAMCALL on all online CPUs concurrently.  Caller to check
 * @sc->err to determine whether any SEAMCALL failed on any cpu.
 */
static void seamcall_on_each_cpu(struct seamcall_ctx *sc)
{
	on_each_cpu(seamcall_smp_call_function, sc, true);
}

static int tdx_module_init_cpus(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_INIT };

	seamcall_on_each_cpu(&sc);

	return atomic_read(&sc.err);
}

static inline bool is_cmr_empty(struct cmr_info *cmr)
{
	return !cmr->size;
}

static inline bool is_cmr_ok(struct cmr_info *cmr)
{
	/* CMR must be page aligned */
	return IS_ALIGNED(cmr->base, PAGE_SIZE) &&
		IS_ALIGNED(cmr->size, PAGE_SIZE);
}

static void print_cmrs(struct cmr_info *cmr_array, int cmr_num,
		       const char *name)
{
	int i;

	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		pr_info("%s : [0x%llx, 0x%llx)\n", name,
				cmr->base, cmr->base + cmr->size);
	}
}

/* Check CMRs reported by TDH.SYS.INFO, and trim tail empty CMRs. */
static int trim_empty_cmrs(struct cmr_info *cmr_array, int *actual_cmr_num)
{
	struct cmr_info *cmr;
	int i, cmr_num;

	/*
	 * Intel TDX module spec, 20.7.3 CMR_INFO:
	 *
	 *   TDH.SYS.INFO leaf function returns a MAX_CMRS (32) entry
	 *   array of CMR_INFO entries. The CMRs are sorted from the
	 *   lowest base address to the highest base address, and they
	 *   are non-overlapping.
	 *
	 * This implies that BIOS may generate invalid empty entries
	 * if total CMRs are less than 32.  Need to skip them manually.
	 *
	 * CMR also must be 4K aligned.  TDX doesn't trust BIOS.  TDX
	 * actually verifies CMRs before it gets enabled, so anything
	 * doesn't meet above means kernel bug (or TDX is broken).
	 */
	cmr = &cmr_array[0];
	/* There must be at least one valid CMR */
	if (WARN_ON_ONCE(is_cmr_empty(cmr) || !is_cmr_ok(cmr)))
		goto err;

	cmr_num = *actual_cmr_num;
	for (i = 1; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];
		struct cmr_info *prev_cmr = NULL;

		/* Skip further empty CMRs */
		if (is_cmr_empty(cmr))
			break;

		/*
		 * Do sanity check anyway to make sure CMRs:
		 *  - are 4K aligned
		 *  - don't overlap
		 *  - are in address ascending order.
		 */
		if (WARN_ON_ONCE(!is_cmr_ok(cmr)))
			goto err;

		prev_cmr = &cmr_array[i - 1];
		if (WARN_ON_ONCE((prev_cmr->base + prev_cmr->size) >
					cmr->base))
			goto err;
	}

	/* Update the actual number of CMRs */
	*actual_cmr_num = i;

	/* Print kernel checked CMRs */
	print_cmrs(cmr_array, *actual_cmr_num, "Kernel-checked-CMR");

	return 0;
err:
	pr_info("[TDX broken ?]: Invalid CMRs detected\n");
	print_cmrs(cmr_array, cmr_num, "BIOS-CMR");
	return -EINVAL;
}

static int tdx_get_sysinfo(void)
{
	struct tdx_module_output out;
	int ret;

	BUILD_BUG_ON(sizeof(struct tdsysinfo_struct) != TDSYSINFO_STRUCT_SIZE);

	ret = seamcall(TDH_SYS_INFO, __pa(&tdx_sysinfo), TDSYSINFO_STRUCT_SIZE,
			__pa(tdx_cmr_array), MAX_CMRS, NULL, &out);
	if (ret)
		return ret;

	/* R9 contains the actual entries written the CMR array. */
	tdx_cmr_num = out.r9;

	pr_info("TDX module: atributes 0x%x, vendor_id 0x%x, major_version %u, minor_version %u, build_date %u, build_num %u",
		tdx_sysinfo.attributes, tdx_sysinfo.vendor_id,
		tdx_sysinfo.major_version, tdx_sysinfo.minor_version,
		tdx_sysinfo.build_date, tdx_sysinfo.build_num);

	/*
	 * trim_empty_cmrs() updates the actual number of CMRs by
	 * dropping all tail empty CMRs.
	 */
	return trim_empty_cmrs(tdx_cmr_array, &tdx_cmr_num);
}

/*
 * Detect and initialize the TDX module.
 *
 * Return -ENODEV when the TDX module is not loaded, 0 when it
 * is successfully initialized, or other error when it fails to
 * initialize.
 */
static int init_tdx_module(void)
{
	int ret;

	/*
	 * Call TDH.SYS.INIT to do the global initialization of
	 * the TDX module.  It also detects the module.
	 */
	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL, NULL);
	if (ret)
		goto out;

	/* Logical-cpu scope initialization */
	ret = tdx_module_init_cpus();
	if (ret)
		goto out;

	ret = tdx_get_sysinfo();
	if (ret)
		goto out;

	/*
	 * Return -EINVAL until all steps of TDX module initialization
	 * process are done.
	 */
	ret = -EINVAL;
out:
	return ret;
}

static void shutdown_tdx_module(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_SHUTDOWN };

	seamcall_on_each_cpu(&sc);
}

static int __tdx_enable(void)
{
	int ret;

	/*
	 * Initializing the TDX module requires doing SEAMCALL on all
	 * boot-time present CPUs.  For simplicity temporarily disable
	 * CPU hotplug to prevent any CPU from going offline during
	 * the initialization.
	 */
	cpus_read_lock();

	/*
	 * Check whether all boot-time present CPUs are online and
	 * return early with a message so the user can be aware.
	 *
	 * Note a non-buggy BIOS should never support physical (ACPI)
	 * CPU hotplug when TDX is enabled, and all boot-time present
	 * CPU should be enabled in MADT, so there should be no
	 * disabled_cpus and num_processors won't change at runtime
	 * either.
	 */
	if (disabled_cpus || num_online_cpus() != num_processors) {
		pr_err("Unable to initialize the TDX module when there's offline CPU(s).\n");
		ret = -EINVAL;
		goto out;
	}

	ret = init_tdx_module();
	if (ret == -ENODEV) {
		pr_info("TDX module is not loaded.\n");
		tdx_module_status = TDX_MODULE_NONE;
		goto out;
	}

	/*
	 * Shut down the TDX module in case of any error during the
	 * initialization process.  It's meaningless to leave the TDX
	 * module in any middle state of the initialization process.
	 *
	 * Shutting down the module also requires doing SEAMCALL on all
	 * MADT-enabled CPUs.  Do it while CPU hotplug is disabled.
	 *
	 * Return all errors during the initialization as -EFAULT as the
	 * module is always shut down.
	 */
	if (ret) {
		pr_info("Failed to initialize TDX module. Shut it down.\n");
		shutdown_tdx_module();
		tdx_module_status = TDX_MODULE_SHUTDOWN;
		ret = -EFAULT;
		goto out;
	}

	pr_info("TDX module initialized.\n");
	tdx_module_status = TDX_MODULE_INITIALIZED;
out:
	cpus_read_unlock();

	return ret;
}

/**
 * tdx_enable - Enable TDX by initializing the TDX module
 *
 * Caller to make sure all CPUs are online and in VMX operation before
 * calling this function.  CPU hotplug is temporarily disabled internally
 * to prevent any cpu from going offline.
 *
 * This function can be called in parallel by multiple callers.
 *
 * Return:
 *
 * * 0:		The TDX module has been successfully initialized.
 * * -ENODEV:	The TDX module is not loaded, or TDX is not supported.
 * * -EINVAL:	The TDX module cannot be initialized due to certain
 *		conditions are not met (i.e. when not all MADT-enabled
 *		CPUs are not online).
 * * -EFAULT:	Other internal fatal errors, or the TDX module is in
 *		shutdown mode due to it failed to initialize in previous
 *		attempts.
 */
int tdx_enable(void)
{
	int ret;

	if (!platform_tdx_enabled())
		return -ENODEV;

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNKNOWN:
		ret = __tdx_enable();
		break;
	case TDX_MODULE_NONE:
		ret = -ENODEV;
		break;
	case TDX_MODULE_INITIALIZED:
		ret = 0;
		break;
	default:
		WARN_ON_ONCE(tdx_module_status != TDX_MODULE_SHUTDOWN);
		ret = -EFAULT;
		break;
	}

	mutex_unlock(&tdx_module_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tdx_enable);
