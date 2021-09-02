// SPDX-License-Identifier: GPL-2.0
/* Load and initialize TDX-module. */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cpu.h>

#include <asm/tdx_arch.h>
#include <asm/tdx_host.h>
#include <asm/cmdline.h>
#include <asm/virtext.h>

#include "seamcall.h"
#include "tdx-ops.h"
#include "p-seamldr.h"
#include "seam.h"

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

static enum TDX_MODULE_STATE tdx_module_state __initdata;

/* KeyID range reserved to TDX by BIOS */
static u32 tdx_keyids_start __initdata;
static u32 tdx_nr_keyids __initdata;

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
