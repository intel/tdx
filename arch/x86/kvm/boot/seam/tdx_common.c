// SPDX-License-Identifier: GPL-2.0
/* Common functions/symbols for SEAMLDR and KVM. */

#include <linux/cpuhotplug.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/idr.h>

#include <asm/kvm_boot.h>

#include "vmx/tdx_arch.h"
#include "vmx/tdx_errno.h"

/*
 * TDX system information returned by TDSYSINFO.
 */
struct tdsysinfo_struct tdx_tdsysinfo;

/* KeyID range reserved to TDX by BIOS */
u32 tdx_keyids_start;
u32 tdx_nr_keyids;

u32 tdx_seam_keyid __ro_after_init;
EXPORT_SYMBOL_GPL(tdx_seam_keyid);

/* TDX keyID pool */
static DEFINE_IDA(tdx_keyid_pool);

static int *tdx_package_masters __ro_after_init;

static int tdx_starting_cpu(unsigned int cpu)
{
	int pkg = topology_physical_package_id(cpu);

	/*
	 * If this package doesn't have a master CPU for IPI operation, use this
	 * CPU as package master.
	 */
	if (tdx_package_masters && tdx_package_masters[pkg] == -1)
		tdx_package_masters[pkg] = cpu;

	return 0;
}

static int tdx_dying_cpu(unsigned int cpu)
{
	int pkg = topology_physical_package_id(cpu);
	int other;

	if (!tdx_package_masters || tdx_package_masters[pkg] != cpu)
		return 0;

	/*
	 * If offlining cpu was used as package master, find other online cpu on
	 * this package.
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

	return 0;
}

/*
 * Setup one-cpu-per-pkg array to do package-scoped SEAMCALLs. The array is
 * only necessary if there are multiple packages.
 */
int __init init_package_masters(void)
{
	int cpu, pkg, nr_filled, nr_pkgs;

	nr_pkgs = topology_max_packages();
	if (nr_pkgs == 1)
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
		if (++nr_filled == topology_max_packages())
			break;
	}

	if (WARN_ON(nr_filled != topology_max_packages())) {
		kfree(tdx_package_masters);
		return -EIO;
	}

	if (cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "tdx/cpu:starting",
				      tdx_starting_cpu, tdx_dying_cpu) < 0) {
		kfree(tdx_package_masters);
		return -EIO;
	}

	return 0;
}

int tdx_seamcall_on_each_pkg(int (*fn)(void *), void *param)
{
	int ret = 0;
	int i;

	cpus_read_lock();
	if (!tdx_package_masters) {
		ret = fn(param);
		goto out;
	}

	for (i = 0; i < topology_max_packages(); i++) {
		ret = smp_call_on_cpu(tdx_package_masters[i], fn, param, 1);
		if (ret)
			break;
	}

out:
	cpus_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(tdx_seamcall_on_each_pkg);

const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	if (boot_cpu_has(X86_FEATURE_TDX))
		return &tdx_tdsysinfo;

	return NULL;
}
EXPORT_SYMBOL_GPL(tdx_get_sysinfo);

int tdx_keyid_alloc(void)
{
	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -EINVAL;

	if (WARN_ON_ONCE(!tdx_keyids_start || !tdx_nr_keyids))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_keyid_pool, tdx_keyids_start + 1,
			       tdx_keyids_start + tdx_nr_keyids - 1,
			       GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(tdx_keyid_alloc);

void tdx_keyid_free(int keyid)
{
	if (!keyid || keyid < 0)
		return;

	ida_free(&tdx_keyid_pool, keyid);
}
EXPORT_SYMBOL_GPL(tdx_keyid_free);

static struct tdx_seamcall_status {
	u64 err_code;
	const char *err_name;
} tdx_seamcall_status_codes[] = {TDX_SEAMCALL_STATUS_CODES};

const char *tdx_seamcall_error_name(u64 error_code)
{
	struct tdx_seamcall_status status;
	int i;

	for (i = 0; i < ARRAY_SIZE(tdx_seamcall_status_codes); i++) {
		status = tdx_seamcall_status_codes[i];
		if ((error_code & TDX_SEAMCALL_STATUS_MASK) == status.err_code)
			return status.err_name;
	}

	return "Unknown SEAMCALL status code";
}
EXPORT_SYMBOL_GPL(tdx_seamcall_error_name);
