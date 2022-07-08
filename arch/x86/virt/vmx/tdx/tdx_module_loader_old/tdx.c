// SPDX-License-Identifier: GPL-2.0
/* Load and initialize TDX-module. */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/earlycpio.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/platform_device.h>
#include <linux/firmware.h>

#include <asm/irq_vectors.h>
#include <asm/apic.h>
#include <asm/nmi.h>
#include <asm/cmdline.h>

#include "tdx_errno.h"
#include "tdx_arch.h"
#include "tdx_host.h"
#include "seamcall.h"
#include "p-seamldr.h"
#include "seam.h"

/* Intel SEAMRR */
#define MSR_IA32_SEAMRR_PHYS_BASE       0x00001400
#define MSR_IA32_SEAMRR_PHYS_MASK       0x00001401

#define MSR_IA32_SEAMRR_PHYS_BASE_CONFIGURED    BIT_ULL(3)
#define MSR_IA32_SEAMRR_PHYS_MASK_ENABLED       BIT_ULL(11)
#define MSR_IA32_SEAMRR_PHYS_MASK_LOCKED        BIT_ULL(10)

#define MTRRCAP_SEAMRR                  BIT(15)

/*
 * is_seamrr_enabled - check if seamrr is supported.
 */
static bool __init is_seamrr_enabled(void)
{
	u64 mtrrcap, seamrr_base, seamrr_mask;

	if (!boot_cpu_has(X86_FEATURE_MTRR))
		return false;

	/* MTRRcap.SEAMRR indicates the support of SEAMRR_PHYS_{BASE, MASK} */
	rdmsrl(MSR_MTRRcap, mtrrcap);
	if (!(mtrrcap & MTRRCAP_SEAMRR))
		return false;

	rdmsrl(MSR_IA32_SEAMRR_PHYS_BASE, seamrr_base);
	if (!(seamrr_base & MSR_IA32_SEAMRR_PHYS_BASE_CONFIGURED)) {
		pr_info("SEAMRR base is not configured by BIOS\n");
		return false;
	}

	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, seamrr_mask);
	if (!(seamrr_mask & MSR_IA32_SEAMRR_PHYS_MASK_ENABLED)) {
		pr_info("SEAMRR is not enabled by BIOS\n");
		return false;
	}

	return true;
}

static bool found_seam;
static int __init tdx_host_early_init(void)
{
	int ret;

	if (!cmdline_find_option_bool(boot_command_line, "tdx_module_loader_old"))
		return 0;

	pr_err("tdx_module_loader_old is supplied\n");

	/* TDX requires SEAM mode. */
	if (!is_seamrr_enabled())
		return -EOPNOTSUPP;

	/* TDX(SEAMCALL) requires VMX. */
	ret = seam_init_vmx_early();
	if (ret)
		return ret;

	ret = p_seamldr_get_info();
	if (ret == -EIO) {
		pr_err("No P-SEAMLDR loaded by BIOS.\n");

		ret = load_p_seamldr();
		if (ret)
			return ret;

		ret = p_seamldr_get_info();
		if (ret) {
			pr_err("Get P-SEAMLDR failed with %d\n", ret);
			return ret;
		}
	} else if (ret) {
		pr_err("Get P-SEAMLDR failed with %d\n", ret);
		return ret;
	}

	found_seam = true;
	return 0;
}
early_initcall(tdx_host_early_init);

static char tdx_module_name[128] __initdata = "intel-seam/libtdx.so";
static char tdx_sigstruct_name[128] __initdata = "intel-seam/libtdx.so.sigstruct";

/*
 * runtime update of TDX module is future task.  Track state of TDX module as
 * preliminary and export the state via sysfs for admin.
 */
enum TDX_MODULE_STATE {
	TDX_MODULE_NOT_LOADED = 0,
	/*
	 * The TDX module is loaded into SEAM region.  Not functional yet until
	 * initialization is done.
	 */
	TDX_MODULE_LOADED,
	/* Initialization is done so that the TDX module is functional. */
	TDX_MODULE_INITIALIZED,
	/* TDX module is already shut down. Futher SEAMCALLs are prevented */
	TDX_MODULE_SHUTDOWN,
	/*
	 * No SEAMCALLs are allowed so that the TDX module is not functional.
	 * It's ready for P-SEAMLDR to update the TDX module.  As something went
	 * wrong, a system reboot would be needed to fix it.
	 */
	TDX_MODULE_ERROR,
};

/* Protect tdx_module_state */
static DEFINE_MUTEX(tdx_mutex);

bool is_debug_seamcall_available __read_mostly = true;

bool is_nonarch_seamcall_available __read_mostly = true;

/*
 * free_seamldr_params - free allocated for seamldr_params including referenced
 *			 pages by params.
 * @params: virtual address of struct seamldr_params to free
 */
static void free_seamldr_params(struct seamldr_params *params)
{
	int i;

	if (!params)
		return;

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
 *
 * KASAN thinks memcpy from initrd image via cpio image invalid access.
 * Here module and sigstruct come from initrd image, not from memory allocator.
 * Annotate it with __no_sanitize_address to apiece KASAN.
 */
static struct seamldr_params *__no_sanitize_address alloc_seamldr_params(
	const void *module, unsigned long module_size, const void *sigstruct,
	unsigned long sigstruct_size, u64 scenario)
{
	struct seamldr_params *params = NULL;
	void *sigstruct_page = NULL;
	void *module_page = NULL;
	int i;

	BUILD_BUG_ON(SEAMLDR_SIGSTRUCT_SIZE > PAGE_SIZE);

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
	params = (struct seamldr_params *)get_zeroed_page(GFP_KERNEL);
	if (!params) {
		pr_err("Unable to allocate memory for SEAMLDR_PARAMS\n");
		goto out;
	}
	params->scenario = scenario;

	/* SEAMLDR requires the sigstruct to be 4K aligned. */
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

struct tdx_install_module_data {
	struct seamldr_params *params;
	atomic_t error;
};

/* Load seam module on one CPU */
static void tdx_install_module_cpu(void *data)
{
	struct tdx_install_module_data *install_module = data;
	int ret = seamldr_install(__pa(install_module->params));

	if (ret)
		atomic_set(&install_module->error, ret);
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
static int tdx_load_module(
	const void *module, unsigned long module_size, const void *sigstruct,
	unsigned long sigstruct_size, u64 scenario)
{
	struct seamldr_params *params;
	struct tdx_install_module_data install_module;
	int cpu;
	int ret = 0;

	params = alloc_seamldr_params(module, module_size, sigstruct,
				      sigstruct_size, scenario);
	if (IS_ERR(params))
		return -ENOMEM;

	install_module.params = params;
	atomic_set(&install_module.error, 0);
	/*
	 * Call the function on each CPUs one by one to avoid NMI watchdog.  If
	 * there are many CPUs, tdx_install_module_cpu() may contend with the
	 * spinlock of seamldr_install() for long time to trigger NMI watchdog.
	 */
	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, tdx_install_module_cpu,
					&install_module, 1);
		/* don't care what exact error occurred on which cpus. */
		ret = atomic_read(&install_module.error);
		if (ret)
			break;
	}

	free_seamldr_params(params);
	return ret;
}

static int __init tdx_load_module_boot(void)
{
	struct cpio_data module, sigstruct;

	pr_info("Loading TDX module via P-SEAMLDR with %s and %s\n",
		tdx_module_name, tdx_sigstruct_name);

	if (!seam_get_firmware(&module, tdx_module_name) ||
	    !seam_get_firmware(&sigstruct, tdx_sigstruct_name)) {
		pr_err("no TDX module or sigstruct found %s/%s\n",
		       tdx_module_name, tdx_sigstruct_name);
		return -ENOENT;
	}

	return tdx_load_module(module.data, module.size, sigstruct.data,
			       sigstruct.size, SEAMLDR_SCENARIO_LOAD);
}

/*
 * Look for seam module binary in built-in firmware and initrd, and load it on
 * all CPUs through P-SEAMLDR.
 */
static int __init tdx_arch_init(void)
{
	int vmxoff_err;
	int ret = 0;

	if (!found_seam)
		goto out_free;

	/*
	 * Because smp is enabled, prevent potential concurrent cpu
	 * online/offline.
	 */
	cpus_read_lock();

	/*
	 * Initialization of TDX module needs to involve all CPUs.  Ensure all
	 * CPUs are online.  All CPUs are required to be initialized by
	 * TDH.SYS.LP.INIT otherwise TDH.SYS.CONFIG fails.
	 */
	if (!cpumask_equal(cpu_present_mask, cpu_online_mask)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	mutex_lock(&tdx_mutex);

	/* SEAMCALL requires to enable VMXON on CPUs. */
	ret = seam_vmxon_on_each_cpu();
	if (ret)
		goto out;

	if (!tdx_module_loaded()) {
		pr_err("No TDX module loaded by BIOS.\n");

		ret = tdx_load_module_boot();
		if (ret) {
			pr_info("Failed to load TDX module.\n");
			goto out;
		}
		pr_info("Loaded TDX module via P-SEAMLDR.\n");
	} else if ((bootloader_type >> 4) == 0xd){
		pr_info("It's a kexec'ed kernel, loading new TDX module kernel itself to overwrite old one\n");

		ret = tdx_load_module_boot();
		if (ret) {
			pr_info("Failed to load TDX module.\n");
			goto out;
		}
		pr_info("Loaded TDX module via P-SEAMLDR.\n");
	}

out:
	/*
	 * Other codes (Especially kvm_intel) expect that they're the first to
	 * use VMX.  That is, VMX is off on their initialization.  Maintain the
	 * assumption to keep them working.
	 */
	vmxoff_err = seam_vmxoff_on_each_cpu();
	if (vmxoff_err) {
		pr_info("Failed to VMXOFF.\n");
		if (!ret)
			ret = vmxoff_err;
	}
	mutex_unlock(&tdx_mutex);
out_unlock:
	cpus_read_unlock();
out_free:
	return ret;
}
/*
 * arch_initcall() is chosen to satisfy the following conditions.
 * - After P-SEAMLDR is loaded.
 * - After SMP initialization.
 */
arch_initcall(tdx_arch_init);
