// SPDX-License-Identifier: GPL-2.0
/* Load and initialize TDX-module. */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/earlycpio.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/cpu.h>

#include <asm/tdx_host.h>
#include <asm/virtext.h>
#include <asm/apic.h>

#include "seamcall.h"
#include "p-seamldr.h"
#include "seam.h"

enum TDX_HOST_OPTION {
	TDX_HOST_OFF,
	TDX_HOST_ON,
};

static enum TDX_HOST_OPTION tdx_host __initdata;

static int __init tdx_host_param(char *str)
{
	if (!strcmp(str, "on"))
		tdx_host = TDX_HOST_ON;

	return 0;
}
early_param("tdx_host", tdx_host_param);

static int __init tdx_early_init(void)
{
	int ret;

	/* Avoid TDX overhead when opt-in is not present. */
	if (tdx_host != TDX_HOST_ON)
		return 0;

	ret = load_p_seamldr();
	return ret;
}
early_initcall(tdx_early_init);

static char *tdx_module_name __initdata = "intel-seam/libtdx.so";
static size_t tdx_module_len __initdata;
static char *tdx_sigstruct_name __initdata = "intel-seam/libtdx.so.sigstruct";
static size_t tdx_sigstruct_len;

static int __init setup_tdx_module(char *str)
{
	tdx_module_len = strlen(str) + 1;
	tdx_module_name = memblock_alloc(tdx_module_len, 0);
	if (!tdx_module_name) {
		tdx_module_len = 0;
		return -ENOMEM;
	}

	strscpy(tdx_module_name, str, tdx_module_len);
	return 1;
}
__setup("tdx_module=", setup_tdx_module);

static int __init setup_tdx_sigstruct(char *str)
{
	tdx_sigstruct_len = strlen(str) + 1;
	tdx_sigstruct_name = memblock_alloc(tdx_sigstruct_len, 0);
	if (!tdx_sigstruct_name) {
		tdx_sigstruct_len = 0;
		return -ENOMEM;
	}

	strscpy(tdx_sigstruct_name, str, tdx_sigstruct_len);
	return 1;
}
__setup("tdx_sigstruct=", setup_tdx_sigstruct);

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
	/*
	 * No SEAMCALLs are allowed so that the TDX module is not functional.
	 * It's ready for P-SEAMLDR to update the TDX module.  As something went
	 * wrong, a system reboot would be needed to fix it.
	 */
	TDX_MODULE_ERROR,
};

/* TODO: export the state via sysfs. */
static enum TDX_MODULE_STATE tdx_module_state __ro_after_init;

/*
 * free_seamldr_params - free allocated for seamldr_params including referenced
 *			 pages by params.
 * @params: virtual address of struct seamldr_params to free
 */
static void __init free_seamldr_params(struct seamldr_params *params)
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
static struct seamldr_params * __init __no_sanitize_address alloc_seamldr_params(
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
static void __init tdx_install_module_cpu(void *data)
{
	struct tdx_install_module_data *install_module = data;
	int ret = seamldr_install(__pa(install_module->params));

	if (ret)
		atomic_set(&install_module->error, ret);
}

/*
 * tdx_install_module - load TDX module by P-SEAMLDR seam_install call.
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
			goto out;
	}

	/* TODO: Early initialization. */

out:
	free_seamldr_params(params);
	return ret;
}

/*
 * Look for seam module binary in built-in firmware and initrd, and load it on
 * all CPUs through P-SEAMLDR.
 */
static int __init tdx_arch_init(void)
{
	struct cpio_data module, sigstruct;
	int vmxoff_err;
	int ret = 0;

	if (!boot_cpu_has(X86_FEATURE_SEAM))
		goto out_free;

	pr_info("Loading TDX module via P-SEAMLDR with %s and %s\n",
		tdx_module_name, tdx_sigstruct_name);

	ret = -EINVAL;
	if (!seam_get_firmware(&module, tdx_module_name) ||
	    !seam_get_firmware(&sigstruct, tdx_sigstruct_name)) {
		ret = -ENOENT;
		goto out_free;
	}

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
		goto out;
	}

	/* SEAMCALL requires to enable VMXON on CPUs. */
	ret = seam_alloc_init_vmcs_tmp_set();
	if (ret)
		goto out;
	ret = seam_vmxon_on_each_cpu();
	if (ret)
		goto out;

	ret = tdx_load_module(module.data, module.size,
			sigstruct.data, sigstruct.size, SEAMLDR_SCENARIO_LOAD);
	if (ret) {
		pr_info("Failed to load TDX module.\n");
		goto out;
	}
	pr_info("Loaded TDX module via P-SEAMLDR.\n");
	tdx_module_state = TDX_MODULE_LOADED;

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
	if (ret)
		tdx_module_state = TDX_MODULE_ERROR;
	cpus_read_unlock();

	seam_free_vmcs_tmp_set();

out_free:
	if (tdx_module_len)
		memblock_free_late(__pa(tdx_module_name), tdx_module_len);
	if (tdx_sigstruct_len)
		memblock_free_late(__pa(tdx_sigstruct_name), tdx_sigstruct_len);
	return ret;
}
/*
 * arch_initcall() is chosen to satisfy the following conditions.
 * - After P-SEAMLDR is loaded.
 * - After SMP initialization.
 */
arch_initcall(tdx_arch_init);
