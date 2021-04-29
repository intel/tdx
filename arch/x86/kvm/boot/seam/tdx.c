// SPDX-License-Identifier: GPL-2.0
#include <linux/earlycpio.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/percpu.h>
#include <linux/memblock.h>
#include <linux/idr.h>
#include <linux/sort.h>

#include <asm/cpu.h>
#include <asm/cmdline.h>
#include <asm/kvm_boot.h>
#include <asm/sync_core.h>
#include <asm/virtext.h>
#include <asm/tlbflush.h>
#include <asm/e820/api.h>

#include "seamloader.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

#include "vmx/tdx_arch.h"
#include "vmx/tdx_errno.h"

#include "vmx/vmcs.h"

struct seamldr_info p_seamldr_info __aligned(256);

static bool __init tdx_all_cpus_available(void)
{
	/*
	 * CPUs detected in ACPI can be marked as disabled due to:
	 *   1) disabled in ACPI MADT table
	 *   2) disabled by 'disable_cpu_apicid' kernel parameter, which
	 *     disables CPU with particular APIC id.
	 *   3) limited by 'nr_cpus' kernel parameter.
	 */
	if (disabled_cpus) {
		pr_info("Disabled CPUs detected");
		goto err;
	}

	if (num_possible_cpus() < num_processors) {
		pr_info("Number of CPUs limited by 'possible_cpus' kernel param");
		goto err;
	}

#ifdef CONFIG_SMP
	if (setup_max_cpus < num_processors) {
		pr_info("Boot-time CPUs limited by 'maxcpus' kernel param");
		goto err;
	}
#endif

	return true;

err:
	pr_cont(", skipping TDX-SEAM load/config.\n");
	return false;
}

static bool __init tdx_get_firmware(struct cpio_data *blob, const char *name)
{
	char path[64];
	long offset;
	void *data;
	size_t size;
	static const char * const search_path[] = {
		"lib/firmware/%s",
		"usr/lib/firmware/%s",
		"opt/intel/%s"
	};
	int i;

	if (get_builtin_firmware(blob, name))
		return true;

	if (!IS_ENABLED(CONFIG_BLK_DEV_INITRD) || !initrd_start)
		return false;

	for (i = 0; i < ARRAY_SIZE(search_path); i++) {
		offset = 0;
		data = (void *)initrd_start;
		size = initrd_end - initrd_start;
		snprintf(path, sizeof(path), search_path[i], name);
		while (size > 0) {
			*blob = find_cpio_data(path, data, size, &offset);

			/* find the filename, the returned blob name is empty */
			if (blob->data && blob->name[0] == '\0')
				return true;

			if (!blob->data)
				break;

			/* match the item with the same path prefix, skip it*/
			data += offset;
			size -= offset;
		}
	}

	return false;
}

void __init tdx_seam_init(void)
{
	const char *np_seamldr_name = "intel-seam/np-seamldr.acm";
	struct cpio_data seamldr;

	if (cmdline_find_option_bool(boot_command_line, "disable_tdx"))
		return;

	/*
	 * Don't load/configure SEAM if not all CPUs can be brought up during
	 * smp_init(), TDX must execute TDH_SYS_LP_INIT on all logical processors.
	 */
	if (!tdx_all_cpus_available())
		goto error;

	if (!tdx_get_firmware(&seamldr, np_seamldr_name)) {
		pr_err("no np-seamldr found\n");
		goto error;
	}

	if (seam_load_module(seamldr.data, seamldr.size)) {
		pr_err("failed to load np-seamldr\n");
		goto error;
	}

	if (seamldr_info(__pa(&p_seamldr_info))) {
		pr_info("Failed to get p-seamldr info\n");
		goto error;
	}
	pr_info("TDX P-SEAMLDR: "
		"attributes 0x%0x vendor_id 0x%x "
		"build_date %d build_num 0x%x "
		"minor_version 0x%x major_version 0x%x.\n",
		p_seamldr_info.attributes,
		p_seamldr_info.vendor_id,
		p_seamldr_info.build_date,
		p_seamldr_info.build_num,
		p_seamldr_info.minor_version,
		p_seamldr_info.major_version);

	setup_force_cpu_cap(X86_FEATURE_TDX);
	pr_info("tdx module successfully initialized.\n");
	return;

error:
	pr_err("can't load/init TDX module. disabling TDX feature.\n");
	setup_clear_cpu_cap(X86_FEATURE_TDX);
}
