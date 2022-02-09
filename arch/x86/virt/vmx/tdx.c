// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2022 Intel Corporation.
 *
 * Intel Trusted Domain Extensions (TDX) support
 */

#define pr_fmt(fmt)	"tdx: " fmt

#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/mutex.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/math.h>
#include <linux/sort.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/cpufeature.h>
#include <asm/cpufeatures.h>
#include <asm/virtext.h>
#include <asm/e820/api.h>
#include <asm/pgtable.h>
#include <asm/smp.h>
#include <asm/tdx.h>
#include "tdx.h"

/* Support Intel Secure Arbitration Mode Range Registers (SEAMRR) */
#define MTRR_CAP_SEAMRR			BIT(15)

/* Core-scope Intel SEAMRR base and mask registers. */
#define MSR_IA32_SEAMRR_PHYS_BASE	0x00001400
#define MSR_IA32_SEAMRR_PHYS_MASK	0x00001401

#define SEAMRR_PHYS_BASE_CONFIGURED	BIT_ULL(3)
#define SEAMRR_PHYS_MASK_ENABLED	BIT_ULL(11)
#define SEAMRR_PHYS_MASK_LOCKED		BIT_ULL(10)

#define SEAMRR_ENABLED_BITS	\
	(SEAMRR_PHYS_MASK_ENABLED | SEAMRR_PHYS_MASK_LOCKED)

/*
 * Intel Trusted Domain CPU Architecture Extension spec:
 *
 * IA32_MKTME_KEYID_PARTIONING:
 *
 *   Bit [31:0]: number of MKTME KeyIDs.
 *   Bit [63:32]: number of TDX private KeyIDs.
 *
 * TDX private KeyIDs start after the last MKTME KeyID.
 */
#define MSR_IA32_MKTME_KEYID_PARTITIONING	0x00000087

#define TDX_KEYID_START(_keyid_part)	\
		((u32)(((_keyid_part) & 0xffffffffull) + 1))
#define TDX_KEYID_NUM(_keyid_part)	((u32)((_keyid_part) >> 32))

/* TDMR must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT_ULL(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

/* Align up and down the address to TDMR boundary */
#define TDMR_ALIGN_DOWN(_addr)	ALIGN_DOWN((_addr), TDMR_ALIGNMENT)
#define TDMR_ALIGN_UP(_addr)	ALIGN((_addr), TDMR_ALIGNMENT)

/* TDMR's start and end address */
#define TDMR_START(_tdmr)	((_tdmr)->base)
#define TDMR_END(_tdmr)		((_tdmr)->base + (_tdmr)->size)

/* Page sizes supported by TDX */
enum tdx_page_sz {
	TDX_PG_4K = 0,
	TDX_PG_2M,
	TDX_PG_1G,
	TDX_PG_MAX,
};

#define TDX_HPAGE_SHIFT	9

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

/* BIOS must configure SEAMRR registers for all cores consistently */
static u64 seamrr_base, seamrr_mask;

static u32 tdx_keyid_start;
static u32 tdx_keyid_num;

static enum tdx_module_status_t tdx_module_status;

/* Prevent concurrent attempts on TDX detection and initialization */
static DEFINE_MUTEX(tdx_module_lock);

static struct p_seamldr_info p_seamldr_info;

/* Base address of CMR array needs to be 512 bytes aligned. */
static struct cmr_info tdx_cmr_array[MAX_CMRS] __aligned(CMR_INFO_ARRAY_ALIGNMENT);
static int tdx_cmr_num;
static struct tdsysinfo_struct tdx_sysinfo;

/* TDX global KeyID to protect TDX metadata */
static u32 __read_mostly tdx_global_keyid;

u32 tdx_get_global_keyid(void)
{
	return tdx_global_keyid;
}
EXPORT_SYMBOL_GPL(tdx_get_global_keyid);

static bool enable_tdx_host;

static int __init tdx_host_setup(char *s)
{
	if (!strcmp(s, "on"))
		enable_tdx_host = true;
	return 1;
}
__setup("tdx_host=", tdx_host_setup);

bool __seamrr_enabled(void)
{
	return (seamrr_mask & SEAMRR_ENABLED_BITS) == SEAMRR_ENABLED_BITS;
}
EXPORT_SYMBOL_GPL(__seamrr_enabled);

static void detect_seam_bsp(struct cpuinfo_x86 *c)
{
	u64 mtrrcap, base, mask;

	/* SEAMRR is reported via MTRRcap */
	if (!boot_cpu_has(X86_FEATURE_MTRR))
		return;

	rdmsrl(MSR_MTRRcap, mtrrcap);
	if (!(mtrrcap & MTRR_CAP_SEAMRR))
		return;

	rdmsrl(MSR_IA32_SEAMRR_PHYS_BASE, base);
	if (!(base & SEAMRR_PHYS_BASE_CONFIGURED)) {
		pr_info("SEAMRR base is not configured by BIOS\n");
		return;
	}

	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, mask);
	if ((mask & SEAMRR_ENABLED_BITS) != SEAMRR_ENABLED_BITS) {
		pr_info("SEAMRR is not enabled by BIOS\n");
		return;
	}

	seamrr_base = base;
	seamrr_mask = mask;
}

static void detect_seam_ap(struct cpuinfo_x86 *c)
{
	u64 base, mask;

	/*
	 * Don't bother to detect this AP if SEAMRR is not
	 * enabled after earlier detections.
	 */
	if (!__seamrr_enabled())
		return;

	rdmsrl(MSR_IA32_SEAMRR_PHYS_BASE, base);
	rdmsrl(MSR_IA32_SEAMRR_PHYS_MASK, mask);

	if (base == seamrr_base && mask == seamrr_mask)
		return;

	pr_err("Inconsistent SEAMRR configuration by BIOS\n");
	/* Mark SEAMRR as disabled. */
	seamrr_base = 0;
	seamrr_mask = 0;
}

static void detect_seam(struct cpuinfo_x86 *c)
{
	if (c == &boot_cpu_data)
		detect_seam_bsp(c);
	else
		detect_seam_ap(c);
}

/* TDX KeyID pool */
static DEFINE_IDA(tdx_keyid_pool);

int tdx_keyid_alloc(void)
{
	if (WARN_ON_ONCE(!tdx_keyid_start || !tdx_keyid_num))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_keyid_pool, tdx_keyid_start + 1,
			       tdx_keyid_start + tdx_keyid_num - 1,
			       GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(tdx_keyid_alloc);

void tdx_keyid_free(int keyid)
{
	/* keyid = 0 is reserved. */
	if (!keyid || keyid <= 0)
		return;

	ida_free(&tdx_keyid_pool, keyid);
}
EXPORT_SYMBOL_GPL(tdx_keyid_free);

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

	rdmsrl(MSR_IA32_MKTME_KEYID_PARTITIONING, keyid_part);

	if ((tdx_keyid_start == TDX_KEYID_START(keyid_part)) &&
			(tdx_keyid_num == TDX_KEYID_NUM(keyid_part)))
		return;

	pr_err("Inconsistent TDX KeyID configuration among packages by BIOS\n");
	tdx_keyid_start = 0;
	tdx_keyid_num = 0;
}

static void detect_tdx_keyids(struct cpuinfo_x86 *c)
{
	if (c == &boot_cpu_data)
		detect_tdx_keyids_bsp(c);
	else
		detect_tdx_keyids_ap(c);
}

void tdx_detect_cpu(struct cpuinfo_x86 *c)
{
	detect_seam(c);
	detect_tdx_keyids(c);
}

static bool seamrr_enabled(void)
{
	/*
	 * To detect any BIOS misconfiguration among cores, all logical
	 * cpus must have been brought up at least once.  This is true
	 * unless 'maxcpus' kernel command line is used to limit the
	 * number of cpus to be brought up during boot time.  However
	 * 'maxcpus' is basically an invalid operation mode due to the
	 * MCE broadcast problem, and it should not be used on a TDX
	 * capable machine.  Just do paranoid check here and WARN()
	 * if not the case.
	 */
	if (WARN_ON_ONCE(!cpumask_equal(&cpus_booted_once_mask,
					cpu_present_mask)))
		return false;

	return __seamrr_enabled();
}

static bool tdx_keyid_sufficient(void)
{
	if (WARN_ON_ONCE(!cpumask_equal(&cpus_booted_once_mask,
					cpu_present_mask)))
		return false;

	/*
	 * TDX requires at least two KeyIDs: one global KeyID to
	 * protect the metadata of the TDX module and one or more
	 * KeyIDs to run TD guests.
	 */
	return tdx_keyid_num >= 2;
}

/*
 * All error codes of both the P-SEAMLDR and the TDX module SEAMCALLs
 * have bit 63 set if SEAMCALL fails.
 */
#define SEAMCALL_LEAF_ERROR(_ret)	((_ret) & BIT_ULL(63))

/**
 * seamcall - make SEAMCALL to the P-SEAMLDR or the TDX module with
 *	      additional check on SEAMRR and CR4.VMXE
 *
 * @fn:			SEAMCALL leaf number.
 * @rcx:		Input operand RCX.
 * @rdx:		Input operand RDX.
 * @r8:			Input operand R8.
 * @r9:			Input operand R9.
 * @seamcall_ret:	SEAMCALL completion status (can be NULL).
 * @out:		Additional output operands (can be NULL).
 *
 * Wrapper of __seamcall() to make SEAMCALL to the P-SEAMLDR or the TDX
 * module with additional defensive check on SEAMRR and CR4.VMXE.  Caller
 * to make sure SEAMRR is enabled and CPU is already in VMX operation
 * before calling this function.
 *
 * Unlike __seamcall(), it returns kernel error code instead of SEAMCALL
 * completion status, which is returned via @seamcall_ret if desired.
 *
 * Return:
 *
 * * -ENODEV:	SEAMCALL failed with VMfailInvalid, or SEAMRR is not enabled.
 * * -EPERM:	CR4.VMXE is not enabled
 * * -EFAULT:	SEAMCALL failed
 * * -0:	SEAMCALL succeeded
 */
static int seamcall(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		    u64 *seamcall_ret, struct tdx_module_output *out)
{
	u64 ret;

	if (WARN_ON_ONCE(!seamrr_enabled()))
		return -ENODEV;

	/*
	 * SEAMCALL instruction requires CPU being already in VMX
	 * operation (VMXON has been done), otherwise it causes #UD.
	 * Sanity check whether CR4.VMXE has been enabled.
	 *
	 * Note VMX being enabled in CR4 doesn't mean CPU is already
	 * in VMX operation, but unfortunately there's no way to do
	 * such check.  However in practice enabling CR4.VMXE and
	 * doing VMXON are done together (for now) so in practice it
	 * checks whether VMXON has been done.
	 *
	 * Preemption is disabled during the CR4.VMXE check and the
	 * actual SEAMCALL so VMX doesn't get disabled by other threads
	 * due to scheduling.
	 */
	preempt_disable();
	if (WARN_ON_ONCE(!cpu_vmx_enabled())) {
		preempt_enable_no_resched();
		return -EPERM;
	}

	ret = __seamcall(fn, rcx, rdx, r8, r9, out);

	preempt_enable_no_resched();

	/*
	 * Convert SEAMCALL error code to kernel error code:
	 *  - -ENODEV:	VMfailInvalid
	 *  - -EFAULT:	SEAMCALL failed
	 *  - 0:	SEAMCALL was successful
	 */
	if (ret == TDX_SEAMCALL_VMFAILINVALID)
		return -ENODEV;

	/* Save the completion status if caller wants to use it */
	if (seamcall_ret)
		*seamcall_ret = ret;

	/*
	 * TDX module SEAMCALLs may also return non-zero completion
	 * status codes but w/o bit 63 set.  Those codes are treated
	 * as additional information/warning while the SEAMCALL is
	 * treated as completed successfully.  Return 0 in this case.
	 * Caller can use @seamcall_ret to get the additional code
	 * when it is desired.
	 */
	if (SEAMCALL_LEAF_ERROR(ret)) {
		pr_err("SEAMCALL leaf %llu failed: 0x%llx\n", fn, ret);
		return -EFAULT;
	}

	return 0;
}

/* Data structure to make SEAMCALL on multiple CPUs concurrently */
struct seamcall_ctx {
	u64 fn;
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	atomic_t err;
	u64 seamcall_ret;
	struct tdx_module_output out;
};

static void seamcall_smp_call_function(void *data)
{
	struct seamcall_ctx *sc = data;
	int ret;

	ret = seamcall(sc->fn, sc->rcx, sc->rdx, sc->r8, sc->r9,
			&sc->seamcall_ret, &sc->out);
	if (ret)
		atomic_set(&sc->err, ret);
}

/*
 * Call the SEAMCALL on all online cpus concurrently.
 * Return error if SEAMCALL fails on any cpu.
 */
static int seamcall_on_each_cpu(struct seamcall_ctx *sc)
{
	on_each_cpu(seamcall_smp_call_function, sc, true);
	return atomic_read(&sc->err);
}

/*
 * Call the SEAMCALL on one (any) cpu for each physical package in
 * serialized way.  Note for serialized calls 'seamcall_ctx::err'
 * doesn't have to be atomic, but for simplicity just reuse it
 * instead of adding a new one.
 *
 * Return -ENXIO if IPI SEAMCALL wasn't run on any cpu, or -EFAULT
 * when SEAMCALL fails, or -EPERM when the cpu where SEAMCALL runs
 * on is not in VMX operation.  In case of -EFAULT, the error code
 * of SEAMCALL is in 'struct seamcall_ctx::seamcall_ret'.
 */
static int seamcall_on_each_package_serialized(struct seamcall_ctx *sc)
{
	cpumask_var_t packages;
	int cpu, ret;

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL))
		return -ENOMEM;

	for_each_online_cpu(cpu) {
		if (cpumask_test_and_set_cpu(topology_physical_package_id(cpu),
					packages))
			continue;

		ret = smp_call_function_single(cpu, seamcall_smp_call_function,
				sc, true);
		if (ret)
			return ret;

		/*
		 * Doesn't have to use atomic_read(), but it doesn't
		 * hurt either.
		 */
		ret = atomic_read(&sc->err);
		if (ret)
			return ret;
	}

	return 0;
}

static inline bool p_seamldr_ready(void)
{
	return !!p_seamldr_info.p_seamldr_ready;
}

static inline bool tdx_module_ready(void)
{
	/*
	 * SEAMLDR_INFO.SEAM_READY indicates whether TDX module
	 * is (loaded and) ready for SEAMCALL.
	 */
	return p_seamldr_ready() && !!p_seamldr_info.seam_ready;
}

/*
 * Detect whether the P-SEAMLDR has been loaded by calling SEAMLDR.INFO
 * SEAMCALL to get the P-SEAMLDR information, which further tells whether
 * the TDX module has been loaded and ready for SEAMCALL.  Caller to make
 * sure only calling this function when CPU is already in VMX operation.
 */
static int detect_p_seamldr(void)
{
	int ret;

	/*
	 * SEAMCALL fails with VMfailInvalid when SEAM software is not
	 * loaded, in which case seamcall() returns -ENODEV.  Use this
	 * to detect the P-SEAMLDR.
	 *
	 * Note the P-SEAMLDR SEAMCALL also fails with VMfailInvalid when
	 * the P-SEAMLDR is already busy with another SEAMCALL.  But this
	 * won't happen here as this function is only called once.
	 */
	ret = seamcall(P_SEAMCALL_SEAMLDR_INFO, __pa(&p_seamldr_info),
			0, 0, 0, NULL, NULL);
	if (ret) {
		if (ret == -ENODEV)
			pr_info("P-SEAMLDR is not loaded.\n");
		else
			pr_info("Failed to detect P-SEAMLDR.\n");

		return ret;
	}

	/*
	 * If SEAMLDR.INFO was successful, it must be ready for SEAMCALL.
	 * Otherwise it's either kernel or firmware bug.
	 */
	if (WARN_ON_ONCE(!p_seamldr_ready()))
		return -ENODEV;

	pr_info("P-SEAMLDR: version 0x%x, vendor_id: 0x%x, build_date: %u, build_num %u, major %u, minor %u\n",
		p_seamldr_info.version, p_seamldr_info.vendor_id,
		p_seamldr_info.build_date, p_seamldr_info.build_num,
		p_seamldr_info.major, p_seamldr_info.minor);

	return 0;
}

static int __tdx_detect(void)
{
	/* Disabled by kernel command line */
	if (!enable_tdx_host)
		goto no_tdx_module;

	/* The TDX module is not loaded if SEAMRR is disabled */
	if (!seamrr_enabled()) {
		pr_info("SEAMRR not enabled.\n");
		goto no_tdx_module;
	}

	/*
	 * Also do not report the TDX module as loaded if there's
	 * no enough TDX private KeyIDs to run any TD guests.
	 */
	if (!tdx_keyid_sufficient()) {
		pr_info("Number of TDX private KeyIDs too small: %u.\n",
				tdx_keyid_num);
		goto no_tdx_module;
	}

	/*
	 * For simplicity any error during detect_p_seamldr() marks
	 * TDX module as not loaded.
	 */
	if (detect_p_seamldr())
		goto no_tdx_module;

	if (!tdx_module_ready()) {
		pr_info("TDX module is not loaded.\n");
		goto no_tdx_module;
	}

	pr_info("TDX module detected.\n");
	tdx_module_status = TDX_MODULE_LOADED;
	return 0;

no_tdx_module:
	tdx_module_status = TDX_MODULE_NONE;
	return -ENODEV;
}

static int tdx_module_init_cpus(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_INIT };

	return seamcall_on_each_cpu(&sc);
}

static inline bool cmr_valid(struct cmr_info *cmr)
{
	return !!cmr->size;
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

static int sanitize_cmrs(struct cmr_info *cmr_array, int cmr_num)
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
	 * This implies that BIOS may generate invalid empty entries
	 * if total CMRs are less than 32.  Skip them manually.
	 */
	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];
		struct cmr_info *prev_cmr = NULL;

		/* Skip further invalid CMRs */
		if (!cmr_valid(cmr))
			break;

		if (i > 0)
			prev_cmr = &cmr_array[i - 1];

		/*
		 * It is a TDX firmware bug if CMRs are not
		 * in address ascending order.
		 */
		if (prev_cmr && ((prev_cmr->base + prev_cmr->size) >
					cmr->base)) {
			pr_err("Firmware bug: CMRs not in address ascending order.\n");
			return -EFAULT;
		}
	}

	/*
	 * Also a sane BIOS should never generate invalid CMR(s) between
	 * two valid CMRs.  Sanity check this and simply return error in
	 * this case.
	 */
	for (j = i; j < cmr_num; j++)
		if (cmr_valid(&cmr_array[j])) {
			pr_err("Firmware bug: invalid CMR(s) among valid CMRs.\n");
			return -EFAULT;
		}

	/*
	 * Trim all tail invalid empty CMRs.  BIOS should generate at
	 * least one valid CMR, otherwise it's a TDX firmware bug.
	 */
	tdx_cmr_num = i;
	if (!tdx_cmr_num) {
		pr_err("Firmware bug: No valid CMR.\n");
		return -EFAULT;
	}

	/* Print kernel sanitized CMRs */
	print_cmrs(tdx_cmr_array, tdx_cmr_num, "Kernel-sanitized-CMR");

	return 0;
}

static int __tdx_get_sysinfo(void)
{
	struct tdx_module_output out;
	u64 tdsysinfo_sz, cmr_num;
	int ret;

	BUILD_BUG_ON(sizeof(struct tdsysinfo_struct) != TDSYSINFO_STRUCT_SIZE);

	ret = seamcall(TDH_SYS_INFO, __pa(&tdx_sysinfo), TDSYSINFO_STRUCT_SIZE,
			__pa(tdx_cmr_array), MAX_CMRS, NULL, &out);
	if (ret)
		return ret;

	/*
	 * If TDH.SYS.CONFIG succeeds, RDX contains the actual bytes
	 * written to @tdx_sysinfo and R9 contains the actual entries
	 * written to @tdx_cmr_array.  Sanity check them.
	 */
	tdsysinfo_sz = out.rdx;
	cmr_num = out.r9;
	if (WARN_ON_ONCE((tdsysinfo_sz > sizeof(tdx_sysinfo)) || !tdsysinfo_sz ||
				(cmr_num > MAX_CMRS) || !cmr_num))
		return -EFAULT;

	pr_info("TDX module: vendor_id 0x%x, major_version %u, minor_version %u, build_date %u, build_num %u",
		tdx_sysinfo.vendor_id, tdx_sysinfo.major_version,
		tdx_sysinfo.minor_version, tdx_sysinfo.build_date,
		tdx_sysinfo.build_num);

	/* Print BIOS provided CMRs */
	print_cmrs(tdx_cmr_array, cmr_num, "BIOS-CMR");

	return sanitize_cmrs(tdx_cmr_array, cmr_num);
}

const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
       const struct tdsysinfo_struct *r = NULL;

       mutex_lock(&tdx_module_lock);
       if (tdx_module_status == TDX_MODULE_INITIALIZED)
	       r = &tdx_sysinfo;
       mutex_unlock(&tdx_module_lock);
       return r;
}
EXPORT_SYMBOL_GPL(tdx_get_sysinfo);

/* Check whether one e820 entry is RAM and could be used as TDX memory */
static bool e820_entry_is_ram(struct e820_entry *entry)
{
	/*
	 * Besides E820_TYPE_RAM, E820_TYPE_RESERVED_KERN type entries
	 * are also treated as TDX memory as they are also added to
	 * memblock.memory in e820__memblock_setup().
	 *
	 * E820_TYPE_SOFT_RESERVED type entries are excluded as they are
	 * marked as reserved and are not later freed to page allocator
	 * (only part of kernel image, initrd, etc are freed to page
	 * allocator).
	 *
	 * Also unconditionally treat x86 legacy PMEMs (E820_TYPE_PRAM)
	 * as TDX memory since they are RAM underneath, and could be used
	 * as TD guest memory.
	 */
	return (entry->type == E820_TYPE_RAM) ||
		(entry->type == E820_TYPE_RESERVED_KERN) ||
		(entry->type == E820_TYPE_PRAM);
}

/*
 * The low memory below 1MB is not covered by CMRs on some TDX platforms.
 * In practice, this range cannot be used for guest memory because it is
 * not managed by the page allocator due to boot-time reservation.  Just
 * skip the low 1MB so this range won't be treated as TDX memory.
 *
 * Return true if the e820 entry is completely skipped, in which case
 * caller should ignore this entry.  Otherwise the actual memory range
 * after skipping the low 1MB is returned via @start and @end.
 */
static bool e820_entry_skip_lowmem(struct e820_entry *entry, u64 *start,
				   u64 *end)
{
	u64 _start = entry->addr;
	u64 _end = entry->addr + entry->size;

	if (_start < SZ_1M)
		_start = SZ_1M;

	*start = _start;
	*end = _end;

	return _start >= _end;
}

/*
 * Trim away non-page-aligned memory at the beginning and the end for a
 * given region.  Return true when there are still pages remaining after
 * trimming, and the trimmed region is returned via @start and @end.
 */
static bool e820_entry_trim(u64 *start, u64 *end)
{
	u64 s, e;

	s = round_up(*start, PAGE_SIZE);
	e = round_down(*end, PAGE_SIZE);

	if (s >= e)
		return false;

	*start = s;
	*end = e;

	return true;
}

/*
 * Get the next memory region (excluding low 1MB) in e820.  @idx points
 * to the entry to start to walk with.  Multiple memory regions in the
 * same NUMA node that are contiguous are merged together (following
 * e820__memblock_setup()).  The merged range is returned via @start and
 * @end.  After return, @idx points to the next entry of the last RAM
 * entry that has been walked, or table->nr_entries (indicating all
 * entries in the e820 table have been walked).
 */
static void e820_next_mem(struct e820_table *table, int *idx, u64 *start,
			  u64 *end)
{
	u64 rs, re;
	int rnid, i;

again:
	rs = re = 0;
	for (i = *idx; i < table->nr_entries; i++) {
		struct e820_entry *entry = &table->entries[i];
		u64 s, e;
		int nid;

		if (!e820_entry_is_ram(entry))
			continue;

		if (e820_entry_skip_lowmem(entry, &s, &e))
			continue;

		/*
		 * Found the first RAM entry.  Record it and keep
		 * looping to find other RAM entries that can be
		 * merged.
		 */
		if (!rs) {
			rs = s;
			re = e;
			rnid = phys_to_target_node(rs);
			if (WARN_ON_ONCE(rnid == NUMA_NO_NODE))
				rnid = 0;
			continue;
		}

		/*
		 * Try to merge with previous RAM entry.  E820 entries
		 * are not necessarily page aligned.  For instance, the
		 * setup_data elements in boot_params are marked as
		 * E820_TYPE_RESERVED_KERN, and they may not be page
		 * aligned.  In e820__memblock_setup() all adjancent
		 * memory regions within the same NUMA node are merged to
		 * a single one, and the non-page-aligned parts (at the
		 * beginning and the end) are trimmed.  Follow the same
		 * rule here.
		 */
		nid = phys_to_target_node(s);
		if (WARN_ON_ONCE(nid == NUMA_NO_NODE))
			nid = 0;
		if ((nid == rnid) && (s == re)) {
			/* Merge with previous range and update the end */
			re = e;
			continue;
		}

		/*
		 * Stop if current entry cannot be merged with previous
		 * one (or more) entries.
		 */
		break;
	}

	/*
	 * @i is either the RAM entry that cannot be merged with previous
	 * one (or more) entries, or table->nr_entries.
	 */
	*idx = i;
	/*
	 * Trim non-page-aligned parts of [@rs, @re), which is either a
	 * valid memory region, or empty.  If there's nothing left after
	 * trimming and there are still entries that have not been
	 * walked, continue to walk.
	 */
	if (!e820_entry_trim(&rs, &re) && i < table->nr_entries)
		goto again;

	*start = rs;
	*end = re;
}

/*
 * Helper to loop all e820 RAM entries with low 1MB excluded
 * in a given e820 table.
 */
#define _e820_for_each_mem(_table, _i, _start, _end)				\
	for ((_i) = 0, e820_next_mem((_table), &(_i), &(_start), &(_end));	\
		(_start) < (_end);						\
		e820_next_mem((_table), &(_i), &(_start), &(_end)))

/*
 * Helper to loop all e820 RAM entries with low 1MB excluded
 * in kernel modified 'e820_table' to honor 'mem' and 'memmap' kernel
 * command lines.
 */
#define e820_for_each_mem(_i, _start, _end)	\
	_e820_for_each_mem(e820_table, _i, _start, _end)

/* Check whether first range is the subrange of the second */
static bool is_subrange(u64 r1_start, u64 r1_end, u64 r2_start, u64 r2_end)
{
	return (r1_start >= r2_start && r1_end <= r2_end) ? true : false;
}

/* Check whether address range is covered by any CMR or not. */
static bool range_covered_by_cmr(struct cmr_info *cmr_array, int cmr_num,
				 u64 start, u64 end)
{
	int i;

	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		if (is_subrange(start, end, cmr->base, cmr->base + cmr->size))
			return true;
	}

	return false;
}

/* Sanity check whether all e820 RAM entries are fully covered by CMRs. */
static int e820_check_against_cmrs(void)
{
	u64 start, end;
	int i;

	/*
	 * Loop over e820_table to find all RAM entries and check
	 * whether they are all fully covered by any CMR.
	 */
	e820_for_each_mem(i, start, end) {
		if (!range_covered_by_cmr(tdx_cmr_array, tdx_cmr_num,
					start, end)) {
			pr_err("[0x%llx, 0x%llx) is not fully convertible memory\n",
					start, end);
			return -EFAULT;
		}
	}

	return 0;
}

/* The starting offset of reserved areas within TDMR_INFO */
#define TDMR_RSVD_START		64

static struct tdmr_info *__alloc_tdmr(void)
{
	int tdmr_sz;

	/*
	 * TDMR_INFO's actual size depends on maximum number of reserved
	 * areas that one TDMR supports.
	 */
	tdmr_sz = TDMR_RSVD_START + tdx_sysinfo.max_reserved_per_tdmr *
		sizeof(struct tdmr_reserved_area);

	/*
	 * TDX requires TDMR_INFO to be 512 aligned.  Always align up
	 * TDMR_INFO size to 512 so the memory allocated via kzalloc()
	 * can meet the alignment requirement.
	 */
	tdmr_sz = ALIGN(tdmr_sz, TDMR_INFO_ALIGNMENT);

	return kzalloc(tdmr_sz, GFP_KERNEL);
}

/* Create a new TDMR at given index in the TDMR array */
static struct tdmr_info *alloc_tdmr(struct tdmr_info **tdmr_array, int idx)
{
	struct tdmr_info *tdmr;

	if (WARN_ON_ONCE(tdmr_array[idx]))
		return NULL;

	tdmr = __alloc_tdmr();
	tdmr_array[idx] = tdmr;

	return tdmr;
}

static void free_tdmrs(struct tdmr_info **tdmr_array, int tdmr_num)
{
	int i;

	for (i = 0; i < tdmr_num; i++) {
		struct tdmr_info *tdmr = tdmr_array[i];

		/* kfree() works with NULL */
		kfree(tdmr);
		tdmr_array[i] = NULL;
	}
}

/*
 * Create TDMRs to cover all RAM entries in e820_table.  The created
 * TDMRs are saved to @tdmr_array and @tdmr_num is set to the actual
 * number of TDMRs.  All entries in @tdmr_array must be initially NULL.
 */
static int create_tdmrs(struct tdmr_info **tdmr_array, int *tdmr_num)
{
	struct tdmr_info *tdmr;
	u64 start, end;
	int i, tdmr_idx;
	int ret = 0;

	tdmr_idx = 0;
	tdmr = alloc_tdmr(tdmr_array, 0);
	if (!tdmr)
		return -ENOMEM;
	/*
	 * Loop over all RAM entries in e820 and create TDMRs to cover
	 * them.  To keep it simple, always try to use one TDMR to cover
	 * one RAM entry.
	 */
	e820_for_each_mem(i, start, end) {
		start = TDMR_ALIGN_DOWN(start);
		end = TDMR_ALIGN_UP(end);

		/*
		 * If the current TDMR's size hasn't been initialized, it
		 * is a new allocated TDMR to cover the new RAM entry.
		 * Otherwise the current TDMR already covers the previous
		 * RAM entry.  In the latter case, check whether the
		 * current RAM entry has been fully or partially covered
		 * by the current TDMR, since TDMR is 1G aligned.
		 */
		if (tdmr->size) {
			/*
			 * Loop to next RAM entry if the current entry
			 * is already fully covered by the current TDMR.
			 */
			if (end <= TDMR_END(tdmr))
				continue;

			/*
			 * If part of current RAM entry has already been
			 * covered by current TDMR, skip the already
			 * covered part.
			 */
			if (start < TDMR_END(tdmr))
				start = TDMR_END(tdmr);

			/*
			 * Create a new TDMR to cover the current RAM
			 * entry, or the remaining part of it.
			 */
			tdmr_idx++;
			if (tdmr_idx >= tdx_sysinfo.max_tdmrs) {
				ret = -E2BIG;
				goto err;
			}
			tdmr = alloc_tdmr(tdmr_array, tdmr_idx);
			if (!tdmr) {
				ret = -ENOMEM;
				goto err;
			}
		}

		tdmr->base = start;
		tdmr->size = end - start;
	}

	/* @tdmr_idx is always the index of last valid TDMR. */
	*tdmr_num = tdmr_idx + 1;

	return 0;
err:
	/*
	 * Clean up already allocated TDMRs in case of error.  @tdmr_idx
	 * indicates the last TDMR that wasn't created successfully,
	 * therefore only needs to free @tdmr_idx TDMRs.
	 */
	free_tdmrs(tdmr_array, tdmr_idx);
	return ret;
}

/* Calculate PAMT size given a TDMR and a page size */
static unsigned long __tdmr_get_pamt_sz(struct tdmr_info *tdmr,
					enum tdx_page_sz pgsz)
{
	unsigned long pamt_sz;

	pamt_sz = (tdmr->size >> ((TDX_HPAGE_SHIFT * pgsz) + PAGE_SHIFT)) *
		tdx_sysinfo.pamt_entry_size;
	/* PAMT size must be 4K aligned */
	pamt_sz = ALIGN(pamt_sz, PAGE_SIZE);

	return pamt_sz;
}

/* Calculate the size of all PAMTs for a TDMR */
static unsigned long tdmr_get_pamt_sz(struct tdmr_info *tdmr)
{
	enum tdx_page_sz pgsz;
	unsigned long pamt_sz;

	pamt_sz = 0;
	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++)
		pamt_sz += __tdmr_get_pamt_sz(tdmr, pgsz);

	return pamt_sz;
}

/*
 * Locate the NUMA node containing the start of the given TDMR's first
 * RAM entry.  The given TDMR may also cover memory in other NUMA nodes.
 */
static int tdmr_get_nid(struct tdmr_info *tdmr)
{
	u64 start, end;
	int i;

	/* Find the first RAM entry covered by the TDMR */
	e820_for_each_mem(i, start, end)
		if (end > TDMR_START(tdmr))
			break;

	/*
	 * One TDMR must cover at least one (or partial) RAM entry,
	 * otherwise it is kernel bug.  WARN_ON() in this case.
	 */
	if (WARN_ON_ONCE((start >= end) || start >= TDMR_END(tdmr)))
		return 0;

	/*
	 * The first RAM entry may be partially covered by the previous
	 * TDMR.  In this case, use TDMR's start to find the NUMA node.
	 */
	if (start < TDMR_START(tdmr))
		start = TDMR_START(tdmr);

	return phys_to_target_node(start);
}

static int tdmr_setup_pamt(struct tdmr_info *tdmr)
{
	unsigned long tdmr_pamt_base, pamt_base[TDX_PG_MAX];
	unsigned long pamt_sz[TDX_PG_MAX];
	unsigned long pamt_npages;
	struct page *pamt;
	enum tdx_page_sz pgsz;
	int nid;

	/*
	 * Allocate one chunk of physically contiguous memory for all
	 * PAMTs.  This helps minimize the PAMT's use of reserved areas
	 * in overlapped TDMRs.
	 */
	nid = tdmr_get_nid(tdmr);
	pamt_npages = tdmr_get_pamt_sz(tdmr) >> PAGE_SHIFT;
	pamt = alloc_contig_pages(pamt_npages, GFP_KERNEL, nid,
			&node_online_map);
	if (!pamt)
		return -ENOMEM;

	/* Calculate PAMT base and size for all supported page sizes. */
	tdmr_pamt_base = page_to_pfn(pamt) << PAGE_SHIFT;
	for (pgsz = TDX_PG_4K; pgsz < TDX_PG_MAX; pgsz++) {
		unsigned long sz = __tdmr_get_pamt_sz(tdmr, pgsz);

		pamt_base[pgsz] = tdmr_pamt_base;
		pamt_sz[pgsz] = sz;

		tdmr_pamt_base += sz;
	}

	tdmr->pamt_4k_base = pamt_base[TDX_PG_4K];
	tdmr->pamt_4k_size = pamt_sz[TDX_PG_4K];
	tdmr->pamt_2m_base = pamt_base[TDX_PG_2M];
	tdmr->pamt_2m_size = pamt_sz[TDX_PG_2M];
	tdmr->pamt_1g_base = pamt_base[TDX_PG_1G];
	tdmr->pamt_1g_size = pamt_sz[TDX_PG_1G];

	return 0;
}

static void tdmr_free_pamt(struct tdmr_info *tdmr)
{
	unsigned long pamt_pfn, pamt_sz;

	pamt_pfn = tdmr->pamt_4k_base >> PAGE_SHIFT;
	pamt_sz = tdmr->pamt_4k_size + tdmr->pamt_2m_size + tdmr->pamt_1g_size;

	/* Do nothing if PAMT hasn't been allocated for this TDMR */
	if (!pamt_sz)
		return;

	if (WARN_ON(!pamt_pfn))
		return;

	free_contig_range(pamt_pfn, pamt_sz >> PAGE_SHIFT);
}

static void tdmrs_free_pamt_all(struct tdmr_info **tdmr_array, int tdmr_num)
{
	int i;

	for (i = 0; i < tdmr_num; i++)
		tdmr_free_pamt(tdmr_array[i]);
}

/* Allocate and set up PAMTs for all TDMRs */
static int tdmrs_setup_pamt_all(struct tdmr_info **tdmr_array, int tdmr_num)
{
	int i, ret;

	for (i = 0; i < tdmr_num; i++) {
		ret = tdmr_setup_pamt(tdmr_array[i]);
		if (ret)
			goto err;
	}

	return 0;
err:
	tdmrs_free_pamt_all(tdmr_array, tdmr_num);
	return -ENOMEM;
}

static int tdmr_add_rsvd_area(struct tdmr_info *tdmr, int *p_idx,
			      u64 addr, u64 size)
{
	struct tdmr_reserved_area *rsvd_areas = tdmr->reserved_areas;
	int idx = *p_idx;

	/* Reserved area must be 4K aligned in offset and size */
	if (WARN_ON(addr & ~PAGE_MASK || size & ~PAGE_MASK))
		return -EINVAL;

	/* Cannot exceed maximum reserved areas supported by TDX */
	if (idx >= tdx_sysinfo.max_reserved_per_tdmr)
		return -E2BIG;

	rsvd_areas[idx].offset = addr - tdmr->base;
	rsvd_areas[idx].size = size;

	*p_idx = idx + 1;

	return 0;
}

/* Compare function called by sort() for TDMR reserved areas */
static int rsvd_area_cmp_func(const void *a, const void *b)
{
	struct tdmr_reserved_area *r1 = (struct tdmr_reserved_area *)a;
	struct tdmr_reserved_area *r2 = (struct tdmr_reserved_area *)b;

	if (r1->offset + r1->size <= r2->offset)
		return -1;
	if (r1->offset >= r2->offset + r2->size)
		return 1;

	/* Reserved areas cannot overlap.  Caller should guarantee. */
	WARN_ON(1);
	return -1;
}

/* Set up reserved areas for a TDMR, including memory holes and PAMTs */
static int tdmr_setup_rsvd_areas(struct tdmr_info *tdmr,
				     struct tdmr_info **tdmr_array,
				     int tdmr_num)
{
	u64 start, end, prev_end;
	int rsvd_idx, i, ret = 0;

	/* Mark holes between e820 RAM entries as reserved */
	rsvd_idx = 0;
	prev_end = TDMR_START(tdmr);
	e820_for_each_mem(i, start, end) {
		/* Break if this entry is after the TDMR */
		if (start >= TDMR_END(tdmr))
			break;

		/* Exclude entries before this TDMR */
		if (end < TDMR_START(tdmr))
			continue;

		/*
		 * Skip if no hole exists before this entry. "<=" is
		 * used because one e820 entry might span two TDMRs.
		 * In that case the start address of this entry is
		 * smaller then the start address of the second TDMR.
		 */
		if (start <= prev_end) {
			prev_end = end;
			continue;
		}

		/* Add the hole before this e820 entry */
		ret = tdmr_add_rsvd_area(tdmr, &rsvd_idx, prev_end,
				start - prev_end);
		if (ret)
			return ret;

		prev_end = end;
	}

	/* Add the hole after the last RAM entry if it exists. */
	if (prev_end < TDMR_END(tdmr)) {
		ret = tdmr_add_rsvd_area(tdmr, &rsvd_idx, prev_end,
				TDMR_END(tdmr) - prev_end);
		if (ret)
			return ret;
	}

	/*
	 * Walk over all TDMRs to find out whether any PAMT falls into
	 * the given TDMR. If yes, mark it as reserved too.
	 */
	for (i = 0; i < tdmr_num; i++) {
		struct tdmr_info *tmp = tdmr_array[i];
		u64 pamt_start, pamt_end;

		pamt_start = tmp->pamt_4k_base;
		pamt_end = pamt_start + tmp->pamt_4k_size +
			tmp->pamt_2m_size + tmp->pamt_1g_size;

		/* Skip PAMTs outside of the given TDMR */
		if ((pamt_end <= TDMR_START(tdmr)) ||
				(pamt_start >= TDMR_END(tdmr)))
			continue;

		/* Only mark the part within the TDMR as reserved */
		if (pamt_start < TDMR_START(tdmr))
			pamt_start = TDMR_START(tdmr);
		if (pamt_end > TDMR_END(tdmr))
			pamt_end = TDMR_END(tdmr);

		ret = tdmr_add_rsvd_area(tdmr, &rsvd_idx, pamt_start,
				pamt_end - pamt_start);
		if (ret)
			return ret;
	}

	/* TDX requires reserved areas listed in address ascending order */
	sort(tdmr->reserved_areas, rsvd_idx, sizeof(struct tdmr_reserved_area),
			rsvd_area_cmp_func, NULL);

	return 0;
}

static int tdmrs_setup_rsvd_areas_all(struct tdmr_info **tdmr_array,
				      int tdmr_num)
{
	int i;

	for (i = 0; i < tdmr_num; i++) {
		int ret;

		ret = tdmr_setup_rsvd_areas(tdmr_array[i], tdmr_array,
				tdmr_num);
		if (ret)
			return ret;
	}

	return 0;
}

static int construct_tdmrs(struct tdmr_info **tdmr_array, int *tdmr_num)
{
	int ret;

	ret = e820_check_against_cmrs();
	if (ret)
		goto err;

	ret = create_tdmrs(tdmr_array, tdmr_num);
	if (ret)
		goto err;

	ret = tdmrs_setup_pamt_all(tdmr_array, *tdmr_num);
	if (ret)
		goto err_free_tdmrs;

	ret = tdmrs_setup_rsvd_areas_all(tdmr_array, *tdmr_num);
	if (ret)
		goto err_free_pamts;

	return 0;
err_free_pamts:
	tdmrs_free_pamt_all(tdmr_array, *tdmr_num);
err_free_tdmrs:
	free_tdmrs(tdmr_array, *tdmr_num);
err:
	return ret;
}

static int config_tdx_module(struct tdmr_info **tdmr_array, int tdmr_num,
			     u64 global_keyid)
{
	u64 *tdmr_pa_array;
	int i, array_sz;
	int ret;

	/*
	 * TDMR_INFO entries are configured to the TDX module via an
	 * array of the physical address of each TDMR_INFO.  TDX requires
	 * the array itself must be 512 aligned.  Round up the array size
	 * to 512 aligned so the buffer allocated by kzalloc() meets the
	 * alignment requirement.
	 */
	array_sz = ALIGN(tdmr_num * sizeof(u64), TDMR_INFO_PA_ARRAY_ALIGNMENT);
	tdmr_pa_array = kzalloc(array_sz, GFP_KERNEL);
	if (!tdmr_pa_array)
		return -ENOMEM;

	for (i = 0; i < tdmr_num; i++)
		tdmr_pa_array[i] = __pa(tdmr_array[i]);

	/*
	 * TDH.SYS.CONFIG fails when TDH.SYS.LP.INIT is not done on all
	 * BIOS-enabled cpus.  tdx_init() only disables CPU hotplug but
	 * doesn't do early check whether all BIOS-enabled cpus are
	 * online, so TDH.SYS.CONFIG can fail here.
	 */
	ret = seamcall(TDH_SYS_CONFIG, __pa(tdmr_pa_array), tdmr_num,
				global_keyid, 0, NULL, NULL);
	/* Free the array as it is not required any more. */
	kfree(tdmr_pa_array);

	return ret;
}

static int config_global_keyid(u64 global_keyid)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_KEY_CONFIG };

	/*
	 * TDH.SYS.KEY.CONFIG may fail with entropy error (which is
	 * a recoverable error).  Assume this is exceedingly rare and
	 * just return error if encountered instead of retrying.
	 */
	return seamcall_on_each_package_serialized(&sc);
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
		struct tdx_module_output out;
		int ret;

		ret = seamcall(TDH_SYS_TDMR_INIT, tdmr->base, 0, 0, 0,
				NULL, &out);
		if (ret)
			return ret;
		/*
		 * RDX contains 'next-to-initialize' address if
		 * TDH.SYS.TDMR.INT succeeded.
		 */
		next = out.rdx;
		if (need_resched())
			cond_resched();
	} while (next < tdmr->base + tdmr->size);

	return 0;
}

/* Initialize all TDMRs */
static int init_tdmrs(struct tdmr_info **tdmr_array, int tdmr_num)
{
	int i;

	/*
	 * Initialize TDMRs one-by-one for simplicity, though the TDX
	 * architecture does allow different TDMRs to be initialized in
	 * parallel on multiple CPUs.  Parallel initialization could
	 * be added later when the time spent in the serialized scheme
	 * becomes a real concern.
	 */
	for (i = 0; i < tdmr_num; i++) {
		int ret;

		ret = init_tdmr(tdmr_array[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static int init_tdx_module(void)
{
	struct tdmr_info **tdmr_array;
	int tdmr_num;
	int ret;

	/* TDX module global initialization */
	ret = seamcall(TDH_SYS_INIT, 0, 0, 0, 0, NULL, NULL);
	if (ret)
		goto out;

	/* Logical-cpu scope initialization */
	ret = tdx_module_init_cpus();
	if (ret)
		goto out;

	/* Get TDX module information and CMRs */
	ret = __tdx_get_sysinfo();
	if (ret)
		goto out;

	/*
	 * Prepare enough space to hold pointers of TDMRs (TDMR_INFO).
	 * TDX requires TDMR_INFO being 512 aligned.  Each TDMR is
	 * allocated individually within construct_tdmrs() to meet
	 * this requirement.
	 */
	tdmr_array = kcalloc(tdx_sysinfo.max_tdmrs, sizeof(struct tdmr_info *),
			GFP_KERNEL);
	if (!tdmr_array) {
		ret = -ENOMEM;
		goto out;
	}

	/* Construct TDMRs to build TDX memory */
	ret = construct_tdmrs(tdmr_array, &tdmr_num);
	if (ret)
		goto out_free_tdmrs;

	/*
	 * Reserve the first TDX KeyID as global KeyID to protect
	 * TDX module metadata.
	 */
	tdx_global_keyid = tdx_keyid_start;

	/* Config the TDX module with TDMRs and global KeyID */
	ret = config_tdx_module(tdmr_array, tdmr_num, tdx_global_keyid);
	if (ret)
		goto out_free_pamts;

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
	 * large (~1/256th of system RAM), just use WBINVD on all cpus to
	 * flush the cache.
	 *
	 * In practice, the current generation of TDX doesn't use the
	 * global KeyID in TDH.SYS.KEY.CONFIG.  Therefore in practice,
	 * the cachelines can be flushed after configuring the global
	 * KeyID on all pkgs is done.  But the future generation of TDX
	 * may change this, so just follow the suggestion of TDX spec to
	 * flush cache before TDH.SYS.KEY.CONFIG.
	 */
	wbinvd_on_all_cpus();

	/* Config the key of global KeyID on all packages */
	ret = config_global_keyid(tdx_global_keyid);
	if (ret)
		goto out_free_pamts;

	/* Initialize TDMRs to complete the TDX module initialization */
	ret = init_tdmrs(tdmr_array, tdmr_num);
	if (ret)
		goto out_free_pamts;

	tdx_module_status = TDX_MODULE_INITIALIZED;
out_free_pamts:
	/*
	 * Free PAMTs allocated in construct_tdmrs() when TDX module
	 * initialization fails.
	 */
	if (ret) {
		/*
		 * Part of PAMTs may already have been initialized by
		 * TDX module.  Flush cache before returning them back
		 * to kernel.
		 */
		wbinvd_on_all_cpus();
		tdmrs_free_pamt_all(tdmr_array, tdmr_num);
	}
out_free_tdmrs:
	/*
	 * TDMRs are only used during initializing TDX module.  Always
	 * free them no matter the initialization was successful or not.
	 */
	free_tdmrs(tdmr_array, tdmr_num);
	kfree(tdmr_array);
out:
	if (ret)
		pr_info("Failed to initialize TDX module.\n");
	else
		pr_info("TDX module initialized.\n");

	return ret;
}

static void shutdown_tdx_module(void)
{
	struct seamcall_ctx sc = { .fn = TDH_SYS_LP_SHUTDOWN };

	seamcall_on_each_cpu(&sc);

	tdx_module_status = TDX_MODULE_SHUTDOWN;
}

static int __tdx_init(void)
{
	int ret;

	/*
	 * Logical-cpu scope initialization requires calling one SEAMCALL
	 * on all logical cpus enabled by BIOS.  Shutting down the TDX
	 * module also has such requirement.  Further more, configuring
	 * the key of the global KeyID requires calling one SEAMCALL for
	 * each package.  For simplicity, disable CPU hotplug in the whole
	 * initialization process.
	 *
	 * It's perhaps better to check whether all BIOS-enabled cpus are
	 * online before starting initializing, and return early if not.
	 * But none of 'possible', 'present' and 'online' CPU masks
	 * represents BIOS-enabled cpus.  For example, 'possible' mask is
	 * impacted by 'nr_cpus' or 'possible_cpus' kernel command line.
	 * Just let the SEAMCALL to fail if not all BIOS-enabled cpus are
	 * online.
	 */
	cpus_read_lock();

	ret = init_tdx_module();

	/*
	 * Shut down the TDX module in case of any error during the
	 * initialization process.  It's meaningless to leave the TDX
	 * module in any middle state of the initialization process.
	 */
	if (ret)
		shutdown_tdx_module();

	cpus_read_unlock();

	return ret;
}

/**
 * tdx_detect - Detect whether the TDX module has been loaded
 *
 * Detect whether the TDX module has been loaded and ready for
 * initialization.  Only call this function when all cpus are
 * already in VMX operation.
 *
 * This function can be called in parallel by multiple callers.
 *
 * Return:
 *
 * * -0:	The TDX module has been loaded and ready for
 *		initialization.
 * * -ENODEV:	The TDX module is not loaded.
 * * -EPERM:	CPU is not in VMX operation.
 * * -EFAULT:	Other internal fatal errors.
 */
int tdx_detect(void)
{
	int ret;

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_UNKNOWN:
		ret = __tdx_detect();
		break;
	case TDX_MODULE_NONE:
		ret = -ENODEV;
		break;
	case TDX_MODULE_LOADED:
	case TDX_MODULE_INITIALIZED:
		ret = 0;
		break;
	case TDX_MODULE_SHUTDOWN:
		ret = -EFAULT;
		break;
	default:
		WARN_ON(1);
		ret = -EFAULT;
	}

	mutex_unlock(&tdx_module_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tdx_detect);

/**
 * tdx_init - Initialize the TDX module
 *
 * Initialize the TDX module to make it ready to run TD guests.  This
 * function should be called after tdx_detect() returns successful.
 * Only call this function when all cpus are online and are in VMX
 * operation.  CPU hotplug is temporarily disabled internally.
 *
 * This function can be called in parallel by multiple callers.
 *
 * Return:
 *
 * * -0:	The TDX module has been successfully initialized.
 * * -ENODEV:	The TDX module is not loaded.
 * * -EPERM:	The CPU which does SEAMCALL is not in VMX operation.
 * * -EFAULT:	Other internal fatal errors.
 */
int tdx_init(void)
{
	int ret;

	mutex_lock(&tdx_module_lock);

	switch (tdx_module_status) {
	case TDX_MODULE_NONE:
		ret = -ENODEV;
		break;
	case TDX_MODULE_LOADED:
		ret = __tdx_init();
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
EXPORT_SYMBOL_GPL(tdx_init);

/**
 * platform_has_tdx - Whether platform supports TDX
 *
 * Check whether platform supports TDX (i.e. TDX is enabled in BIOS),
 * regardless whether TDX is truly enabled by kernel.
 *
 * Return true if SEAMRR is enabled, and there are sufficient TDX private
 * KeyIDs to run TD guests.
 */
bool platform_has_tdx(void)
{
	return seamrr_enabled() && tdx_keyid_sufficient();
}
EXPORT_SYMBOL_GPL(platform_has_tdx);
