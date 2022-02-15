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
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/cpufeature.h>
#include <asm/cpufeatures.h>
#include <asm/virtext.h>
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

static bool __seamrr_enabled(void)
{
	return (seamrr_mask & SEAMRR_ENABLED_BITS) == SEAMRR_ENABLED_BITS;
}

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
 * All error codes of both P-SEAMLDR and TDX module SEAMCALLs
 * have bit 63 set if SEAMCALL fails.
 */
#define SEAMCALL_LEAF_ERROR(_ret)	((_ret) & BIT_ULL(63))

/**
 * seamcall - make SEAMCALL to P-SEAMLDR or TDX module with additional
 *	      check on SEAMRR and CR4.VMXE
 *
 * @fn:			SEAMCALL leaf number.
 * @rcx:		Input operand RCX.
 * @rdx:		Input operand RDX.
 * @r8:			Input operand R8.
 * @r9:			Input operand R9.
 * @seamcall_ret:	SEAMCALL completion status (can be NULL).
 * @out:		Additional output operands (can be NULL).
 *
 * Wrapper of __seamcall() to make SEAMCALL to TDX module or P-SEAMLDR
 * with additional defensive check on SEAMRR and CR4.VMXE.  Caller to
 * make sure SEAMRR is enabled and CPU is already in VMX operation before
 * calling this function.
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
 * Call the SEAMCALAL on all online cpus concurrently.
 * Return error if SEAMCALL fails on any cpu.
 */
static int seamcall_on_each_cpu(struct seamcall_ctx *sc)
{
	on_each_cpu(seamcall_smp_call_function, sc, true);
	return atomic_read(&sc->err);
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
 * Detect whether P-SEAMLDR has been loaded by calling SEAMLDR.INFO
 * SEAMCALL to P-SEAMLDR information, which also contains whether
 * the TDX module has been loaded and ready for SEAMCALL.  Caller to
 * make sure only calling this function when CPU is already in VMX
 * operation.
 */
static int detect_p_seamldr(void)
{
	int ret;

	/*
	 * SEAMCALL fails with VMfailInvalid when SEAM software is not
	 * loaded, in which case seamcall() returns -ENODEV.  Use this
	 * to detect P-SEAMLDR.
	 *
	 * Note P-SEAMLDR SEAMCALL also fails with VMfailInvalid when
	 * P-SEAMLDR is already busy with another SEAMCALL.  But this
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
	/*
	 * TDX module cannot be possibly loaded if SEAMRR is disabled.
	 * Also do not report TDX module as loaded if there's no enough
	 * TDX private KeyIDs to run any TD guests.
	 */
	if (!seamrr_enabled()) {
		pr_info("SEAMRR not enabled.\n");
		goto no_tdx_module;
	}

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

static int init_tdx_module(void)
{
	/*
	 * Return -EFAULT until all steps of TDX module
	 * initialization are done.
	 */
	return -EFAULT;
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
	 * on all logical cpus enabled by BIOS.  Shutting down TDX module
	 * also has such requirement.  Further more, configuring the key
	 * of the global KeyID requires calling one SEAMCALL for each
	 * package.  For simplicity, disable CPU hotplug in the whole
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
	 * Put TDX module to shutdown mode in case of any error during
	 * the initialization process.  It's meaningless to leave the TDX
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
 * * -0:	TDX module has been loaded and ready for initialization.
 * * -ENODEV:	TDX module is not loaded.
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
