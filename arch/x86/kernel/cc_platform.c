// SPDX-License-Identifier: GPL-2.0-only
/*
 * Confidential Computing Platform Capability checks
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <linux/export.h>
#include <linux/cc_platform.h>
#include <linux/mem_encrypt.h>
#include <linux/device.h>

#include <asm/mshyperv.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/tdx.h>

#ifdef CONFIG_INTEL_TDX_GUEST

unsigned int x86_disable_cc = -1;

static int __init x86_cc_clear_setup(char *arg)
{
	get_option(&arg, &x86_disable_cc);

	return 1;
}
__setup("x86_cc_clear=", x86_cc_clear_setup);

#endif

static bool intel_cc_platform_has(enum cc_attr attr)
{
	if (attr == x86_disable_cc)
		return false;

	switch (attr) {
	case CC_ATTR_GUEST_UNROLL_STRING_IO:
	case CC_ATTR_HOTPLUG_DISABLED:
	case CC_ATTR_GUEST_TDX:
	case CC_ATTR_GUEST_MEM_ENCRYPT:
	case CC_ATTR_MEM_ENCRYPT:
	case CC_ATTR_GUEST_SECURE_TIME:
	case CC_ATTR_GUEST_CPUID_FILTER:
		return true;
	case CC_ATTR_GUEST_DEVICE_FILTER:
		return tdx_filter_enabled();
	default:
		return false;
	}

	return false;
}

/*
 * SME and SEV are very similar but they are not the same, so there are
 * times that the kernel will need to distinguish between SME and SEV. The
 * cc_platform_has() function is used for this.  When a distinction isn't
 * needed, the CC_ATTR_MEM_ENCRYPT attribute can be used.
 *
 * The trampoline code is a good example for this requirement.  Before
 * paging is activated, SME will access all memory as decrypted, but SEV
 * will access all memory as encrypted.  So, when APs are being brought
 * up under SME the trampoline area cannot be encrypted, whereas under SEV
 * the trampoline area must be encrypted.
 */
static bool amd_cc_platform_has(enum cc_attr attr)
{
#ifdef CONFIG_AMD_MEM_ENCRYPT
	switch (attr) {
	case CC_ATTR_MEM_ENCRYPT:
		return sme_me_mask;

	case CC_ATTR_HOST_MEM_ENCRYPT:
		return sme_me_mask && !(sev_status & MSR_AMD64_SEV_ENABLED);

	case CC_ATTR_GUEST_MEM_ENCRYPT:
		return sev_status & MSR_AMD64_SEV_ENABLED;

	case CC_ATTR_GUEST_STATE_ENCRYPT:
		return sev_status & MSR_AMD64_SEV_ES_ENABLED;

	/*
	 * With SEV, the rep string I/O instructions need to be unrolled
	 * but SEV-ES supports them through the #VC handler.
	 */
	case CC_ATTR_GUEST_UNROLL_STRING_IO:
		return (sev_status & MSR_AMD64_SEV_ENABLED) &&
			!(sev_status & MSR_AMD64_SEV_ES_ENABLED);

	default:
		return false;
	}
#else
	return false;
#endif
}

static bool hyperv_cc_platform_has(enum cc_attr attr)
{
	return attr == CC_ATTR_GUEST_MEM_ENCRYPT;
}

bool cc_platform_has(enum cc_attr attr)
{
	if (sme_me_mask)
		return amd_cc_platform_has(attr);
	else if (is_tdx_guest())
		return intel_cc_platform_has(attr);

	if (hv_is_isolation_supported())
		return hyperv_cc_platform_has(attr);

	return false;
}
EXPORT_SYMBOL_GPL(cc_platform_has);

pgprot_t pgprot_encrypted(pgprot_t prot)
{
        if (sme_me_mask)
                return __pgprot(__sme_set(pgprot_val(prot)));
        else if (is_tdx_guest())
		return __pgprot(pgprot_val(prot) & ~tdx_shared_mask());

        return prot;
}
EXPORT_SYMBOL_GPL(pgprot_encrypted);

pgprot_t pgprot_decrypted(pgprot_t prot)
{
	if (sme_me_mask)
		return __pgprot(__sme_clr(pgprot_val(prot)));
	else if (is_tdx_guest())
		return __pgprot(pgprot_val(prot) | tdx_shared_mask());

	return prot;
}
EXPORT_SYMBOL_GPL(pgprot_decrypted);

/*
 * cc_guest_dev_authorized() - Used to get ARCH specific authorized status
 *			       of the given device.
 * @dev			     - device structure
 *
 * Return True to allow the device or False to deny it.
 *
 */
bool cc_guest_dev_authorized(struct device *dev)
{
	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return tdx_guest_dev_authorized(dev);

	return dev->authorized;
}
EXPORT_SYMBOL_GPL(cc_guest_dev_authorized);
