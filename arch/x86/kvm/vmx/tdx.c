// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <asm/cpufeature.h>
#include <asm/tdx.h>
#include "capabilities.h"
#include "x86_ops.h"
#include "tdx.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define pr_tdx_error(__fn, __err)	\
	pr_err_ratelimited("SEAMCALL %s failed: 0x%llx\n", #__fn, __err)

#define __pr_tdx_error_N(__fn_str, __err, __fmt, ...)		\
	pr_err_ratelimited("SEAMCALL " __fn_str " failed: 0x%llx, " __fmt,  __err,  __VA_ARGS__)

#define pr_tdx_error_1(__fn, __err, __rcx)		\
	__pr_tdx_error_N(#__fn, __err, "rcx 0x%llx\n", __rcx)

#define pr_tdx_error_2(__fn, __err, __rcx, __rdx)	\
	__pr_tdx_error_N(#__fn, __err, "rcx 0x%llx, rdx 0x%llx\n", __rcx, __rdx)

#define pr_tdx_error_3(__fn, __err, __rcx, __rdx, __r8)	\
	__pr_tdx_error_N(#__fn, __err, "rcx 0x%llx, rdx 0x%llx, r8 0x%llx\n", __rcx, __rdx, __r8)

bool enable_tdx __ro_after_init;
module_param_named(tdx, enable_tdx, bool, 0444);

static enum cpuhp_state tdx_cpuhp_state;

static const struct tdx_sys_info *tdx_sysinfo;

#define KVM_SUPPORTED_TD_ATTRS (TDX_TD_ATTR_SEPT_VE_DISABLE)

static u64 tdx_get_supported_attrs(const struct tdx_sys_info_td_conf *td_conf)
{
	u64 val = KVM_SUPPORTED_TD_ATTRS;

	if ((val & td_conf->attributes_fixed1) != td_conf->attributes_fixed1)
		return 0;

	val &= td_conf->attributes_fixed0;

	return val;
}

static u64 tdx_get_supported_xfam(const struct tdx_sys_info_td_conf *td_conf)
{
	u64 val = kvm_caps.supported_xcr0 | kvm_caps.supported_xss;

	/*
	 * PT and CET can be exposed to TD guest regardless of KVM's XSS, PT
	 * and, CET support.
	 */
	val |= XFEATURE_MASK_PT | XFEATURE_MASK_CET_USER |
	       XFEATURE_MASK_CET_KERNEL;

	if ((val & td_conf->xfam_fixed1) != td_conf->xfam_fixed1)
		return 0;

	val &= td_conf->xfam_fixed0;

	return val;
}

static u32 tdx_set_guest_phys_addr_bits(const u32 eax, int addr_bits)
{
	return (eax & ~GENMASK(23, 16)) | (addr_bits & 0xff) << 16;
}

#define KVM_TDX_CPUID_NO_SUBLEAF	((__u32)-1)

static void td_init_cpuid_entry2(struct kvm_cpuid_entry2 *entry, unsigned char idx)
{
	const struct tdx_sys_info_td_conf *td_conf = &tdx_sysinfo->td_conf;

	entry->function = (u32)td_conf->cpuid_config_leaves[idx];
	entry->index = td_conf->cpuid_config_leaves[idx] >> 32;
	entry->eax = (u32)td_conf->cpuid_config_values[idx][0];
	entry->ebx = td_conf->cpuid_config_values[idx][0] >> 32;
	entry->ecx = (u32)td_conf->cpuid_config_values[idx][1];
	entry->edx = td_conf->cpuid_config_values[idx][1] >> 32;

	if (entry->index == KVM_TDX_CPUID_NO_SUBLEAF)
		entry->index = 0;

	/* Work around missing support on old TDX modules */
	if (entry->function == 0x80000008)
		entry->eax = tdx_set_guest_phys_addr_bits(entry->eax, 0xff);
}

static int init_kvm_tdx_caps(const struct tdx_sys_info_td_conf *td_conf,
			     struct kvm_tdx_capabilities *caps)
{
	int i;

	caps->supported_attrs = tdx_get_supported_attrs(td_conf);
	if (!caps->supported_attrs)
		return -EIO;

	caps->supported_xfam = tdx_get_supported_xfam(td_conf);
	if (!caps->supported_xfam)
		return -EIO;

	caps->cpuid.nent = td_conf->num_cpuid_config;

	for (i = 0; i < td_conf->num_cpuid_config; i++)
		td_init_cpuid_entry2(&caps->cpuid.entries[i], i);

	return 0;
}

static int tdx_get_capabilities(struct kvm_tdx_cmd *cmd)
{
	const struct tdx_sys_info_td_conf *td_conf = &tdx_sysinfo->td_conf;
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities *caps = NULL;
	int ret = 0;

	/* flags is reserved for future use */
	if (cmd->flags)
		return -EINVAL;

	caps = kmalloc(sizeof(*caps) +
		       sizeof(struct kvm_cpuid_entry2) * td_conf->num_cpuid_config,
		       GFP_KERNEL);
	if (!caps)
		return -ENOMEM;

	user_caps = u64_to_user_ptr(cmd->data);
	if (copy_from_user(caps, user_caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}

	if (caps->cpuid.nent < td_conf->num_cpuid_config) {
		ret = -E2BIG;
		goto out;
	}

	ret = init_kvm_tdx_caps(td_conf, caps);
	if (ret)
		goto out;

	if (copy_to_user(user_caps, caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}

	if (copy_to_user(user_caps->cpuid.entries, caps->cpuid.entries,
			 caps->cpuid.nent *
			 sizeof(caps->cpuid.entries[0])))
		ret = -EFAULT;

out:
	/* kfree() accepts NULL. */
	kfree(caps);
	return ret;
}

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	/*
	 * Userspace should never set hw_error. It is used to fill
	 * hardware-defined error by the kernel.
	 */
	if (tdx_cmd.hw_error)
		return -EINVAL;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
	case KVM_TDX_CAPABILITIES:
		r = tdx_get_capabilities(&tdx_cmd);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &tdx_cmd, sizeof(struct kvm_tdx_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

static int tdx_online_cpu(unsigned int cpu)
{
	unsigned long flags;
	int r;

	/* Sanity check CPU is already in post-VMXON */
	WARN_ON_ONCE(!(cr4_read_shadow() & X86_CR4_VMXE));

	local_irq_save(flags);
	r = tdx_cpu_enable();
	local_irq_restore(flags);

	return r;
}

static void __do_tdx_cleanup(void)
{
	/*
	 * Once TDX module is initialized, it cannot be disabled and
	 * re-initialized again w/o runtime update (which isn't
	 * supported by kernel).  Only need to remove the cpuhp here.
	 * The TDX host core code tracks TDX status and can handle
	 * 'multiple enabling' scenario.
	 */
	WARN_ON_ONCE(!tdx_cpuhp_state);
	cpuhp_remove_state_nocalls(tdx_cpuhp_state);
	tdx_cpuhp_state = 0;
}

static int __init __do_tdx_bringup(void)
{
	int r;

	/*
	 * TDX-specific cpuhp callback to call tdx_cpu_enable() on all
	 * online CPUs before calling tdx_enable(), and on any new
	 * going-online CPU to make sure it is ready for TDX guest.
	 */
	r = cpuhp_setup_state_cpuslocked(CPUHP_AP_ONLINE_DYN,
					 "kvm/cpu/tdx:online",
					 tdx_online_cpu, NULL);
	if (r < 0)
		return r;

	tdx_cpuhp_state = r;

	r = tdx_enable();
	if (r)
		__do_tdx_cleanup();

	return r;
}

static bool __init kvm_can_support_tdx(void)
{
	return cpu_feature_enabled(X86_FEATURE_TDX_HOST_PLATFORM);
}

static int __init __tdx_bringup(void)
{
	int r;

	/*
	 * Enabling TDX requires enabling hardware virtualization first,
	 * as making SEAMCALLs requires CPU being in post-VMXON state.
	 */
	r = kvm_enable_virtualization();
	if (r)
		return r;

	cpus_read_lock();
	r = __do_tdx_bringup();
	cpus_read_unlock();

	if (r)
		goto tdx_bringup_err;

	r = -EINVAL;
	/* Get TDX global information for later use */
	tdx_sysinfo = tdx_get_sysinfo();
	if (WARN_ON_ONCE(!tdx_sysinfo))
		goto get_sysinfo_err;

	/* Check TDX module and KVM capabilities */
	if (!tdx_get_supported_attrs(&tdx_sysinfo->td_conf) ||
	    !tdx_get_supported_xfam(&tdx_sysinfo->td_conf))
		goto get_sysinfo_err;

	/*
	 * Leave hardware virtualization enabled after TDX is enabled
	 * successfully.  TDX CPU hotplug depends on this.
	 */
	return 0;

get_sysinfo_err:
	__do_tdx_cleanup();
tdx_bringup_err:
	kvm_disable_virtualization();
	return r;
}

void tdx_cleanup(void)
{
	if (enable_tdx) {
		__do_tdx_cleanup();
		kvm_disable_virtualization();
	}
}

int __init tdx_bringup(void)
{
	int r;

	enable_tdx = enable_tdx && kvm_can_support_tdx();

	if (!enable_tdx)
		return 0;

	/*
	 * Ideally KVM should probe whether TDX module has been loaded
	 * first and then try to bring it up, because KVM should treat
	 * them differently.  I.e., KVM should just disable TDX while
	 * still allow module to be loaded when TDX module is not
	 * loaded, but fail to load module when it actually fails to
	 * bring up TDX.
	 *
	 * But unfortunately TDX needs to use SEAMCALL to probe whether
	 * the module is loaded (there is no CPUID or MSR for that),
	 * and making SEAMCALL requires enabling virtualization first,
	 * just like the rest steps of bringing up TDX module.
	 *
	 * The first SEAMCALL to bring up TDX module returns -ENODEV
	 * when the module is not loaded.  For simplicity just try to
	 * bring up TDX and use the return code as the way to probe,
	 * albeit this is not perfect, i.e., need to make sure
	 * __tdx_bringup() doesn't return -ENODEV in other cases.
	 */
	r = __tdx_bringup();
	if (r) {
		enable_tdx = 0;
		/*
		 * Disable TDX only but don't fail to load module when
		 * TDX module is not loaded.  No need to print message
		 * saying "module is not loaded" because it was printed
		 * when the first SEAMCALL failed.
		 */
		if (r == -ENODEV)
			r = 0;
	}

	return r;
}
