// SPDX-License-Identifier: GPL-2.0
/* C-wrapper functions for P-SEAMLDR SEAMCALLs and functions for P-SEAMLDR */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/memblock.h>
#include <linux/kobject.h>
#include <linux/kdebug.h>
#include <linux/slab.h>

#include <asm/trace/seam.h>
#include <asm/debugreg.h>
#include <asm/cmdline.h>
#include <asm/trapnr.h>
#include <asm/delay.h>
#include <asm/apic.h>
#include <asm/virtext.h>

#include "p-seamldr.h"
#include "seamcall.h"
#include "seam.h"
#include "tdx.h"

static int seamldr_info(phys_addr_t seamldr_info)
{
	u64 ret;

	ret = seamcall(SEAMCALL_SEAMLDR_INFO, seamldr_info, 0, 0, 0, NULL);
	if (ret) {
		if (ret == P_SEAMLDR_VMFAILINVALID)
			pr_info("The P-SEAMLDR is not loaded by BIOS.  Skip TDX initialization.\n");
		else
			pr_err("SEAMCALL[SEAMLDR_INFO] failed %s (0x%llx)\n",
				p_seamldr_error_name(ret), ret);
		return -EIO;
	}
	return 0;
}

static struct p_seamldr_info *p_seamldr_info;

int __init p_seamldr_get_info(void)
{
	struct vmcs *vmcs = NULL;
	int vmxoff_err = 0;
	int err = 0;

	/* p_seamldr_info requires P_SEAMLDR_INFO_ALIGNMENT-aligned. */
	BUILD_BUG_ON(!is_power_of_2(sizeof(*p_seamldr_info)));
	BUILD_BUG_ON((sizeof(*p_seamldr_info) % P_SEAMLDR_INFO_ALIGNMENT) != 0);
	p_seamldr_info = kmalloc(sizeof(*p_seamldr_info), GFP_KERNEL);
	if (!p_seamldr_info)
		return -ENOMEM;

	/* P-SEAMLDR executes in SEAM VMX-root that requires VMXON. */
	vmcs = (struct vmcs *)get_zeroed_page(GFP_KERNEL);
	if (!vmcs) {
		err = -ENOMEM;
		goto out;
	}
	seam_init_vmxon_vmcs(vmcs);

	/*
	 * Because it's before kvm_init, VMX shouldn't be enabled as initial
	 * reset value.  In kexec case, cpu_emergency_vmxoff() disables VMX on
	 * kexec reboot.
	 */
	WARN_ON(__read_cr4() & X86_CR4_VMXE);
	err = cpu_vmxon(__pa(vmcs));
	if (err)
		goto out;

	err = seamldr_info(__pa(p_seamldr_info));

	/*
	 * Other initialization codes expect that no one else uses VMX and that
	 * VMX is off.  Disable VMX to keep such assumptions.
	 */
	vmxoff_err = cpu_vmxoff();
	if (!err && vmxoff_err)
		err = vmxoff_err;
	if (err)
		goto out;

	pr_info("TDX P-SEAMLDR: version 0x%0x attributes 0x%0x vendor_id 0x%x "
		"build_date %d build_num 0x%x minor 0x%x major 0x%x.\n",
		p_seamldr_info->version, p_seamldr_info->attributes,
		p_seamldr_info->vendor_id, p_seamldr_info->build_date,
		p_seamldr_info->build_num,
		p_seamldr_info->minor, p_seamldr_info->major);
out:
	free_page((unsigned long)vmcs); /* free_page() ignores NULL */
	/* On success, keep p_seamldr_info to export the info via sysfs. */
	if (err) {
		kfree(p_seamldr_info); /* kfree() is NULL-safe. */
		p_seamldr_info = NULL;
	}
	return err;
}

/*
 * Workaround for clobbered registers by NP-SEAMLDR.  NP-SEAMLDR clobbers
 * several registers and there is a window where NMI isn't safe.  If NMI happens
 * during the window and the kernel is about to die, correct the unexpected CPU
 * status.
 */
static int __init np_seamldr_die_notify(struct notifier_block *nb,
					unsigned long cmd, void *args)
{
	struct die_args *die_args = args;
	struct pt_regs *regs = die_args->regs;
	const u8 *insn = (u8 *)regs->ip;

	/*
	 * NP-SEAMLDR clobbers %cr4.  Because it's before feature discovery,
	 * features disabled by %cr4 aren't used.
	 */

	/* Workaround for clobbered %cs/%ss. */
	if (cmd == DIE_GPF && die_args->trapnr == X86_TRAP_GP &&
		/* iretq */
		insn[0] == 0x48 && insn[1] == 0xcf) {
		struct iretq_frame {
			unsigned long ip;
			unsigned long cs;
			unsigned long flags;
			unsigned long sp;
			unsigned long ss;
		};
		struct iretq_frame *iret = (struct iretq_frame *)regs->sp;

		if ((unsigned long)&np_seamldr_nmi_fixup_begin <= iret->ip &&
			iret->ip < (unsigned long)&np_seamldr_nmi_fixup_end) {
			/*
			 * iretq in nmi_restore causes #GP due to clobbered
			 * %CS/%SS.  Correct them.
			 */
			iret->cs = __KERNEL_CS;
			iret->ss = __KERNEL_DS;
			return NOTIFY_STOP;
		}
	}

	return NOTIFY_DONE;
}

static struct notifier_block np_seamldr_die_notifier __initdata = {
	.notifier_call = np_seamldr_die_notify,
};

static u64 __init __p_seamldr_load(void *np_seamldr,
				unsigned long np_seamldr_size)
{
	/*
	 * The np_seamldr_launch() clobbers some MSRs and DR7.  Save and restore
	 * them.
	 *
	 * No need to save and restore MSR_CORE_PERF_GLOBAL_CTRL,
	 * MSR_IA32_PEBS_ENABLE, MSR_IA32_RTIT_CTL, and MSR_ARCH_LBR_CTL because
	 * it's before those features are discovered and used.  Later they will
	 * be initialized.
	 */
	unsigned long dr7;
	unsigned long misc_enable;
	unsigned long efer;
	unsigned long cr_pat;

	u64 err;

	get_debugreg(dr7, 7);
	rdmsrl(MSR_IA32_MISC_ENABLE, misc_enable);
	rdmsrl(MSR_EFER, efer);
	rdmsrl(MSR_IA32_CR_PAT, cr_pat);

	err = np_seamldr_launch(__pa(np_seamldr), np_seamldr_size);

	wrmsrl(MSR_IA32_CR_PAT, cr_pat);
	wrmsrl(MSR_EFER, efer);
	wrmsrl(MSR_IA32_MISC_ENABLE, misc_enable);
	set_debugreg(dr7, 7);

	return err;
}

/*
 * p_seamldr_load - load the P-SEAMLDR by launching the NP-SEAMLDR ACM.
 * @np_seamldr: cpio data to np_sealdr image
 * @return: 0 on success, error code on failure.
 *
 * Put all APs into Wait-For-SIPI state and then, launch Authenticated Code
 * Module(ACM) by invoking GETSEC[EnterACCS] on BSP.  It's caller's
 * responsibility to ensure that all the APs are safe to receive INIT.
 * Call this function before SMP initialization smp_init() (or ensure all
 * the APs are offline with CPU lock held.)
 *
 * KASAN thinks that memcpy from initrd image via cpio_data is invalid access
 * because the boot loader allocates the region of initrd image.  Not by the
 * kernel memory allocator.  Add the annotation of __no_sanitize_address to
 * apiece KASAN.
 */
static int __init __no_sanitize_address
p_seamldr_load(struct cpio_data *cpio_np_seamldr)
{
	unsigned long np_seamldr_size = cpio_np_seamldr->size;
	phys_addr_t np_seamldr_pa = 0;
	void *np_seamldr = NULL;
	u32 icr_busy;
	int enteraccs_attempts = 10;
	int ret;
	u64 err;

	if (!np_seamldr_size) {
		pr_info("Invalid NP-SEAMLDR ACM size\n");
		return -EINVAL;
	}

	/* GETSEC[EnterACCS] requires the ACM to be 4k aligned and below 4G. */
	np_seamldr_pa = memblock_phys_alloc_range(np_seamldr_size, PAGE_SIZE, 0,
						BIT_ULL(32));
	if (!np_seamldr_pa) {
		pr_info("failed to allocate memory for NP-SEAMLDR ACM. size 0x%lx\n",
			np_seamldr_size);
		return -ENOMEM;
	}
	np_seamldr = __va(np_seamldr_pa);

	/*
	 * KASAN thinks that (cpio_np_seamldr->data, cpio_np_seamldr->data)
	 * is invalid address because the region comes from the initrd placed
	 * by boot loader, not by the kernel memory allocator.
	 */
	memcpy(np_seamldr, cpio_np_seamldr->data, np_seamldr_size);

	/*
	 * Because this is the early boot phase, it's assumed that VMX isn't
	 * enabled yet. (kvm_intel isn't initialized yet.) The TDX first
	 * firmware loader (NP-SEAMLDR) requires that VMX is disabled.
	 *
	 * In normal (re)boot case, VMX is off as a reset value.  In kexec case,
	 * cpu_emergency_vmxoff() disables VMX on kexec reboot.
	 *
	 * If VMX is enabled, someone else is using VMX or the CPU is in an
	 * unknown state possibly due to the incomplete kexec reboot.  Warn and
	 * let the NP-SEAMLDR fail instead of risking unintended situations.
	 */
	WARN_ON(__read_cr4() & X86_CR4_VMXE);

	ret = -EIO;
	/* Ensure APs are in Wait-For-SIPI. */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_INT_ASSERT |
		       APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto out;

	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto out;

	ret = register_die_notifier(&np_seamldr_die_notifier);
	if (ret)
		goto out;

	while (1) {
		err = __p_seamldr_load(np_seamldr, np_seamldr_size);

		/*
		 * P_SEAMLDR was already loaded.  For example in the case of
		 * kexec reboot.  Re-use the already loaded one.
		 */
		if (err == NP_SEAMLDR_EMODBUSY) {
			pr_info("P-SEAMLDR was already loaded. reusing it.\n");
			err = 0;
			break;
		}

		/*
		 * Gracefully handle special error cases.
		 * - NP_SEAMLDR_EUNSPECERR: entropy is lacking.  Because there
		 *    is no way to detect enough entropy, wait for a while and
		 *    retry.
		 * - -EFAULT: #GPs on EnterACCS due to APs not in Wait-For-SIPI
		 *    state.  EnterACCS requires APs to be in Wait-For-SIPI
		 *    state, but doesn't provide any way for software to confirm
		 *    APs are in Wait-For-SIPI state, i.e. try-catch is sadly
		 *    the most optimal approach.
		 */
		if (err != NP_SEAMLDR_EUNSPECERR && err != -EFAULT)
			break;

		/* reach retry limit */
		if (WARN_ON(!enteraccs_attempts--))
			break;

		/*
		 * Wait for enough entropy or for APs to be in Wait-For-SIPI
		 * state.
		 */
		udelay(1 * USEC_PER_MSEC);
	}
	if (err) {
		pr_err("NP-SEAMLDR returned 0x%llx\n", err);
		ret = -EIO;
	}
	unregister_die_notifier(&np_seamldr_die_notifier);

out:
	if (np_seamldr)
		memblock_free(np_seamldr, np_seamldr_size);
	return ret;
}

#define NP_SEAMLDR	"kernel/x86/tdx/np-seamldr.acm"

/*
 * load_p_seamldr() - load P-SEAMLDR
 *
 * Call this function
 *  - Interrupt Stack Table(IST) for NMI is set by trap_init().
 *  - Only BSP is running before bringing up all APs by smp_init().
 */
int __init load_p_seamldr(void)
{
	struct cpio_data np_seamldr;
	int err;

	if (!seam_get_firmware(&np_seamldr, NP_SEAMLDR)) {
		pr_err("No NP-SEAMLDR found. \"%s\"\n", NP_SEAMLDR);
		return -ENOENT;
	}

	pr_info("Loading TDX P-SEAMLDR %s.\n", NP_SEAMLDR);
	err = p_seamldr_load(&np_seamldr);
	if (err) {
		pr_err("Failed to load TDX P-SEAMLDR\n");
		return err;
	}

	pr_info("Successfully loaded TDX P-SEAMLDR.\n");
	return 0;
}

#ifdef CONFIG_SYSFS

static struct kobject *p_seamldr_kobj;

#define P_SEAMLDR_ATTR_SHOW_FMT(name, fmt)				\
static ssize_t name ## _show(						\
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)	\
{									\
	return sprintf(buf, fmt, p_seamldr_info->name);			\
}									\
static struct kobj_attribute p_seamldr_##name = __ATTR_RO(name)

#define P_SEAMLDR_ATTR_SHOW_DEC(name)	P_SEAMLDR_ATTR_SHOW_FMT(name, "%d\n")
#define P_SEAMLDR_ATTR_SHOW_HEX(name)	P_SEAMLDR_ATTR_SHOW_FMT(name, "0x%x\n")

P_SEAMLDR_ATTR_SHOW_HEX(version);
P_SEAMLDR_ATTR_SHOW_FMT(attributes, "0x08%x\n");
P_SEAMLDR_ATTR_SHOW_HEX(vendor_id);
P_SEAMLDR_ATTR_SHOW_DEC(build_date);
P_SEAMLDR_ATTR_SHOW_HEX(build_num);
P_SEAMLDR_ATTR_SHOW_HEX(minor);
P_SEAMLDR_ATTR_SHOW_HEX(major);

static struct attribute *p_seamldr_attrs[] = {
	&p_seamldr_version.attr,
	&p_seamldr_attributes.attr,
	&p_seamldr_vendor_id.attr,
	&p_seamldr_build_date.attr,
	&p_seamldr_build_num.attr,
	&p_seamldr_minor.attr,
	&p_seamldr_major.attr,
	NULL,
};

static const struct attribute_group p_seamldr_attr_group = {
	.attrs = p_seamldr_attrs,
};

static int __init p_seamldr_sysfs_init(void)
{
	int ret = 0;

	ret = tdx_sysfs_init();
	if (ret)
		goto out;

	if (!p_seamldr_info)
		goto out;

	p_seamldr_kobj = kobject_create_and_add("p_seamldr", tdx_kobj);
	if (!p_seamldr_kobj) {
		pr_err("kobject_create_and_add p_seamldr failed\n");
		ret = -EINVAL;
		goto out;
	}

	ret = sysfs_create_group(p_seamldr_kobj, &p_seamldr_attr_group);
	if (ret) {
		pr_err("Sysfs exporting attribute failed with error %d", ret);
		kobject_put(p_seamldr_kobj);
		p_seamldr_kobj = NULL;
	}

out:
	return ret;
}
device_initcall(p_seamldr_sysfs_init);
#endif
