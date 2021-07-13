// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

static int tdx_vm_init(struct kvm *kvm) { return 0; }
static void tdx_vm_teardown(struct kvm *kvm) {}
static void tdx_vm_destroy(struct kvm *kvm) {}
static int tdx_vcpu_create(struct kvm_vcpu *vcpu) { return 0; }
static void tdx_vcpu_free(struct kvm_vcpu *vcpu) {}
static void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event) {}
static void tdx_inject_nmi(struct kvm_vcpu *vcpu) {}
static fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu) { return EXIT_FASTPATH_NONE; }
static void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu) {}
static void tdx_vcpu_put(struct kvm_vcpu *vcpu) {}
static void tdx_hardware_enable(void) {}
static void tdx_hardware_disable(void) {}
static void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu) {}
static int tdx_handle_exit(struct kvm_vcpu *vcpu,
			   enum exit_fastpath_completion fastpath) { return 0; }
static int tdx_dev_ioctl(void __user *argp) { return -EINVAL; }
static int tdx_vm_ioctl(struct kvm *kvm, void __user *argp) { return -EINVAL; }
static int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp) { return -EINVAL; }
static void tdx_flush_tlb(struct kvm_vcpu *vcpu) {}
static void tdx_load_mmu_pgd(struct kvm_vcpu *vcpu, unsigned long pgd,
			     int pgd_level) {}
static void tdx_set_virtual_apic_mode(struct kvm_vcpu *vcpu) {}
static void tdx_apicv_post_state_restore(struct kvm_vcpu *vcpu) {}
static int tdx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector) { return -1; }
static void tdx_get_exit_info(struct kvm_vcpu *vcpu, u64 *info1, u64 *info2,
			      u32 *intr_info, u32 *error_code) {}
static int tdx_prepare_memory_region(struct kvm *kvm,
				     struct kvm_memory_slot *memslot,
				     const struct kvm_userspace_memory_region *mem,
				     enum kvm_mr_change change) { return 0; }
static void tdx_prepare_switch_to_guest(struct kvm_vcpu *vcpu) {}
static int __init tdx_check_processor_compatibility(void) { return 0; }
static void __init tdx_pre_kvm_init(unsigned int *vcpu_size,
				    unsigned int *vcpu_align,
				    unsigned int *vm_size) {}
static int __init tdx_init(void) { return 0; }
static void __exit tdx_exit(void) {}
static void tdx_update_exception_bitmap(struct kvm_vcpu *vcpu) {}
static void tdx_set_dr7(struct kvm_vcpu *vcpu, unsigned long val) {}
static int tdx_get_cpl(struct kvm_vcpu *vcpu) { return 0; }
static unsigned long tdx_get_rflags(struct kvm_vcpu *vcpu) { return 0; }
static void tdx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags) {}
static bool tdx_is_emulated_msr(u32 index, bool write) { return false; }
static int tdx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr) { return 1; }
static int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr) { return 1; }
static u64 tdx_get_segment_base(struct kvm_vcpu *vcpu, int seg) { return 0; }
static void tdx_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var,
			    int seg) {}
