// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_para.h>
#include <linux/kvm.h>
#include "x86/apic.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"

#define APIC_SPIV_MSR	(APIC_BASE_MSR + (APIC_SPIV >> 4))

static uint64_t interrupt_received = -1;
static uint64_t invalid_vector = 0x10;
static uint64_t notify_vector = 0x20;

static uint64_t tdg_vp_vmcall_setup_event_notify(uint64_t vector)
{
	struct tdx_hypercall_args args;

	memset(&args, 0, sizeof(struct tdx_hypercall_args));

	args.r11 = TDG_VP_VMCALL_SETUP_EVENT_NOTIFY;
	args.r12 = vector;

	return __tdx_hypercall(&args, 0);
}

static void guest_code_setup_event_notify(void)
{
	uint64_t status;

	asm volatile("sti");

	tdg_vp_vmcall_instruction_wrmsr(APIC_SPIV_MSR, APIC_SPIV_APIC_ENABLED);

	status = tdg_vp_vmcall_setup_event_notify(invalid_vector);
	if (status != TDG_VP_VMCALL_STATUS_INVALID_OPERAND)
		tdx_test_fatal_with_data(__LINE__, status);

	status = tdg_vp_vmcall_setup_event_notify(notify_vector);
	if (status)
		tdx_test_fatal_with_data(__LINE__, status);

	interrupt_received = -1;
	/* Let userspace inject the interrupt, the value doesn't matter. */
	tdx_test_report_to_user_space(0);

	if (interrupt_received != notify_vector)
		tdx_test_fatal_with_data(__LINE__, interrupt_received);

	tdx_test_success();
}

static void guest_event_notify_handler(struct ex_regs *regs)
{
	interrupt_received = regs->vector;
}

static void inject_interrupt(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint32_t vector)
{
	struct kvm_msi msi = {
		.address_lo	= (vcpu->id & 0xff) << 12,
		.address_hi	= vcpu->id & 0xffffff00,
		.data		= vector | (APIC_DM_FIXED << 8),
	};

	__vm_ioctl(vm, KVM_SIGNAL_MSI, &msi);
}

void vcpu_run_and_handle_events(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	static uint64_t notify_vector = -1;

	for (;;) {
		tdx_run(vcpu);

		if (vcpu->run->exit_reason == KVM_EXIT_TDX_SETUP_EVENT_NOTIFY) {
			if (vcpu->run->tdx_setup_event_notify.vector >= 32) {
				vcpu->run->tdx_setup_event_notify.ret = 0;
				notify_vector = vcpu->run->tdx_setup_event_notify.vector;
			} else {
				/* This should not happen. */
				TEST_ASSERT(0, "Unexpected vector range, KVM should have checked the range.");
			}
			continue;
		} else if (vcpu->run->exit_reason == KVM_EXIT_IO &&
			   vcpu->run->io.port == TDX_TEST_REPORT_PORT) {
			/* Inject a interrupt with vector set up. */
			inject_interrupt(vm, vcpu, notify_vector);
			continue;
		}
		break;
	}
}

static void verify_setup_event_notify(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);

	vcpu = td_vcpu_add(vm, 0, guest_code_setup_event_notify);
	vm_install_exception_handler(vm, notify_vector, guest_event_notify_handler);

	td_finalize(vm);

	printf("TDG.VP.VMCALL<SetupEventNotifyInterrupt>:\n");
	vcpu_run_and_handle_events(vm, vcpu);
	tdx_test_assert_success(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

int main(int argc, char **argv)
{
	ksft_print_header();

	if (!is_tdx_enabled())
		ksft_exit_skip("TDX is not supported by the KVM. Exiting.\n");

	ksft_set_plan(1);
	ksft_test_result(!run_in_new_process(&verify_setup_event_notify),
			 "verify_setup_event_notify\n");

	ksft_finished();
	return 0;
}
