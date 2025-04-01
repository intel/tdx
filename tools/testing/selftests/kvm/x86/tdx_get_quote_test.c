// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_para.h>
#include <linux/kvm.h>
#include <linux/tdx-guest.h>
#include <linux/sizes.h>
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"

#define GET_QUOTE_CMD_VER	1

#define TEST_BUF_SIZE	SZ_4K

/* TDX GetQuote status codes */
#define GET_QUOTE_SUCCESS		0
#define GET_QUOTE_IN_FLIGHT		0xffffffffffffffff

struct tdx_quote_buf {
	u64 version;
	u64 status;
	u32 in_len;
	u32 out_len;
	u8 data[];
};

static uint64_t test_buffer_gpa;
static uint64_t test_buffer_gpa_shared;
static const uint64_t test_buffer_gva = 0x90000000;
static const uint64_t test_buffer_gva_shared = 0x90000000 | BIT_ULL(32);

static uint64_t tdg_vp_vmcall_get_quote(uint64_t gpa, uint64_t size)
{
	struct tdx_hypercall_args args;

	memset(&args, 0, sizeof(struct tdx_hypercall_args));

	args.r11 = TDG_VP_VMCALL_GET_QUOTE;
	args.r12 = gpa;
	args.r13 = size;

	return __tdx_hypercall(&args, 0);
}

static void guest_code_get_quote(void)
{
	uint64_t placeholder, ret;
	struct tdx_quote_buf *quote_buf = (struct tdx_quote_buf *) test_buffer_gva_shared;

	ret = tdg_vp_vmcall_get_quote(test_buffer_gpa, TEST_BUF_SIZE);
	if (ret != TDG_VP_VMCALL_STATUS_INVALID_OPERAND)
		tdx_test_fatal_with_data(__LINE__, ret);

	ret = tdg_vp_vmcall_map_gpa(test_buffer_gpa_shared, TEST_BUF_SIZE, &placeholder);
	if (ret)
		tdx_test_fatal_with_data(__LINE__, ret);

	memset(quote_buf, 0, TEST_BUF_SIZE);
	quote_buf->version = GET_QUOTE_CMD_VER;
	quote_buf->in_len = TDX_REPORT_LEN;

	ret = tdg_vp_vmcall_get_quote(test_buffer_gpa_shared, TEST_BUF_SIZE);
	if (ret)
		tdx_test_fatal_with_data(__LINE__, ret);

	if (quote_buf->status != GET_QUOTE_IN_FLIGHT)
		tdx_test_fatal_with_data(__LINE__, quote_buf->status);

	/* Let userspace change status field, the value doesn't matter. */
	tdx_test_report_to_user_space(0);

	if (quote_buf->status != GET_QUOTE_SUCCESS)
		tdx_test_fatal_with_data(__LINE__, quote_buf->status);

	tdx_test_success();
}

void vcpu_run_and_handle_events(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	struct tdx_quote_buf *quote_buf = addr_gva2hva(vm, test_buffer_gva_shared);

	for (;;) {
		tdx_run(vcpu);

		if (vcpu->run->exit_reason == KVM_EXIT_HYPERCALL &&
		    vcpu->run->hypercall.nr == KVM_HC_MAP_GPA_RANGE) {
			uint64_t gpa = vcpu->run->hypercall.args[0];

			handle_memory_conversion(vm, vcpu->id, gpa,
						 vcpu->run->hypercall.args[1] << 12,
						 vcpu->run->hypercall.args[2] &
						 KVM_MAP_GPA_RANGE_ENCRYPTED);
			vcpu->run->hypercall.ret = 0;
			continue;
		} else if (vcpu->run->exit_reason == KVM_EXIT_TDX_GET_QUOTE) {
			TEST_ASSERT_EQ(quote_buf->version, GET_QUOTE_CMD_VER);
			TEST_ASSERT_EQ(quote_buf->in_len, TDX_REPORT_LEN);
			TEST_ASSERT(!(vcpu->run->tdx_get_quote.gpa & vm->arch.s_bit),
				    "Shared-bit should have been dropped.");
			quote_buf->status = GET_QUOTE_IN_FLIGHT;
			vcpu->run->tdx_get_quote.ret = 0;
			continue;
		} else if (vcpu->run->exit_reason == KVM_EXIT_IO &&
			   vcpu->run->io.port == TDX_TEST_REPORT_PORT) {
			quote_buf->status = GET_QUOTE_SUCCESS;
			continue;
		}
		break;
	}
}

static void verify_get_quote(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t npages;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);

	vcpu = td_vcpu_add(vm, 0, guest_code_get_quote);

	TEST_ASSERT_EQ(vm_vaddr_alloc(vm, TEST_BUF_SIZE, test_buffer_gva), test_buffer_gva);
	test_buffer_gpa = addr_gva2gpa(vm, test_buffer_gva);
	sync_global_to_guest(vm, test_buffer_gpa);

	test_buffer_gpa_shared = test_buffer_gpa | vm->arch.s_bit;
	sync_global_to_guest(vm, test_buffer_gpa_shared);

	npages = (TEST_BUF_SIZE + vm->page_size - 1) >> vm->page_shift;
	virt_map_shared(vm, test_buffer_gva_shared, test_buffer_gpa, npages);
	TEST_ASSERT_EQ(addr_gva2gpa(vm, test_buffer_gva_shared), test_buffer_gpa);

	td_finalize(vm);
	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL, BIT_ULL(KVM_HC_MAP_GPA_RANGE));

	printf("TDG.VP.VMCALL<GetQuote>:\n");
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
	ksft_test_result(!run_in_new_process(&verify_get_quote),
			 "verify_get_quote\n");

	ksft_finished();
	return 0;
}
