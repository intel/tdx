// SPDX-License-Identifier: GPL-2.0-only
#include <test_util.h>
#include <kvm_random.h>
#include <kvm_util.h>
#include <processor.h>

#include "tdx.h"

struct tdsysinfo_struct sysinfo;

int kvm_fd;

static struct kvm_vm *dummy_vm;

void tdx_enable(int argc, char **argv)
{
	struct cmr_info cmrs[TDX_MAX_NR_CMRS] __aligned(512);

	init_random(parse_seed(argc, argv));

	kvm_fd = open(KVM_DEV_PATH, O_RDWR);
	TEST_ASSERT(kvm_fd >= 0, "failed to open /dev/kvm fd: %i errno: %i",
		    kvm_fd, errno);

	/* Create a dummy VM to coerce KVM into doing VMXON. */
	dummy_vm = vm_create_default(0, 0, NULL);


	seamcall5(TDH_SYS_INFO, __pa(&sysinfo), sizeof(sysinfo), __pa(&cmrs),
		  ARRAY_SIZE(cmrs));
}

void tdx_disable(void)
{
	close(kvm_fd);
	kvm_vm_free(dummy_vm);
}
