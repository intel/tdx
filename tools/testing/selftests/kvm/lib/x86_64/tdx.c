// SPDX-License-Identifier: GPL-2.0-only
#include <test_util.h>
#include <kvm_random.h>
#include <kvm_util.h>
#include <processor.h>

#include "tdx.h"

#define VMX_EPTP_MT_WB				0x6ull
#define VMX_EPTP_PWL_4				0x18ull

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

static void tdx_init_td(struct test_td *td)
{
	struct td_params params;

	memset(&params, 0, sizeof(params));
	params.max_vcpus = 1;
	params.eptp_controls = VMX_EPTP_MT_WB | VMX_EPTP_PWL_4;
	params.exec_controls = 0;
	params.xfam = sysinfo.xfam_fixed1;
	params.tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(5 * 1000 * 1000);

	seamcall3(TDH_MNG_INIT, __pa(&td->tdr), __pa(&params));
}

static void tdx_create_tdvps(struct test_td *td)
{
	int i;

	seamcall3(TDH_VP_CREATE, __pa(&td->tdvpr), __pa(&td->tdr));

	for (i = 0; i < ((sysinfo.tdvps_base_size / PAGE_SIZE) - 1); i++)
		seamcall3(TDH_VP_ADDCX, __pa(&td->tdvpx[i]), __pa(&td->tdvpr));

	seamcall3(TDH_VP_INIT, __pa(&td->tdvpr), 0);
}

void tdx_create_td(struct test_td *td)
{
	int i;

	/* Zero the TD, even though it may be redundant, to fault it in. */
	memset(td, 0, sizeof(*td));

	/* Can't get real hkid from KVM, just hardcode a fake hkid. */
	td->hkid = 2;

	seamcall3(TDH_MNG_CREATE, __pa(&td->tdr), td->hkid);

	/* TODO: Run TDCONFIGKEY on each CPU. */
	seamcall2(TDH_SYS_KEY_CONFIG, __pa(&td->tdr));

	for (i = 0; i < ((sysinfo.tdcs_base_size) / PAGE_SIZE); i++)
		seamcall3(TDH_MNG_ADDCX, __pa(&td->tdcx[i]), __pa(&td->tdr));

	tdx_init_td(td);

	tdx_create_tdvps(td);

	seamcall2(TDH_MR_FINALIZE, __pa(&td->tdr));
}

static void tdx_tdwbcache(void)
{
	u64 err = 0;

	do {
		err = seamcall(SEAMCALL_TDH_PHYMEM_CACHE_WB, !!err, 0, 0, 0, 0);
	} while (err == TDX_INTERRUPTED_RESUMABLE);
}

static void tdx_reclaim_td_page(struct td_page *page)
{
	seamcall2(TDH_PHYMEM_PAGE_RECLAIM, __pa(page));
	seamcall2(TDH_PHYMEM_PAGE_WBINVD, __pa(page));
}

void tdx_destroy_td(struct test_td *td)
{
	int i;

	seamcall2(TDH_MNG_KEY_RECLAIMID, __pa(&td->tdr));

	seamcall2(TDH_VP_FLUSH, __pa(&td->tdvpr));

	seamcall2(TDH_MNG_VPFLUSHDONE, __pa(&td->tdr));

	tdx_tdwbcache();

	seamcall2(TDH_MNG_KEY_FREEID, __pa(&td->tdr));

	for (i = 0; i < ((sysinfo.tdvps_base_size / PAGE_SIZE) - 1); i++)
		tdx_reclaim_td_page(&td->tdvpx[i]);
	tdx_reclaim_td_page(&td->tdvpr);

	for (i = 0; i < ((sysinfo.tdcs_base_size) / PAGE_SIZE); i++)
		tdx_reclaim_td_page(&td->tdcx[i]);
	tdx_reclaim_td_page(&td->tdr);
}
