/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SHARED_TDX_H
#define _ASM_X86_SHARED_TDX_H

#include <linux/bits.h>
#include <linux/types.h>

#define TDX_HYPERCALL_STANDARD  0

#define TDX_CPUID_LEAF_ID	0x21
#define TDX_IDENT		"IntelTDX    "

/* TDX module Call Leaf IDs */
#define TDX_GET_INFO			1
#define TDX_EXTEND_RTMR			2
#define TDX_GET_VEINFO			3
#define TDX_GET_REPORT			4
#define TDX_ACCEPT_PAGE			6
#define TDX_WR				8
#define TDX_VERIFY_REPORT		22

/* TDCS fields. To be used by TDG.VM.WR and TDG.VM.RD module calls */
#define TDCS_NOTIFY_ENABLES		0x9100000000000010

/* TDX hypercall Leaf IDs */
#define TDVMCALL_MAP_GPA		0x10001
#define TDVMCALL_GET_QUOTE		0x10002
#define TDVMCALL_REPORT_FATAL_ERROR	0x10003
#define TDVMCALL_SERVICE		0x10005

/* TDX service command response codes */
#define TDX_SERVICE_CMD_SUCCESS			0x0
#define TDX_SERVICE_CMD_DEVICE_ERR		0x1
#define TDX_SERVICE_CMD_TIMEOUT			0x2
#define TDX_SERVICE_CMD_RESP_BUF_SMALL		0x3
#define TDX_SERVICE_CMD_BAD_CMD_BUF_SIZE	0x4
#define TDX_SERVICE_CMD_BAD_RESP_BUF_SIZE	0x5
#define TDX_SERVICE_CMD_BUSY			0x6
#define TDX_SERVICE_CMD_INVALID_PARAM		0x7
#define TDX_SERVICE_CMD_OUT_OF_RES		0x8
#define TDX_SERVICE_CMD_UNSUPPORTED		0xFFFFFFFE
#define TDX_SERVICE_CMD_RESERVED		0xFFFFFFFF

#ifndef __ASSEMBLY__

/*
 * Used in __tdx_hypercall() to pass down and get back registers' values of
 * the TDCALL instruction when requesting services from the VMM.
 *
 * This is a software only structure and not part of the TDX module/VMM ABI.
 */
struct tdx_hypercall_args {
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 rdi;
	u64 rsi;
	u64 rbx;
	u64 rdx;
};

/* Used to request services from the VMM */
u64 __tdx_hypercall(struct tdx_hypercall_args *args);
u64 __tdx_hypercall_ret(struct tdx_hypercall_args *args);

/*
 * Wrapper for standard use of __tdx_hypercall with no output aside from
 * return code.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = fn,
		.r12 = r12,
		.r13 = r13,
		.r14 = r14,
		.r15 = r15,
	};

	return __tdx_hypercall(&args);
}


/* Called from __tdx_hypercall() for unrecoverable failure */
void __tdx_hypercall_failed(void);

/*
 * Used in __tdx_module_call() to gather the output registers' values of the
 * TDCALL instruction when requesting services from the TDX module. This is a
 * software only structure and not part of the TDX module/VMM ABI
 */
struct tdx_module_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

/* Used to communicate with the TDX module */
u64 __tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		      struct tdx_module_output *out);

bool tdx_accept_memory(phys_addr_t start, phys_addr_t end);

/*
 * The TDG.VP.VMCALL-Instruction-execution sub-functions are defined
 * independently from but are currently matched 1:1 with VMX EXIT_REASONs.
 * Reusing the KVM EXIT_REASON macros makes it easier to connect the host and
 * guest sides of these calls.
 */
static __always_inline u64 hcall_func(u64 exit_reason)
{
        return exit_reason;
}

/**
 * struct tdx_service_req_hdr - Service hypercall request command buffer
 * 				header
 * @guid: GUID of the service requested.
 * @buf_len: Length of the command buffer including the header.
 * @rsvd: Reserved for future use.
 */
struct tdx_service_req_hdr
{
	u8 guid[16];
	u32 buf_len;
	u32 rsvd1;
};

/**
 * struct tdx_service_resp_hdr - Service hypercall response buffer header.
 * @guid: GUID of the service requested.
 * @buf_len: Length of the response buffer including the header.
 * @status: Status of the request.
 */
struct tdx_service_resp_hdr
{
	u8 guid[16];
	u32 buf_len;
	u32 status;
};

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_SHARED_TDX_H */
