/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_TDX_H
#define _UAPI_ASM_X86_TDX_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define TDX_REPORT_DATA_LEN		64
#define TDX_TDREPORT_LEN		1024

#define TDX_CMD_GET_TDREPORT		_IOWR('T', 0x01, __u64)
#define TDX_CMD_GEN_QUOTE		_IOR('T', 0x02, __u64)
#define TDX_CMD_GET_QUOTE_SIZE		_IOR('T', 0x03, __u64)

#endif /* _UAPI_ASM_X86_TDX_H */
