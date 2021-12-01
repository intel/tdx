/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Intel Corporation.
 *
 * Intel TDX P-SEAMLDR support
 */

#ifndef _X86_TDX_P_SEAMLOADER_H
#define _X86_TDX_P_SEAMLOADER_H

int detect_p_seamldr(void);
bool tdx_module_ready(void);

#endif /* _X86_TDX_P_SEAMLOADER_H */
