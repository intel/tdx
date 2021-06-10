/* SPDX-License-Identifier: GPL-2.0 */
/* helper functions to invoke SEAM ACM. */

#ifndef _X86_TDX_SEAM_H
#define _X86_TDX_SEAM_H

bool __init seam_get_firmware(struct cpio_data *blob, const char *name);

extern int seam_vmxon_size __initdata;	/* for p_seamldr_get_info() */
int __init seam_init_vmx_early(void);

int __init seam_init_vmxon_vmcs(struct vmcs *vmcs);
void __init seam_free_vmcs(void);
int __init seam_alloc_vmcs(void);
int __init seam_init_vmcs(void);
int __init seam_vmxon(void);
int __init seam_vmxoff(void);

#endif /* _X86_TDX_SEAM_H */
