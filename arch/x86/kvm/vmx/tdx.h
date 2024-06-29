#ifndef  __KVM_X86_VMX_TDX_H
#define __KVM_X86_VMX_TDX_H

#ifdef CONFIG_INTEL_TDX_HOST
void tdx_bringup(void);
void tdx_cleanup(void);
#else
static inline void tdx_bringup(void) {}
static inline void tdx_cleanup(void) {}
#endif

#endif
