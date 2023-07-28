#ifndef _ASM_X86_UNACCEPTED_MEMORY_H
#define _ASM_X86_UNACCEPTED_MEMORY_H

#include <linux/efi.h>
#include <asm/tdx.h>
#include <asm/sev.h>
#include <asm/set_memory.h>

static inline void arch_accept_memory(phys_addr_t start, phys_addr_t end)
{
	/* Platform-specific memory-acceptance call goes here */
	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST)) {
		if (!tdx_accept_memory(start, end))
			panic("TDX: Failed to accept memory\n");
	} else if (cc_platform_has(CC_ATTR_GUEST_SEV_SNP)) {
		snp_accept_memory(start, end);
	} else {
		panic("Cannot accept memory: unknown platform\n");
	}
}

static inline void arch_unaccept_memory(phys_addr_t start, phys_addr_t end)
{
	set_memory_decrypted((unsigned long)__va(start), (end - start) >> PAGE_SHIFT);
}

static inline struct efi_unaccepted_memory *efi_get_unaccepted_table(void)
{
	if (efi.unaccepted == EFI_INVALID_TABLE_ADDR)
		return NULL;
	return __va(efi.unaccepted);
}
#endif
