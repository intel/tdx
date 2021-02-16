/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_OPS_H
#define __KVM_X86_TDX_OPS_H

#include <linux/compiler.h>

#include <asm/asm.h>
#include <asm/kvm_host.h>
#include <asm/cacheflush.h>

struct tdx_ex_ret {
	union {
		/* Used to retrieve values from hardware. */
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
		};
		/* Functions that return SEPT and level that failed. */
		struct {
			u64 septep;
			int level;
		};
		/* TDDBG{RD,WR} return the TDR, field code, and value. */
		struct {
			u64 tdr;
			u64 field;
			u64 field_val;
		};
		/* TDDBG{RD,WR}MEM return the address and its value. */
		struct {
			u64 addr;
			u64 val;
		};
		/* TDRDPAGEMD and TDRECLAIMPAGE return page metadata. */
		struct {
			u64 page_type;
			u64 owner;
			u64 page_size;
		};
		/* TDRDSEPT returns the contents of the SEPT entry. */
		struct {
			u64 septe;
			u64 ign;
		};
		/*
		 * TDSYSINFO returns the buffer address and its size, and the
		 * CMR_INFO address and its number of entries.
		 */
		struct {
			u64 buffer;
			u64 nr_bytes;
			u64 cmr_info;
			u64 nr_cmr_entries;
		};
		/*
		 * TDINIT and TDSYSINIT return CPUID info on error.  Note, only
		 * the leaf and subleaf are valid on TDINIT error.
		 */
		struct {
			u32 leaf;
			u32 subleaf;
			u32 eax_mask;
			u32 ebx_mask;
			u32 ecx_mask;
			u32 edx_mask;
			u32 eax_val;
			u32 ebx_val;
			u32 ecx_val;
			u32 edx_val;
		};
		/* TDSYSINITTDMR returns the input PA and next PA. */
		struct {
			u64 prev;
			u64 next;
		};
	};
};

#define pr_seamcall_error(op, err)					  \
	pr_err_ratelimited("SEAMCALL[" #op "] failed: 0x%llx (cpu %d)\n", \
			   (err), smp_processor_id())

#define pr_seamcall_error_ex(op, err, ex)				\
	pr_err_ratelimited("SEAMCALL[" #op "] failed: "			\
			   "0x%llx 0x%llx 0x%llx (cpu %d)\n",		\
			   (err), (ex)->rcx, (ex)->rdx,			\
			   smp_processor_id())

#define TDX_ERR(err, op)			\
({						\
	int __ret_warn_on = WARN_ON_ONCE(err);	\
						\
	if (unlikely(__ret_warn_on))		\
		pr_seamcall_error(op, err);	\
	__ret_warn_on;				\
})

#define tdenter(args...)		({ 0; })

#define seamcall ".byte 0x66,0x0f,0x01,0xcf"

#ifndef	INTEL_TDX_BOOT_TIME_SEAMCALL
#define __seamcall				\
	"1:" seamcall "\n\t"			\
	"jmp 3f\n\t"				\
	"2: call kvm_spurious_fault\n\t"	\
	"3:\n\t"				\
	_ASM_EXTABLE(1b, 2b)
#else
/*
 * The default BUG()s on faults, which is undesirable during boot, and calls
 * kvm_spurious_fault(), which isn't linkable if KVM is built as a module.
 * RAX contains '0' on success, TDX-SEAM errno on failure, vector on fault.
 */
#define __seamcall			\
	"1:" seamcall "\n\t"		\
	"2: \n\t"			\
	_ASM_EXTABLE_FAULT(1b, 2b)
#endif

#define seamcall_N(fn, inputs...)					\
do {									\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret)			\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	return ret;							\
} while (0)

#define seamcall_0(fn)	 						\
	seamcall_N(fn, "i"(0))
#define seamcall_1(fn, rcx)	 					\
	seamcall_N(fn, "c"(rcx))
#define seamcall_2(fn, rcx, rdx)					\
	seamcall_N(fn, "c"(rcx), "d"(rdx))
#define seamcall_3(fn, rcx, rdx, __r8)					\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N(fn, "c"(rcx), "d"(rdx), "r"(r8));			\
} while (0)
#define seamcall_4(fn, rcx, rdx, __r8, __r9)				\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N(fn, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));		\
} while (0)

#define seamcall_N_2(fn, ex, inputs...)					\
do {									\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret),			\
		       "=c"((ex)->rcx), "=d"((ex)->rdx)			\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	return ret;							\
} while (0)

#define seamcall_0_2(fn, ex)						\
	seamcall_N_2(fn, ex, "i"(0))
#define seamcall_1_2(fn, rcx, ex)					\
	seamcall_N_2(fn, ex, "c"(rcx))
#define seamcall_2_2(fn, rcx, rdx, ex)					\
	seamcall_N_2(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_2(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_2(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_2(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_2(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

#define seamcall_N_3(fn, ex, inputs...)					\
do {									\
	register long r8_out asm("r8");					\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret),			\
		       "=c"((ex)->rcx), "=d"((ex)->rdx), "=r"(r8_out)	\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	(ex)->r8 = r8_out;						\
	return ret;							\
} while (0)

#define seamcall_0_3(fn, ex)						\
	seamcall_N_3(fn, ex, "i"(0))
#define seamcall_1_3(fn, rcx, ex)					\
	seamcall_N_3(fn, ex, "c"(rcx))
#define seamcall_2_3(fn, rcx, rdx, ex)					\
	seamcall_N_3(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_3(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_3(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_3(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_3(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

#define seamcall_N_4(fn, ex, inputs...)					\
do {									\
	register long r8_out asm("r8");					\
	register long r9_out asm("r9");					\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret), "=c"((ex)->rcx),	\
		       "=d"((ex)->rdx), "=r"(r8_out), "=r"(r9_out)	\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	(ex)->r8 = r8_out;						\
	(ex)->r9 = r9_out;						\
	return ret;							\
} while (0)

#define seamcall_0_4(fn, ex)						\
	seamcall_N_4(fn, ex, "i"(0))
#define seamcall_1_4(fn, rcx, ex)					\
	seamcall_N_4(fn, ex, "c"(rcx))
#define seamcall_2_4(fn, rcx, rdx, ex)					\
	seamcall_N_4(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_4(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_4(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_4(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_4(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

#define seamcall_N_5(fn, ex, inputs...)					\
do {									\
	register long r8_out asm("r8");					\
	register long r9_out asm("r9");					\
	register long r10_out asm("r10");				\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret), "=c"((ex)->rcx),	\
		       "=d"((ex)->rdx), "=r"(r8_out), "=r"(r9_out),	\
		       "=r"(r10_out)					\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	(ex)->r8 = r8_out;						\
	(ex)->r9 = r9_out;						\
	(ex)->r10 = r10_out;						\
	return ret;							\
} while (0)

#define seamcall_0_5(fn, ex)						\
	seamcall_N_5(fn, ex, "i"(0))
#define seamcall_1_5(fn, rcx, ex)					\
	seamcall_N_5(fn, ex, "c"(rcx))
#define seamcall_2_5(fn, rcx, rdx, ex)					\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_5(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_5(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)
#define seamcall_5_5(fn, rcx, rdx, __r8, __r9, __r10, ex)		\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
	register long r10 asm("r10") = __r10;				\
									\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9), "r"(r10)); \
} while (0)

static inline void tdx_clflush_page(hpa_t addr)
{
	clflush_cache_range(__va(addr), PAGE_SIZE);
}

static inline u64 tdaddcx(hpa_t tdr, hpa_t addr)
{
	tdx_clflush_page(addr);
	seamcall_2(TDADDCX, addr, tdr);
}

static inline u64 tdaddpage(hpa_t tdr, gpa_t gpa, hpa_t hpa, hpa_t source,
			    struct tdx_ex_ret *ex)
{
	tdx_clflush_page(hpa);
	seamcall_4_2(TDADDPAGE, gpa, tdr, hpa, source, ex);
}

static inline u64 tdaddsept(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
			    struct tdx_ex_ret *ex)
{
	tdx_clflush_page(page);
	seamcall_3_2(TDADDSEPT, gpa | level, tdr, page, ex);
}

static inline u64 tdaddvpx(hpa_t tdvpr, hpa_t addr)
{
	tdx_clflush_page(addr);
	seamcall_2(TDADDVPX, addr, tdvpr);
}

static inline u64 tdassignhkid(hpa_t tdr, int hkid)
{
	seamcall_3(TDASSIGNHKID, tdr, 0, hkid);
}

static inline u64 tdaugpage(hpa_t tdr, gpa_t gpa, hpa_t hpa,
			    struct tdx_ex_ret *ex)
{
	tdx_clflush_page(hpa);
	seamcall_3_2(TDAUGPAGE, gpa, tdr, hpa, ex);
}

static inline u64 tdblock(hpa_t tdr, gpa_t gpa, int level,
			  struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDBLOCK, gpa | level, tdr, ex);
}

static inline u64 tdconfigkey(hpa_t tdr)
{
	seamcall_1(TDCONFIGKEY, tdr);
}

static inline u64 tdcreate(hpa_t tdr, int hkid)
{
	tdx_clflush_page(tdr);
	seamcall_2(TDCREATE, tdr, hkid);
}

static inline u64 tdcreatevp(hpa_t tdr, hpa_t tdvpr)
{
	tdx_clflush_page(tdvpr);
	seamcall_2(TDCREATEVP, tdvpr, tdr);
}

static inline u64 tddbgrd(hpa_t tdr, u64 field, struct tdx_ex_ret *ex)
{
	seamcall_2_3(TDDBGRD, tdr, field, ex);
}

static inline u64 tddbgwr(hpa_t tdr, u64 field, u64 val, u64 mask,
			  struct tdx_ex_ret *ex)
{
	seamcall_4_3(TDDBGWR, tdr, field, val, mask, ex);
}

static inline u64 tddbgrdmem(hpa_t addr, struct tdx_ex_ret *ex)
{
	seamcall_1_2(TDDBGRDMEM, addr, ex);
}

static inline u64 tddbgwrmem(hpa_t addr, u64 val, struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDDBGWRMEM, addr, val, ex);
}

static inline u64 tddemotepage(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
			       struct tdx_ex_ret *ex)
{
	seamcall_3_2(TDDEMOTEPAGE, gpa | level, tdr, page, ex);
}

static inline u64 tdextendmr(hpa_t tdr, gpa_t gpa, struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDEXTENDMR, gpa, tdr, ex);
}

static inline u64 tdfinalizemr(hpa_t tdr)
{
	seamcall_1(TDFINALIZEMR, tdr);
}

static inline u64 tdflushvp(hpa_t tdvpr)
{
	seamcall_1(TDFLUSHVP, tdvpr);
}

static inline u64 tdflushvpdone(hpa_t tdr)
{
	seamcall_1(TDFLUSHVPDONE, tdr);
}

static inline u64 tdfreehkids(hpa_t tdr)
{
	seamcall_1(TDFREEHKIDS, tdr);
}

static inline u64 tdinit(hpa_t tdr, hpa_t td_params, struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDINIT, tdr, td_params, ex);
}

static inline u64 tdinitvp(hpa_t tdvpr, u64 rcx)
{
	seamcall_2(TDINITVP, tdvpr, rcx);
}

static inline u64 tdpromotepage(hpa_t tdr, gpa_t gpa, int level,
				struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDPROMOTEPAGE, gpa | level, tdr, ex);
}

static inline u64 tdrdpagemd(hpa_t page, struct tdx_ex_ret *ex)
{
	seamcall_1_3(TDRDPAGEMD, page, ex);
}

static inline u64 tdrdsept(hpa_t tdr, gpa_t gpa, int level,
			   struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDRDSEPT, gpa | level, tdr, ex);
}

static inline u64 tdrdvps(hpa_t tdvpr, u64 field, struct tdx_ex_ret *ex)
{
	seamcall_2_3(TDRDVPS, tdvpr, field, ex);
}

static inline u64 tdreclaimhkids(hpa_t tdr)
{
	seamcall_1(TDRECLAIMHKIDS, tdr);
}

static inline u64 tdreclaimpage(hpa_t page, struct tdx_ex_ret *ex)
{
	seamcall_1_3(TDRECLAIMPAGE, page, ex);
}

static inline u64 tdremovepage(hpa_t tdr, gpa_t gpa, int level,
				struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDREMOVEPAGE, gpa | level, tdr, ex);
}

static inline u64 tdremovesept(hpa_t tdr, gpa_t gpa, int level,
			       struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDREMOVESEPT, gpa | level, tdr, ex);
}

static inline u64 tdsysconfig(hpa_t tdmr, int nr_entries, int hkid)
{
	seamcall_3(TDSYSCONFIG, tdmr, nr_entries, hkid);
}

static inline u64 tdsysconfigkey(void)
{
	seamcall_0(TDSYSCONFIGKEY);
}

static inline u64 tdsysinfo(hpa_t tdsysinfo, int nr_bytes, hpa_t cmr_info,
			    int nr_cmr_entries, struct tdx_ex_ret *ex)
{
	seamcall_4_4(TDSYSINFO, tdsysinfo, nr_bytes, cmr_info, nr_cmr_entries, ex);
}

static inline u64 tdsysinit(u64 attributes, struct tdx_ex_ret *ex)
{
	seamcall_1_5(TDSYSINIT, attributes, ex);
}

static inline u64 tdsysinitlp(struct tdx_ex_ret *ex)
{
	seamcall_0_3(TDSYSINITLP, ex);
}

static inline u64 tdsysinittdmr(hpa_t tdmr, struct tdx_ex_ret *ex)
{
	seamcall_1_2(TDSYSINITTDMR, tdmr, ex);
}

static inline u64 tdsysshutdownlp(void)
{
	seamcall_0(TDSYSSHUTDOWNLP);
}

static inline u64 tdteardown(hpa_t tdr)
{
	seamcall_1(TDTEARDOWN, tdr);
}

static inline u64 tdtrack(hpa_t tdr)
{
	seamcall_1(TDTRACK, tdr);
}

static inline u64 tdunblock(hpa_t tdr, gpa_t gpa, int level,
			    struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDUNBLOCK, gpa | level, tdr, ex);
}

static inline u64 tdwbcache(bool resume)
{
	seamcall_1(TDWBCACHE, resume ? 1 : 0);
}

static inline u64 tdwbinvdpage(hpa_t page)
{
	seamcall_1(TDWBINVDPAGE, page);
}

static inline u64 tdwrsept(hpa_t tdr, gpa_t gpa, int level, u64 val,
			   struct tdx_ex_ret *ex)
{
	seamcall_3_2(TDWRSEPT, gpa | level, tdr, val, ex);
}

static inline u64 tdwrvps(hpa_t tdvpr, u64 field, u64 val, u64 mask,
			  struct tdx_ex_ret *ex)
{
	seamcall_4_3(TDWRVPS, tdvpr, field, val, mask, ex);
}

static inline u64 tddebugconfig(u64 subleaf, u64 param1, u64 param2)
{
	seamcall_3(TDDEBUGCONFIG, subleaf, param1, param2);
}

static inline void tdx_trace_seamcalls(u64 level)
{
	u64 err;

	err = tddebugconfig(DEBUGCONFIG_SET_TRACE_LEVEL, level, 0);
	if (err)
		pr_seamcall_error(TDDEBUGCONFIG, err);
}

static inline u64 tdxmode(bool intercept_vmexits, u64 intercept_bitmap)
{
	seamcall_2(TDXMODE, intercept_vmexits, intercept_bitmap);
}

#endif /* __KVM_X86_TDX_OPS_H */
