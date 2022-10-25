/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KVM_LIB_TDX_H_
#define KVM_LIB_TDX_H_

#include <kvm_util.h>
#include "processor.h"

/*
 * Max page size for the guest image.
 */
#define TDX_GUEST_MAX_NR_PAGES 10000

/*
 * Max number of vCPUs for the guest VM
 */
 #define TDX_GUEST_MAX_NUM_VCPUS 3

/*
 * Page Table Address used when paging is enabled.
 */
#define TDX_GUEST_PT_FIXED_ADDR (0xFFFFFFFF -\
				 (TDX_GUEST_MAX_NR_PAGES * PAGE_SIZE) + 1)

/*
 * Max Page Table Size
 * To map 4GB memory regions for each private and shared memory with 2MB pages,
 * there needs to be 1 page for PML4, 1 Page for PDPT, 8 pages for PD. Reserving
 * 10 pages for PT.
 */
#define TDX_GUEST_NR_PT_PAGES (1 + 1 + 8)

/*
 * Guest Virtual Address Shared Bit
 * TDX's shared bit is defined as the highest order bit in the GPA. Since the
 * highest order bit allowed in the GPA may exceed the GVA's, a 1:1 mapping
 * cannot be applied for shared memory. This value is a bit within the range
 * [32 - 38] (0-indexed) that will designate a 4 GB region of GVAs that map the
 * shared GPAs. This approach does not increase number of PML4 and PDPT pages.
 */
#define TDX_GUEST_VIRT_SHARED_BIT 32

/*
 * Predefined GDTR values.
 */
#define TDX_GUEST_GDTR_ADDR (TDX_GUEST_PT_FIXED_ADDR + (TDX_GUEST_NR_PT_PAGES *\
							PAGE_SIZE))
#define TDX_GUEST_GDTR_BASE (TDX_GUEST_GDTR_ADDR + PAGE_SIZE)
#define TDX_GUEST_LINEAR_CODE64_SEL 0x38

#define TDX_GUEST_STACK_NR_PAGES (3)
#define TDX_GUEST_STACK_BASE (TDX_GUEST_GDTR_BASE + (TDX_GUEST_STACK_NR_PAGES *\
						     PAGE_SIZE) - 1)
/*
 * Reserving some pages to copy the test code. This is an arbitrary number for
 * now to simplify to guest image layout calculation.
 * TODO: calculate the guest code dynamcially.
 */
#define TDX_GUEST_CODE_ENTRY (TDX_GUEST_GDTR_BASE + (TDX_GUEST_STACK_NR_PAGES *\
						     PAGE_SIZE))

#define KVM_MAX_CPUID_ENTRIES 256

/*
 * TODO: Move page attributes to processor.h file.
 */
#define _PAGE_PRESENT       (1UL<<0)       /* is present */
#define _PAGE_RW            (1UL<<1)       /* writeable */
#define _PAGE_PS            (1UL<<7)       /* page size bit*/

#define TDX_VMCALL_SUCCESS 0x0000000000000000
#define TDX_VMCALL_INVALID_OPERAND 0x8000000000000000

#define TDX_GET_TD_VM_CALL_INFO 0x10000
#define TDX_MAP_GPA 0x10001
#define TDX_REPORT_FATAL_ERROR 0x10003
#define TDX_INSTRUCTION_CPUID 10
#define TDX_INSTRUCTION_HLT 12
#define TDX_INSTRUCTION_IO 30
#define TDX_INSTRUCTION_RDMSR 31
#define TDX_INSTRUCTION_WRMSR 32
#define TDX_INSTRUCTION_VE_REQUEST_MMIO 48

#define TDX_SUCCESS_PORT 0x30
#define TDX_TEST_PORT 0x31
#define TDX_DATA_REPORT_PORT 0x32
#define TDX_IO_READ 0
#define TDX_IO_WRITE 1
#define TDX_MMIO_READ 0
#define TDX_MMIO_WRITE 1

#define TDX_TDCALL_INFO   1

#define TDX_TDPARAM_ATTR_SEPT_VE_DISABLE_BIT	(1UL << 28)
#define TDX_TDPARAM_ATTR_PKS_BIT		(1UL << 30)

#define GDT_ENTRY(flags, base, limit)				\
		((((base)  & 0xff000000ULL) << (56-24)) |	\
		 (((flags) & 0x0000f0ffULL) << 40) |		\
		 (((limit) & 0x000f0000ULL) << (48-16)) |	\
		 (((base)  & 0x00ffffffULL) << 16) |		\
		 (((limit) & 0x0000ffffULL)))

struct tdx_cpuid_data {
	struct kvm_cpuid2 cpuid;
	struct kvm_cpuid_entry2 entries[KVM_MAX_CPUID_ENTRIES];
};

struct __packed tdx_gdtr {
	uint16_t limit;
	uint32_t base;
};

struct page_table {
	uint64_t  pml4[512];
	uint64_t  pdpt[512];
	uint64_t  pd[8][512];
};

void add_td_memory(struct kvm_vm *vm, void *source_page,
		   uint64_t gpa, int size);
void finalize_td_memory(struct kvm_vm *vm);
void get_tdx_capabilities(struct kvm_vm *vm);
void initialize_td(struct kvm_vm *vm);
void initialize_td_with_attributes(struct kvm_vm *vm, uint64_t attributes);
void initialize_td_vcpu(struct kvm_vcpu *vcpu);
void prepare_source_image(struct kvm_vm *vm, void *guest_code,
			  size_t guest_code_size,
			  uint64_t guest_code_signature);

/*
 * Generic TDCALL function that can be used to communicate with TDX module or
 * VMM.
 * Input operands: rax, rbx, rcx, rdx, r8-r15, rbp, rsi, rdi
 * Output operands: rax, r8-r15, rbx, rdx, rdi, rsi
 * rcx is actually a bitmap to tell TDX module which register values will be
 * exposed to the VMM.
 * XMM0-XMM15 registers can be used as input operands but the current
 * implementation does not support it yet.
 */
static inline void tdcall(struct kvm_regs *regs)
{
	asm volatile (
			"mov %14, %%rax;\n\t"
			"mov %15, %%rbx;\n\t"
			"mov %16, %%rcx;\n\t"
			"mov %17, %%rdx;\n\t"
			"mov %18, %%r8;\n\t"
			"mov %19, %%r9;\n\t"
			"mov %20, %%r10;\n\t"
			"mov %21, %%r11;\n\t"
			"mov %22, %%r12;\n\t"
			"mov %23, %%r13;\n\t"
			"mov %24, %%r14;\n\t"
			"mov %25, %%r15;\n\t"
			"mov %26, %%rbp;\n\t"
			"mov %27, %%rsi;\n\t"
			"mov %28, %%rdi;\n\t"
			".byte 0x66, 0x0F, 0x01, 0xCC;\n\t"
			"mov %%rax, %0;\n\t"
			"mov %%rbx, %1;\n\t"
			"mov %%rcx, %2;\n\t"
			"mov %%rdx, %3;\n\t"
			"mov %%r8, %4;\n\t"
			"mov %%r9, %5;\n\t"
			"mov %%r10, %6;\n\t"
			"mov %%r11, %7;\n\t"
			"mov %%r12, %8;\n\t"
			"mov %%r13, %9;\n\t"
			"mov %%r14, %10;\n\t"
			"mov %%r15, %11;\n\t"
			"mov %%rsi, %12;\n\t"
			"mov %%rdi, %13;\n\t"
			: "=m" (regs->rax), "=m" (regs->rbx), "=m" (regs->rcx),
			"=m" (regs->rdx), "=m" (regs->r8), "=m" (regs->r9),
			"=m" (regs->r10), "=m" (regs->r11), "=m" (regs->r12),
			"=m" (regs->r13), "=m" (regs->r14), "=m" (regs->r15),
			"=m" (regs->rsi), "=m" (regs->rdi)
			: "m" (regs->rax), "m" (regs->rbx), "m" (regs->rcx),
			"m" (regs->rdx), "m" (regs->r8), "m" (regs->r9),
			"m" (regs->r10), "m" (regs->r11), "m" (regs->r12),
			"m" (regs->r13), "m" (regs->r14), "m" (regs->r15),
			"m" (regs->rbp), "m" (regs->rsi), "m" (regs->rdi)
			: "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11",
			"r12", "r13", "r14", "r15", "rbp", "rsi", "rdi");
}


/*
 * Do a TDVMCALL IO request
 *
 * Input Args:
 *  port - IO port to do read/write
 *  size - Number of bytes to read/write. 1=1byte, 2=2bytes, 4=4bytes.
 *  write - 1=IO write 0=IO read
 *  data - pointer for the data to write
 *
 * Output Args:
 *  data - pointer for data to be read
 *
 * Return:
 *   On success, return 0. For Invalid-IO-Port error, returns -1.
 *
 * Does an IO operation using the following tdvmcall interface.
 *
 * TDG.VP.VMCALL<Instruction.IO>-Input Operands
 * R11 30 for IO
 *
 * R12 Size of access. 1=1byte, 2=2bytes, 4=4bytes.
 * R13 Direction. 0=Read, 1=Write.
 * R14 Port number
 * R15 Data to write, if R13 is 1.
 *
 * TDG.VP.VMCALL<Instruction.IO>-Output Operands
 * R10 TDG.VP.VMCALL-return code.
 * R11 Data to read, if R13 is 0.
 *
 * TDG.VP.VMCALL<Instruction.IO>-Status Codes
 * Error Code Value Description
 * TDG.VP.VMCALL_SUCCESS 0x0 TDG.VP.VMCALL is successful
 * TDG.VP.VMCALL_INVALID_OPERAND 0x80000000 00000000 Invalid-IO-Port access
 */
static inline uint64_t tdvmcall_io(uint64_t port, uint64_t size,
				   uint64_t write, uint64_t *data)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_INSTRUCTION_IO;
	regs.r12 = size;
	regs.r13 = write;
	regs.r14 = port;
	if (write) {
		regs.r15 = *data;
		regs.rcx = 0xFC00;
	} else {
		regs.rcx = 0x7C00;
	}
	tdcall(&regs);
	if (!write)
		*data = regs.r11;
	return regs.r10;
}

/*
 * Report test success to user space.
 */
static inline void tdvmcall_success(void)
{
	uint64_t code = 0;

	tdvmcall_io(TDX_SUCCESS_PORT, /*size=*/4, TDX_IO_WRITE, &code);
}

/*
 * Report an error to user space.
 * data_gpa may point to an optional shared guest memory holding the error string.
 * Return value from tdvmcall is ignored since execution is not expected to
 * continue beyond this point.
 */
static inline void tdvmcall_fatal(uint64_t error_code)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_REPORT_FATAL_ERROR;
	regs.r12 = error_code;
	regs.rcx = 0x1C00;
	tdcall(&regs);
}

/*
 * Get td vmcall info.
 * Used to help request the host VMM enumerate which TDG.VP.VMCALLs are supported.
 * Returns return in r10 code and leaf-specific output in r11-r14.
 */
static inline uint64_t tdvmcall_get_td_vmcall_info(uint64_t *r11, uint64_t *r12,
						   uint64_t *r13, uint64_t *r14)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_GET_TD_VM_CALL_INFO;
	regs.r12 = 0;
	regs.rcx = 0x1C00;
	tdcall(&regs);
	*r11 = regs.r11;
	*r12 = regs.r12;
	*r13 = regs.r13;
	*r14 = regs.r14;
	return regs.r10;
}

/*
 * Read MSR register.
 */
static inline uint64_t tdvmcall_rdmsr(uint64_t index, uint64_t *ret_value)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_INSTRUCTION_RDMSR;
	regs.r12 = index;
	regs.rcx = 0x1C00;
	tdcall(&regs);
	*ret_value = regs.r11;
	return regs.r10;
}

/*
 * Write MSR register.
 */
static inline uint64_t tdvmcall_wrmsr(uint64_t index, uint64_t value)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_INSTRUCTION_WRMSR;
	regs.r12 = index;
	regs.r13 = value;
	regs.rcx = 0x3C00;
	tdcall(&regs);
	return regs.r10;
}

/*
 * Execute HLT instruction.
 */
static inline uint64_t tdvmcall_hlt(uint64_t interrupt_blocked_flag)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_INSTRUCTION_HLT;
	regs.r12 = interrupt_blocked_flag;
	regs.rcx = 0x1C00;
	tdcall(&regs);
	return regs.r10;
}

/*
 * Execute MMIO request instruction for read.
 */
static inline uint64_t tdvmcall_mmio_read(uint64_t address, uint64_t size, uint64_t *data_out)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_INSTRUCTION_VE_REQUEST_MMIO;
	regs.r12 = size;
	regs.r13 = TDX_MMIO_READ;
	regs.r14 = address;
	regs.rcx = 0x7C00;
	tdcall(&regs);
	*data_out = regs.r11;
	return regs.r10;
}

/*
 * Execute MMIO request instruction for write.
 */
static inline uint64_t tdvmcall_mmio_write(uint64_t address, uint64_t size, uint64_t data_in)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_INSTRUCTION_VE_REQUEST_MMIO;
	regs.r12 = size;
	regs.r13 = TDX_MMIO_WRITE;
	regs.r14 = address;
	regs.r15 = data_in;
	regs.rcx = 0xFC00;
	tdcall(&regs);
	return regs.r10;
}

/*
 * Execute CPUID instruction.
 */
static inline uint64_t tdvmcall_cpuid(uint32_t eax, uint32_t ecx,
				      uint32_t *ret_eax, uint32_t *ret_ebx,
				      uint32_t *ret_ecx, uint32_t *ret_edx)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_INSTRUCTION_CPUID;
	regs.r12 = eax;
	regs.r13 = ecx;
	regs.rcx = 0xFC00;
	tdcall(&regs);
	*ret_eax = regs.r12;
	*ret_ebx = regs.r13;
	*ret_ecx = regs.r14;
	*ret_edx = regs.r15;
	return regs.r10;
}

/*
 * Execute TDG.VP.INFO instruction.
 */
static inline uint64_t tdcall_vp_info(uint64_t *rcx, uint64_t *rdx,
				      uint64_t *r8, uint64_t *r9,
				      uint64_t *r10, uint64_t *r11)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.rax = TDX_TDCALL_INFO;
	tdcall(&regs);

	if (rcx)
		*rcx = regs.rcx;
	if (rdx)
		*rdx = regs.rdx;
	if (r8)
		*r8 = regs.r8;
	if (r9)
		*r9 = regs.r9;
	if (r10)
		*r10 = regs.r10;
	if (r11)
		*r11 = regs.r11;

	return regs.rax;
}

/*
 * Execute MapGPA instruction.
 */
static inline uint64_t tdvmcall_map_gpa(uint64_t address, uint64_t size,
					uint64_t *data_out)
{
	struct kvm_regs regs;

	memset(&regs, 0, sizeof(regs));
	regs.r11 = TDX_MAP_GPA;
	regs.r12 = address;
	regs.r13 = size;
	regs.rcx = 0x3C00;
	tdcall(&regs);
	*data_out = regs.r11;
	return regs.r10;
}

/*
 * Reports a 32 bit value from the guest to user space using a TDVM IO call.
 * Data is reported on port TDX_DATA_REPORT_PORT.
 */
static inline uint64_t tdvm_report_to_user_space(uint32_t data)
{
	// Need to upcast data to match tdvmcall_io signature.
	uint64_t data_64 = data;

	return tdvmcall_io(TDX_DATA_REPORT_PORT, /*size=*/4, TDX_IO_WRITE, &data_64);
}

/*
 * Reports a 64 bit value from the guest to user space using a TDVM IO call.
 * Data is reported on port TDX_DATA_REPORT_PORT.
 * Data is sent to host in 2 calls. LSB is sent (and needs to be read) first.
 */
static inline uint64_t tdvm_report_64bit_to_user_space(uint64_t data)
{
	uint64_t err;
	uint64_t data_lo = data & 0xFFFFFFFF;
	uint64_t data_hi = (data >> 32) & 0xFFFFFFFF;

	err = tdvmcall_io(TDX_DATA_REPORT_PORT, /*size=*/4, TDX_IO_WRITE,
			  &data_lo);
	if (err)
		return err;

	return tdvmcall_io(TDX_DATA_REPORT_PORT, /*size=*/4, TDX_IO_WRITE,
			   &data_hi);
}

#define TDX_FUNCTION_SIZE(name) ((uint64_t)&__stop_sec_ ## name -\
			   (uint64_t)&__start_sec_ ## name) \

#define TDX_GUEST_FUNCTION__(name, section_name) \
extern char *__start_sec_ ## name ; \
extern char *__stop_sec_ ## name ; \
static void \
__attribute__((__flatten__, section(section_name))) name(void *arg)


#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)
#define CONCAT2(a, b) a##b
#define CONCAT(a, b) CONCAT2(a, b)


#define TDX_GUEST_FUNCTION(name) \
TDX_GUEST_FUNCTION__(name, STRINGIFY(CONCAT(sec_, name)))

#endif  // KVM_LIB_TDX_H_
