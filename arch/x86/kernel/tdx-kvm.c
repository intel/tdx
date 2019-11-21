// SPDX-License-Identifier: GPL-2.0-or-later

long tdx_kvm_hypercall0(unsigned int nr)
{
	register long r10 asm("r10") = TDVMCALL_VENDOR_KVM;
	register long r11 asm("r11") = nr;
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10 and R11 down to the VMM */
	rcx = BIT(10) | BIT(11);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11)
			: "memory");

	BUG_ON(ret);
	return r10;
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall0);

long tdx_kvm_hypercall1(unsigned int nr, unsigned long p1)
{
	register long r10 asm("r10") = TDVMCALL_VENDOR_KVM;
	register long r11 asm("r11") = nr;
	register long r12 asm("r12") = p1;
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10, R11 and R12 down to the VMM */
	rcx = BIT(10) | BIT(11) | BIT(12);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11), "r"(r12)
			: "memory");

	BUG_ON(ret);
	return r10;
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall1);

long tdx_kvm_hypercall2(unsigned int nr, unsigned long p1, unsigned long p2)
{
	register long r10 asm("r10") = TDVMCALL_VENDOR_KVM;
	register long r11 asm("r11") = nr;
	register long r12 asm("r12") = p1;
	register long r13 asm("r13") = p2;
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10, R11, R12 and R13 down to the VMM */
	rcx = BIT(10) | BIT(11) | BIT(12) | BIT(13);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11), "r"(r12),
			  "r"(r13)
			: "memory");

	BUG_ON(ret);
	return r10;
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall2);

long tdx_kvm_hypercall3(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3)
{
	register long r10 asm("r10") = TDVMCALL_VENDOR_KVM;
	register long r11 asm("r11") = nr;
	register long r12 asm("r12") = p1;
	register long r13 asm("r13") = p2;
	register long r14 asm("r14") = p3;
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10, R11, R12, R13 and R14 down to the VMM */
	rcx = BIT(10) | BIT(11) | BIT(12) | BIT(13) | BIT(14);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11), "r"(r12),
			  "r"(r13), "r"(r14)
			: "memory");

	BUG_ON(ret);
	return r10;
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall3);

long tdx_kvm_hypercall4(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3, unsigned long p4)
{
	register long r10 asm("r10") = TDVMCALL_VENDOR_KVM;
	register long r11 asm("r11") = nr;
	register long r12 asm("r12") = p1;
	register long r13 asm("r13") = p2;
	register long r14 asm("r14") = p3;
	register long r15 asm("r15") = p4;
	register long rcx asm("rcx");
	long ret;

	/* Allow to pass R10, R11, R12, R13, R14 and R15 down to the VMM */
	rcx = BIT(10) | BIT(11) | BIT(12) | BIT(13) | BIT(14) | BIT(15);

	asm volatile(TDCALL
			: "=a"(ret), "=r"(r10)
			: "a"(TDVMCALL), "r"(rcx), "r"(r10), "r"(r11), "r"(r12),
			  "r"(r13), "r"(r14), "r"(r15)
			: "memory");

	BUG_ON(ret);
	return r10;
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall4);
