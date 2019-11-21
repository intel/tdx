// SPDX-License-Identifier: GPL-2.0

static long tdvmcall_vendor(unsigned int fn, unsigned long r12,
			    unsigned long r13, unsigned long r14,
			    unsigned long r15)
{
	return __tdvmcall_vendor_kvm(fn, r12, r13, r14, r15, NULL);
}

/* Used by kvm_hypercall0() to trigger hypercall in TDX guest */
long tdx_kvm_hypercall0(unsigned int nr)
{
	return tdvmcall_vendor(nr, 0, 0, 0, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall0);

/* Used by kvm_hypercall1() to trigger hypercall in TDX guest */
long tdx_kvm_hypercall1(unsigned int nr, unsigned long p1)
{
	return tdvmcall_vendor(nr, p1, 0, 0, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall1);

/* Used by kvm_hypercall2() to trigger hypercall in TDX guest */
long tdx_kvm_hypercall2(unsigned int nr, unsigned long p1, unsigned long p2)
{
	return tdvmcall_vendor(nr, p1, p2, 0, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall2);

/* Used by kvm_hypercall3() to trigger hypercall in TDX guest */
long tdx_kvm_hypercall3(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3)
{
	return tdvmcall_vendor(nr, p1, p2, p3, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall3);

/* Used by kvm_hypercall4() to trigger hypercall in TDX guest */
long tdx_kvm_hypercall4(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3, unsigned long p4)
{
	return tdvmcall_vendor(nr, p1, p2, p3, p4);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall4);
