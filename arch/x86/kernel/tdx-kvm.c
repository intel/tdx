// SPDX-License-Identifier: GPL-2.0-or-later

static long tdvmcall_vendor(unsigned int fn, unsigned long r12,
			    unsigned long r13, unsigned long r14,
			    unsigned long r15)
{
	return __tdvmcall_vendor_kvm(fn, r12, r13, r14, r15, NULL);
}

long tdx_kvm_hypercall0(unsigned int nr)
{
	return tdvmcall_vendor(nr, 0, 0, 0, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall0);

long tdx_kvm_hypercall1(unsigned int nr, unsigned long p1)
{
	return tdvmcall_vendor(nr, p1, 0, 0, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall1);

long tdx_kvm_hypercall2(unsigned int nr, unsigned long p1, unsigned long p2)
{
	return tdvmcall_vendor(nr, p1, p2, 0, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall2);

long tdx_kvm_hypercall3(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3)
{
	return tdvmcall_vendor(nr, p1, p2, p3, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall3);

long tdx_kvm_hypercall4(unsigned int nr, unsigned long p1, unsigned long p2,
		unsigned long p3, unsigned long p4)
{
	return tdvmcall_vendor(nr, p1, p2, p3, p4);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall4);
