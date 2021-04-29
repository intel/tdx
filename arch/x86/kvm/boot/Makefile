# SPDX-License-Identifier: GPL-2.0

asflags-y += -I$(srctree)/arch/x86/kvm
ccflags-y += -I$(srctree)/arch/x86/kvm

obj-$(CONFIG_KVM_INTEL_TDX) += seam/tdx_common.o seam/seamcall.o seam/seamloader.o \
				seam/seamldr.o seam/tdx.o
