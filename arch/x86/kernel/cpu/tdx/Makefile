# SPDX-License-Identifier: GPL-2.0
# Makefile for seamldr and tdx module

obj-y	+= np-seamldr.o seam.o seamcall.o p-seamldr.o
obj-y	+= tdx.o tdx-error.o tdmr-common.o tdmr-sysmem.o
obj-$(CONFIG_ENABLE_TDX_FOR_X86_PMEM_LEGACY)	+= tdmr-legacy-pmem.o
obj-y	+= tdx-tdmr.o
