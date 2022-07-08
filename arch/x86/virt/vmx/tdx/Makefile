# SPDX-License-Identifier: GPL-2.0-only
CFLAGS_tdx.o += -Wframe-larger-than=4096
obj-y += tdx.o seamcall.o
obj-$(CONFIG_INTEL_TDX_HOST_DEBUG)	+= tdx_debug.o
obj-$(CONFIG_INTEL_TDX_MODULE_LOADER_OLD) += tdx_module_loader_old/
