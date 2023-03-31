# SPDX-License-Identifier: GPL-2.0

CFLAGS = $(KHDR_INCLUDES)
CFLAGS += -Wall -Wstrict-prototypes -Wuninitialized -std=gnu99

TEST_GEN_PROGS += restrictedmem_hugepage_test

include ../lib.mk

EXTRA_CLEAN = $(OUTPUT)/common.o

$(OUTPUT)/common.o: common.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c -ffreestanding $< -o $@

$(TEST_GEN_PROGS): $(OUTPUT)/common.o
