# SPDX-License-Identifier: GPL-2.0
include ../../../scripts/Makefile.include

all: attest

clean: attest_clean

install: attest_install

attest:
	$(call descend,attest)

attest_install:
	$(call descend,attest,install)

attest_clean:
	$(call descend,attest,clean)

.PHONY: all install clean attest latency_install latency_clean
