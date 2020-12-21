==========
TDX MODULE
==========

Integrating TDX MODULE into initrd
==================================
If TDX is enabled in KVM(CONFIG_KVM_INTEL_TDX=y), kernel is able to load
tdx seam module from initrd.
The related modules (seamldr.ac, libtdx.so and libtdx.so.sigstruct) need to be
stored in initrd.

tdx-seam is a sample hook script for initramfs-tools.
TDXSEAM_SRCDIR are the directory in the host file system to store files related
to TDX MODULE.

Since it heavily depends on distro how to prepare initrd, here's a example how
to prepare an initrd.
(Actually this is taken from Documentation/x86/microcode.rst)
::
  #!/bin/bash

  if [ -z "$1" ]; then
      echo "You need to supply an initrd file"
      exit 1
  fi

  INITRD="$1"

  DSTDIR=lib/firmware/intel-seam
  TMPDIR=/tmp/initrd
  LIBTDX="/lib/firmware/intel-seam/seamldr.acm /lib/firmware/intel-seam/libtdx.so /lib/firmware/intel-seam/libtdx.so.sigstruct"

  rm -rf $TMPDIR

  mkdir $TMPDIR
  cd $TMPDIR
  mkdir -p $DSTDIR

  cp ${LIBTDX} ${DSTDIR}

  find . | cpio -o -H newc > ../tdx-seam.cpio
  cd ..
  mv $INITRD $INITRD.orig
  cat tdx-seam.cpio $INITRD.orig > $INITRD

  rm -rf $TMPDIR
