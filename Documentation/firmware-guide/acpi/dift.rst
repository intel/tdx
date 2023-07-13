.. SPDX-License-Identifier: GPL-2.0

=============================
Device ID Filter Table (DIFT)
=============================

The goal of the DIFT is to reduce the kernel attack surface. It provides a way
to identify the devices at boot time so that device enumeration can be filtered
early.

DIFT supports only PCI devices.

The DIFT consists of the ACPI Table Header followed by::

	UINT32		reserved	// Must be zero

Followed by zero or more::

	UINT8		type      	// Subtable type
	UINT8		length		// Subtable length
	UINT16		reserved	// Must be zero
	UINT32		segment_group	// Segment Group Number
	UINT16		bus		// Bus Number
	UINT8		slot		// Device Number
	UINT8		function	// Function Number
	UINT16		vendor		// Vendor ID
	UINT16		device		// Device ID
	UINT16		subvendor	// Subsystem Vendor ID
	UINT16		subdevice	// Subsystem Device ID
	UINT32		class_code	// Class Code
	UINT32		class_mask	// Mask which bytes, if any, of the Class Code to match

Subtable types::

	ACPI_DIFT_TYPE_PCI     0

Example::

             Signature : "DIFT"    [Device ID Filter table]
          Table Length : 00000000
              Revision : 01
              Checksum : 00
                Oem ID : "OEM"
          Oem Table ID : "OEMTABLE"
          Oem Revision : 00000001
       Asl Compiler ID : ""
 Asl Compiler Revision : 00000000

                UINT32 : 00000000	// reserved

                 Label : StartRecord00
                UINT8  : 00		// Subtable type
                UINT8  : $EndRecord00 - $StartRecord00 // Subtable length
                UINT16 : 0000		// reserved
                UINT32 : 0xFFFFFFFF	// Segment Group Number
                UINT16 : 0xFFFF		// Bus Number
                UINT8  : 0xFF		// Device Number
                UINT8  : 0xFF		// Function Number
                UINT16 : 0x1AF4		// Vendor ID
                UINT16 : 0x1000		// Device ID - transitional virtio net
                UINT16 : 0xFFFF		// Subsystem Vendor ID
                UINT16 : 0xFFFF		// Subsystem Device ID
                UINT32 : 00000000	// Class Code
                UINT32 : 00000000	// Class Code Mask
                Label  : EndRecord00

                 Label : StartRecord01
                UINT8  : 00		// Subtable type
                UINT8  : $EndRecord01 - $StartRecord01 // Subtable length
                UINT16 : 0000		// reserved
                UINT32 : 0xFFFFFFFF	// Segment Group Number
                UINT16 : 0xFFFF		// Bus Number
                UINT8  : 0xFF		// Device Number
                UINT8  : 0xFF		// Function Number
                UINT16 : 0x1AF4		// Vendor ID
                UINT16 : 0x1001		// Device ID - transitional virtio block
                UINT16 : 0xFFFF		// Subsystem Vendor ID
                UINT16 : 0xFFFF		// Subsystem Device ID
                UINT32 : 00000000	// Class Code
                UINT32 : 00000000	// Class Code Mask
                Label  : EndRecord01

                 Label : StartRecord02
                UINT8  : 00		// Subtable type
                UINT8  : $EndRecord02 - $StartRecord02 // Subtable length
                UINT16 : 0000		// reserved
                UINT32 : 0xFFFFFFFF	// Segment Group Number
                UINT16 : 0xFFFF		// Bus Number
                UINT8  : 0xFF		// Device Number
                UINT8  : 0xFF		// Function Number
                UINT16 : 0x1AF4		// Vendor ID
                UINT16 : 0x1003		// Device ID - transitional virtio console
                UINT16 : 0xFFFF		// Subsystem Vendor ID
                UINT16 : 0xFFFF		// Subsystem Device ID
                UINT32 : 00000000	// Class Code
                UINT32 : 00000000	// Class Code Mask
                Label  : EndRecord02

                 Label : StartRecord03
                UINT8  : 00		// Subtable type
                UINT8  : $EndRecord03 - $StartRecord03 // Subtable length
                UINT16 : 0000		// reserved
                UINT32 : 0xFFFFFFFF	// Segment Group Number
                UINT16 : 0xFFFF		// Bus Number
                UINT8  : 0xFF		// Device Number
                UINT8  : 0xFF		// Function Number
                UINT16 : 0x1AF4		// Vendor ID
                UINT16 : 0x1009		// Device ID - transitional virtio 9p console
                UINT16 : 0xFFFF		// Subsystem Vendor ID
                UINT16 : 0xFFFF		// Subsystem Device ID
                UINT32 : 00000000	// Class Code
                UINT32 : 00000000	// Class Code Mask
                Label  : EndRecord03

                 Label : StartRecord04
                UINT8  : 00		// Subtable type
                UINT8  : $EndRecord04 - $StartRecord04 // Subtable length
                UINT16 : 0000		// reserved
                UINT32 : 0xFFFFFFFF	// Segment Group Number
                UINT16 : 0xFFFF		// Bus Number
                UINT8  : 0xFF		// Device Number
                UINT8  : 0xFF		// Function Number
                UINT16 : 0x1AF4		// Vendor ID
                UINT16 : 0x1041		// Device ID - transitional virtio net
                UINT16 : 0xFFFF		// Subsystem Vendor ID
                UINT16 : 0xFFFF		// Subsystem Device ID
                UINT32 : 00000000	// Class Code
                UINT32 : 00000000	// Class Code Mask
                Label  : EndRecord04

                 Label : StartRecord05
                UINT8  : 00		// Subtable type
                UINT8  : $EndRecord05 - $StartRecord05 // Subtable length
                UINT16 : 0000		// reserved
                UINT32 : 0xFFFFFFFF	// Segment Group Number
                UINT16 : 0xFFFF		// Bus Number
                UINT8  : 0xFF		// Device Number
                UINT8  : 0xFF		// Function Number
                UINT16 : 0x1AF4		// Vendor ID
                UINT16 : 0x1042		// Device ID - transitional virtio block
                UINT16 : 0xFFFF		// Subsystem Vendor ID
                UINT16 : 0xFFFF		// Subsystem Device ID
                UINT32 : 00000000	// Class Code
                UINT32 : 00000000	// Class Code Mask
                Label  : EndRecord05

                 Label : StartRecord06
                UINT8  : 00		// Subtable type
                UINT8  : $EndRecord06 - $StartRecord06 // Subtable length
                UINT16 : 0000		// reserved
                UINT32 : 0xFFFFFFFF	// Segment Group Number
                UINT16 : 0xFFFF		// Bus Number
                UINT8  : 0xFF		// Device Number
                UINT8  : 0xFF		// Function Number
                UINT16 : 0x1AF4		// Vendor ID
                UINT16 : 0x1043		// Device ID - transitional virtio console
                UINT16 : 0xFFFF		// Subsystem Vendor ID
                UINT16 : 0xFFFF		// Subsystem Device ID
                UINT32 : 00000000	// Class Code
                UINT32 : 00000000	// Class Code Mask
                Label  : EndRecord06

                 Label : StartRecord07
                UINT8  : 00		// Subtable type
                UINT8  : $EndRecord07 - $StartRecord07 // Subtable length
                UINT16 : 0000		// reserved
                UINT32 : 0xFFFFFFFF	// Segment Group Number
                UINT16 : 0xFFFF		// Bus Number
                UINT8  : 0xFF		// Device Number
                UINT8  : 0xFF		// Function Number
                UINT16 : 0x1AF4		// Vendor ID
                UINT16 : 0x1049		// Device ID - transitional virtio 9p console
                UINT16 : 0xFFFF		// Subsystem Vendor ID
                UINT16 : 0xFFFF		// Subsystem Device ID
                UINT32 : 00000000	// Class Code
                UINT32 : 00000000	// Class Code Mask
                Label  : EndRecord07

                 Label : StartRecord08
                UINT8  : 00		// Subtable type
                UINT8  : $EndRecord08 - $StartRecord08 // Subtable length
                UINT16 : 0000		// reserved
                UINT32 : 0xFFFFFFFF	// Segment Group Number
                UINT16 : 0xFFFF		// Bus Number
                UINT8  : 0xFF		// Device Number
                UINT8  : 0xFF		// Function Number
                UINT16 : 0x1AF4		// Vendor ID
                UINT16 : 0x1053		// Device ID - transitional virtio vsock transport
                UINT16 : 0xFFFF		// Subsystem Vendor ID
                UINT16 : 0xFFFF		// Subsystem Device ID
                UINT32 : 00000000	// Class Code
                UINT32 : 00000000	// Class Code Mask
                Label  : EndRecord08
