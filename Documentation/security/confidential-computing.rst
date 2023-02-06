===============================
Confidential Computing in Linux
===============================

.. contents:: :local:

Overview
========

Confidential Computing (CC) refers to a set of HW and SW technologies that
allow Cloud Service Providers (CSPs) to provide stronger security guarantees
to their clients (usually referred as tenants) by excluding all the CSP's
infrastructure and SW out of tenant's Trusted Computing Base (TCB). While the
concrete implementation details differ between technologies, the common
guarantees that such mechanisms provide are confidentiality and integrity
of CC guest private memory and execution state (vcpu registers), more tightly
controlled guest interrupt injection, as well as some additional mechanisms
to control page mapping between GPAs and HPAs. More details on these
technologies can be found in Documentation/x86/tdx.rst and Documentation/x86/
amd-memory-encryption.rst.

Confidential Computing Threat model and security objectives
===========================================================

The Linux CC threat model assumes an untrusted host and a hypervisor with
abilities to perform attacks against a CC guest limited by the guarantees
provided by the CC technology solutions, i.e. private memory encryption and
integrity protection, protection of vcpu register state, etc. The **Linux
kernel CC security objectives** can be summarized as follows:

1. Prevent privileged escalation from a host (hypervisor) into a CC guest
   Linux kernel
2. Preserve the confidentiality and integrity of CC guest private memory

The above security objectives result in two primary **Linux kernel CC assets**:

1. guest kernel execution context
2. guest kernel private memory

The Denial of Service (DoS) attacks from the host (hypervisor) towards a CC
guest are explicitly out of scope because an untrusted host (hypervisor)
retains a full control of CC guest resources, and has an ability to deny
these resources at any time.

The **Linux CC attack surface** is any interface exposed from a CC guest Linux
kernel towards an untrusted host that is not covered by the CC technology
SW/HW protections. This includes any possible side-channels, as well as
transient execution side channels. Examples of explicit (not side-channel)
interfaces include accesses to port I/O, MMIO and DMA interfaces, access to
PCI configuration space, VMM-specific hypercalls, as well as CC technology
specific hypercalls. Additionally, it also includes all the data consumed
from untrusted host during the CC guest initialization, including the kernel
itself, its command line, provided ACPI tables, etc.

The range of mitigations to secure the above interfaces for Linux varies,
but can be roughly split it into the two groups:

1. **Attestation-based mechanisms.** It is possible to attest the input
provided by an untrusted host (hypervisor) to guarantee its expected
configuration and avoid an arbitrary potentially malicious input. This
can be applied to secure known configurations that are passed from a
hypervisor to the CC guest such as virtual FW and its configuration,
Linux kernel code itself, command line, ACPI tables, etc.

2. **Other mitigations.** For the runtime interactions that the attestation
cannot cover, a different range of mitigations needs to be applied. These
mitigations are described below in this document.


Linux kernel CC Mitigations
===========================

Device filter
-------------

As stated above, one of the primary security objective for confidential
computing is to protect the Linux CC guest kernel from hypervisor attacks
through exposed communication interfaces. The analysis of the kernel code
has shown that the biggest users of such interfaces are device drivers
(more than 95%), because every time a device driver performs a port IO/MMIO
read, or accesses a pci config space, there is a possibility for a malicious
hypervisor to inject a malformed value.

Fortunately, only a small subset of device drivers are required for a typical
CC Linux guest operation, so most of the attack surface can be disabled by
preventing these drivers from executing. Note that explicit disabling of
these drivers is required because the host (hypervisor) can always emulate a
device with incorrect PCI IDs and make the CC guest to load any arbitrary
driver of its choice.

Preventing the execution of arbitrary and non-required device drivers within
a Linux CC guest is the main goal of the *runtime device filter*. It allows
to define an allow or deny device list, and non-authorized devices are not
allowed to bind drivers. Note that the device driver initialization code is
still able to execute even if the device has not been authorized by the filter.

The concept of authorizing devices is not new in Linux. Bus drivers
like "USB" or "Thunderbolt" also have similar requirements and
implement a custom version of device authorization. However, for the Linux CC
guest there is a need to extend this concept towards all devices and
buses.

Considered alternatives
~~~~~~~~~~~~~~~~~~~~~~~

1. **Secure all Linux drivers.** A natural alternative to reducing the attack
surface is to ensure its security, but since Linux has enormous amount of
device drivers, this approach is unpractical.

2. **Minimal CC guest kernel configuration.** On a first thought the problem
of deactivating most of the kernel drivers can be adequately solved by
adjusting the CC guest kernel config to disable all non-required modules
or drivers. The advantages of this method would be using an existing
well-understood mechanism (kernel config), as well as preventing *any*
code from the disabled module/driver to execute in a runtime (including
initialization code). However, not all drivers can be disabled using this
method, namely the build-in platform drivers. Moreover, managing and
distributing a CC-specific kernel config is cumbersome and undesirable for
many Linux OS vendors who prefer to use their standard configs for most of
their usecases.

3. **modprobe allow/deny list.** This method also has the disadvantage of not
being able to deactivate the build-in modules and drivers and therefore
cannot be applied as a full solution. Additionally, it is even less effective
than a minimal CC kernel config approach, because it does depend on kernel
config's selections (build-in vs modular).

4. **Trusted execution environment (TEE) IO devices.** In the future Linux will
have support for adding physical devices to CC guests in a way that guarantees
an end-to-end secure channel between a physical device and a CC guest, as well
as ensures that an untrusted hypervisor cannot alter device's configuration.
This approach is an efficient and secure method to perform trusted I/O
transactions between a CC guest and devices, but it does not address the problem
of reducing an attack surface presented by existing Linux device drivers.
Moreover, virtual devices (such as virtio-based devices), commonly used for the
virtualization solutions nowadays, are not going to be covered by this mechanism.

5. **Fixed device tree configuration.** An alternative to runtime discovery of
devices in a CC guest, would be to define a fixed device tree-based configuration
of required devices that is passed to the CC guest kernel upon startup. While
security-wise it might be a good alternative, it goes against established
practices in cloud computing, as well as it would require major adjustments from
the OS vendors. Additionally, it won't co-exist with future trusted IO devices
that require runtime configuration and extensive usage of PCI(e) infrastructure.

Configuring device filter
~~~~~~~~~~~~~~~~~~~~~~~~~

An *authorized* device attribute (exposed via /sys/devices/.../authorized)
is used to update and check the authorization status
of a given device. Only authorized device is allowed to bind the driver.
If authorization status is updated, it will attempt to bind or
unbind the driver based on the authorization status. This is only
enabled for bus devices which are marked authorizable. Acceptable
values are,

===========  ===================================================
"on" or 1    device is authorized and allowed to bind the driver.
"off" or 0   device is not authorized and cannot bind driver.
===========  ===================================================

Currently this is supported on all devices expect for bus or
subsystem devices which opt out of it by marking it non
authorizable.

By default this attribute is initialized to "true" (allow all) to
avoid regressions. However, this is a bad default for CC guests, where
only a small set of allowed devices is required. For that reason a
command line option "dev.authorize.all" is added to allow CC guests
to change the default authorized status.

Finally, the device core "authorized" support has been extended to
allow the user to provide the platform specific allow/deny
list as a firmware blob. Details about the firmware blob can be
found in Documentation/driver-api/device-authorize.rst. The parsing
of the allowed list provided this way is done as part of arch initcall
in order to handle early device enumeration.




