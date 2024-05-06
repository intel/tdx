// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test configure of APIC bus frequency.
 *
 * Copyright (c) 2024 Intel Corporation
 *
 * To verify if the APIC bus frequency can be configured this, test starts
 * by setting the TSC frequency in KVM, and then:
 * For every APIC timer frequency supported:
 * * In the guest:
 * * * Start the APIC timer by programming the APIC TMICT (initial count
 *       register) to the largest value possible to guarantee that it will
 *       not expire during the test,
 * * * Wait for a known duration based on previously set TSC frequency,
 * * * Stop the timer and read the APIC TMCCT (current count) register to
 *       determine the count at that time (TMCCT is loaded from TMICT when
 *       TMICT is programmed and then starts counting down).
 * * In the host:
 * * * Determine if the APIC counts close to configured APIC bus frequency
 *     while taking into account how the APIC timer frequency was modified
 *     using the APIC TDCR (divide configuration register).
 */
#define _GNU_SOURCE /* for program_invocation_short_name */

#include "apic.h"
#include "test_util.h"

/*
 * Pick one convenient value, 1.5GHz. No special meaning and different from
 * the default value, 1GHz.
 */
#define TSC_HZ			(1500 * 1000 * 1000ULL)

/* Wait for 100 msec, not too long, not too short value. */
#define LOOP_MSEC		100ULL
#define TSC_WAIT_DELTA		(TSC_HZ / 1000 * LOOP_MSEC)

/*
 * Pick a typical value, 25MHz. Different enough from the default value, 1GHz.
 */
#define APIC_BUS_CLOCK_FREQ	(25 * 1000 * 1000ULL)

static void guest_code(void)
{
	/*
	 * Possible TDCR values and its divide count. Used to modify APIC
	 * timer frequency.
	 */
	struct {
		u32 tdcr;
		u32 divide_count;
	} tdcrs[] = {
		{0x0, 2},
		{0x1, 4},
		{0x2, 8},
		{0x3, 16},
		{0x8, 32},
		{0x9, 64},
		{0xa, 128},
		{0xb, 1},
	};

	u32 tmict, tmcct;
	u64 tsc0, tsc1;
	int i;

	asm volatile("cli");

	xapic_enable();

	/*
	 * Setup one-shot timer.  The vector does not matter because the
	 * interrupt does not fire.
	 */
	xapic_write_reg(APIC_LVT0, APIC_LVT_TIMER_ONESHOT);

	for (i = 0; i < ARRAY_SIZE(tdcrs); i++) {
		xapic_write_reg(APIC_TDCR, tdcrs[i].tdcr);

		/* Set the largest value to not trigger the interrupt. */
		tmict = ~0;
		xapic_write_reg(APIC_TMICT, tmict);

		/* Busy wait for LOOP_MSEC */
		tsc0 = rdtsc();
		tsc1 = tsc0;
		while (tsc1 - tsc0 < TSC_WAIT_DELTA)
			tsc1 = rdtsc();

		/* Read APIC timer and TSC */
		tmcct = xapic_read_reg(APIC_TMCCT);
		tsc1 = rdtsc();

		/* Stop timer */
		xapic_write_reg(APIC_TMICT, 0);

		/* Report it. */
		GUEST_SYNC_ARGS(tdcrs[i].divide_count, tmict - tmcct,
				tsc1 - tsc0, 0, 0);
	}

	GUEST_DONE();
}

void test_apic_bus_clock(struct kvm_vcpu *vcpu)
{
	bool done = false;
	struct ucall uc;

	while (!done) {
		vcpu_run(vcpu);
		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_DONE:
			done = true;
			break;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			break;
		case UCALL_SYNC: {
			u32 divide_counter = uc.args[1];
			u32 apic_cycles = uc.args[2];
			u64 tsc_cycles = uc.args[3];
			u64 freq;

			TEST_ASSERT(tsc_cycles > 0,
				    "TSC cycles must not be zero.");

			/* Allow 1% slack. */
			freq = apic_cycles * divide_counter * TSC_HZ / tsc_cycles;
			TEST_ASSERT(freq < APIC_BUS_CLOCK_FREQ * 101 / 100,
				    "APIC bus clock frequency is too large");
			TEST_ASSERT(freq > APIC_BUS_CLOCK_FREQ * 99 / 100,
				    "APIC bus clock frequency is too small");
			break;
		}
		default:
			TEST_FAIL("Unknown ucall %lu", uc.cmd);
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_X86_APIC_BUS_CYCLES_NS));

	vm = vm_create(1);
	vm_ioctl(vm, KVM_SET_TSC_KHZ, (void *)(TSC_HZ / 1000));
	/*
	 * KVM_CAP_X86_APIC_BUS_CYCLES_NS expects APIC bus clock rate in
	 * nanoseconds and requires that no vCPU is created.
	 */
	vm_enable_cap(vm, KVM_CAP_X86_APIC_BUS_CYCLES_NS,
		      NSEC_PER_SEC / APIC_BUS_CLOCK_FREQ);
	vcpu = vm_vcpu_add(vm, 0, guest_code);

	virt_pg_map(vm, APIC_DEFAULT_GPA, APIC_DEFAULT_GPA);

	test_apic_bus_clock(vcpu);
	kvm_vm_free(vm);
}
