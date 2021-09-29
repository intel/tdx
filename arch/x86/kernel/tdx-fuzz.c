/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020, 2021 Intel Corporation */
/* Author: Andi Kleen */

/*
 * Fuzzer for TDCALLs/virtio to harden kernel against attacks from malicious
 * hypervisors.
 */
#include <linux/fault-inject.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/debugfs.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <asm/tdx.h>

static DEFINE_PER_CPU(struct rnd_state, fuzz_rndstate);
static DECLARE_FAULT_ATTR(tdx_fault);
static bool fuzz_tdcall;
static bool fuzz_errors;
static u16 fuzz_num_bits = 2;
static bool fuzz_early_seed;

static u64 __tdx_fuzz(u64 var, int bits, enum tdx_fuzz_loc loc)
{
	struct rnd_state *rndstate;
	unsigned num_bits;
	u64 oldvar = var;

	get_cpu();
	rndstate = this_cpu_ptr(&fuzz_rndstate);
	num_bits = READ_ONCE(fuzz_num_bits);
	if (num_bits >= 64) {
		prandom_bytes_state(rndstate, &var, sizeof(long));
	} else {
		int i;
		char rnd[64];
		prandom_bytes_state(rndstate, rnd, num_bits);
		for (i = 0; i < num_bits; i++)
			var ^= 1ULL << (rnd[i] & (bits-1));
	}
	put_cpu();
	return var;
}

u64 tdx_fuzz(u64 var, enum tdx_fuzz_loc loc)
{
	if (!fuzz_tdcall || !should_fail(&tdx_fault, 1))
		return var;

	return __tdx_fuzz(var, BITS_PER_LONG, loc);
}

bool tdx_fuzz_err(enum tdx_fuzz_loc loc)
{
	if (!fuzz_errors || !should_fail(&tdx_fault, 1))
		return false;

	return true;
}

static void fuzz_init_seed(unsigned long seed)
{
	int cpu;
	pr_info("tdxfuzz: setting seed to %lu\n", seed);
	for_each_possible_cpu (cpu)
		prandom_seed_state(&per_cpu(fuzz_rndstate, cpu), seed + cpu);
}

static int fuzz_seed_set(void *data, u64 val)
{
	fuzz_init_seed(val);
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(fuzz_seed_fops, NULL, fuzz_seed_set, "%llu\n");

static int __init tdx_fuzz_setup(char *str)
{
	unsigned long seed;
	unsigned off;

	if (sscanf(str, "seed:%lu%n", &seed, &off) == 1) {
		fuzz_init_seed(seed);
		fuzz_early_seed = true;
		str += off;
		if (*str == ',')
			str++;
	}
	if (sscanf(str, "tdcall%n", &off) == 1) {
		fuzz_tdcall = true;
		str += off;
		if (*str == ',')
			str++;
	}
	if (sscanf(str, "tderrors%n", &off) == 1) {
		fuzz_errors = true;
		str += off;
		if (*str == ',')
			str++;
	}
	if (sscanf(str, "numbits:%hu", &fuzz_num_bits) == 1) {
		str += off;
		if (*str == ',')
			str++;
	}
	return setup_fault_attr(&tdx_fault, str);
}
early_param("fail_tdx", tdx_fuzz_setup);

static int __init tdx_fuzz_init(void)
{
	struct dentry *dbp;

	dbp = fault_create_debugfs_attr("fail_tdx", NULL, &tdx_fault);
	if (!dbp)
		return PTR_ERR(dbp);

	/* Don't allow verbose because printk can trigger another tdcall */
	tdx_fault.verbose = 0;
	debugfs_remove(debugfs_lookup("verbose", dbp));

	debugfs_create_bool("tdcall", 0600, dbp, &fuzz_tdcall);
	debugfs_create_bool("tderrors", 0600, dbp, &fuzz_errors);
	debugfs_create_u16("num_change_bits", 0600, dbp, &fuzz_num_bits);
	debugfs_create_file("seed", 0200, dbp, NULL, &fuzz_seed_fops);

	if (!fuzz_early_seed)
		fuzz_init_seed(get_random_u64());
	return 0;
}

__initcall(tdx_fuzz_init)
