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
#include <linux/kfifo.h>
#include <linux/slab.h>
#include <asm/tdx.h>
#include <asm/trace/tdx.h>

static DEFINE_PER_CPU(struct rnd_state, fuzz_rndstate);
static DECLARE_FAULT_ATTR(tdx_fault);
static bool fuzz_tdcall;
static bool fuzz_errors;
static u16 fuzz_num_bits = 2;
static bool fuzz_early_seed;
static bool fallback_enabled = true;
static unsigned long inject_active;

#define FUZZ_FIFO_LEN 4096
#define FALLBACK_FIFO_LEN 256
#define FALLBACK_FIFO_USED 199

/*
 * This all is not very cache line friendly.
 * Assume fuzzed TDX guests don't have many vcpus for now.
 *
 * Maintain a fallback fifo to loop existing data in case
 * the input doesn't feed enough.
 */
struct fuzz_fifo {
	DECLARE_KFIFO(inject, u64, FUZZ_FIFO_LEN);
	DECLARE_KFIFO(fallback, u64, FALLBACK_FIFO_LEN);
};
static struct fuzz_fifo *inject_fifo;
/* protect fifos for multiple readers and most stats */
static DEFINE_SPINLOCK(inject_lock);
/* Statistics */
static u64 inject_success;
static u64 inject_fallback;
static u64 inject_miss_no_fallback  = ATOMIC_INIT(0);
static atomic_t inject_nmi_conflict;

static bool get_inject_val(enum tdx_fuzz_loc loc, u64 *valp)
{
	struct fuzz_fifo *f = &inject_fifo[loc];

	if (kfifo_out(&f->inject, valp, 1) != 1) {
		if (!fallback_enabled)
			return false;
		if (!kfifo_out(&f->fallback, valp, 1)) {
			inject_miss_no_fallback++;
			return false;
		}
		inject_fallback++;
	} else {
		inject_success++;
		if (kfifo_size(&f->fallback) == FALLBACK_FIFO_USED)
			kfifo_skip(&f->fallback);
	}
	kfifo_in(&f->fallback, valp, 1);
	return true;
}

static bool fuzz_inject(enum tdx_fuzz_loc loc, u64 *valp)
{
	bool ok;

	if (in_nmi()) {
		if (!spin_trylock(&inject_lock)) {
			atomic_inc(&inject_nmi_conflict);
			return false;
		}
		ok = get_inject_val(loc, valp);
		spin_unlock(&inject_lock);
	} else {
		unsigned long flags;
		spin_lock_irqsave(&inject_lock, flags);
		ok = get_inject_val(loc, valp);
		spin_unlock_irqrestore(&inject_lock, flags);
	}
	return ok;
}

static u64 __tdx_fuzz(u64 var, int bits, enum tdx_fuzz_loc loc)
{
	struct rnd_state *rndstate;
	unsigned num_bits;
	u64 oldvar = var;

	if (READ_ONCE(inject_active)) {
		u64 newvar;
		if (fuzz_inject(loc, &newvar)) {
			var = newvar;
			trace_tdx_fuzz((u64)__builtin_return_address(0),
				       bits, oldvar, newvar, loc);
		}
		return var;
	}

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
	trace_tdx_fuzz((u64)__builtin_return_address(0), bits, oldvar, var, loc);
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

	if (READ_ONCE(inject_active)) {
		u64 res = 0;
		return fuzz_inject(loc, &res);
	}

	trace_tdx_fuzz((u64)__builtin_return_address(0), 1, 0, 1, loc);
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

/*
 * Injection allows a feedbacker fuzzer to provide values.
 */

static int inject_open(struct inode *inode, struct file *file)
{
	if (test_and_set_bit(0, &inject_active))
		return -EBUSY;
	if (inject_fifo == NULL) {
		struct fuzz_fifo *infifo;
		int i;

		infifo = kvmalloc(TDX_FUZZ_MAX * sizeof(struct fuzz_fifo),
				  GFP_KERNEL);
		if (!infifo) {
			clear_bit(0, &inject_active);
			return -ENOMEM;
		}
		for (i = 0; i < TDX_FUZZ_MAX; i++) {
			INIT_KFIFO(infifo[i].inject);
			INIT_KFIFO(infifo[i].fallback);
		}
		WRITE_ONCE(inject_fifo, infifo);
	}
	return 0;
}

static int inject_release(struct inode *inode, struct file *file)
{
	clear_bit(0, &inject_active);
	/* Never free the fifos */
	return 0;
}

static ssize_t inject_write(struct file *f, const char __user *buf,
			    size_t len, loff_t *off)
{
	int num, i;
	unsigned copied;

	if (len % 16)
		return -EINVAL;
	num = len / 16;
	for (i = 0; i < num; i++) {
		u64 loc;
		if (get_user(loc, buf))
			return -EFAULT;
		if (loc >= TDX_FUZZ_MAX)
			return -EINVAL;
		buf += 8;
		if (kfifo_from_user(&inject_fifo[loc].inject, buf, 8, &copied))
			return -EFAULT;
		if (copied != 8)
			return i*16;
		buf += 8;
	}
	return len;
}

static struct file_operations inject_fops = {
	.owner	 = THIS_MODULE,
	.open	 = inject_open,
	.release = inject_release,
	.write	 = inject_write,
	.llseek  = no_llseek,
};

static int __init tdx_fuzz_init(void)
{
	struct dentry *dbp, *statp;

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

	debugfs_create_bool("fallback", 0600, dbp, &fallback_enabled);
	debugfs_create_file("inject", 0600, dbp, NULL, &inject_fops);
	statp = debugfs_create_dir("stats", dbp);
	debugfs_create_u64("inject_success", 0600, statp, &inject_success);
	debugfs_create_u64("inject_fallback", 0600, statp, &inject_fallback);
	debugfs_create_u64("inject_miss_no_fallback", 0600, statp,
			      &inject_miss_no_fallback);
	debugfs_create_atomic_t("inject_nmi_conflict", 0600, statp,
			      &inject_nmi_conflict);

	if (!fuzz_early_seed)
		fuzz_init_seed(get_random_u64());
	return 0;
}

__initcall(tdx_fuzz_init)
