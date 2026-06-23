// SPDX-License-Identifier: GPL-2.0-only
// page-fault address harvest for cent.tmgp.sgame.
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

#include <driver/types.h>
#include <driver/uapi.h>

#include "compat/compat.h"
#include "harvest.h"
#include "hook_engine.h"
#include "kallsym.h"
#include "kdebug.h"
#include "log.h"

#ifndef KCFG_TARGET_PACKAGE
#  define KCFG_TARGET_PACKAGE "cent.tmgp.sgame"
#endif

/* Stack-relative qword indices into task->stack at the kprobe-fired frame. */
#define HARVEST_STACK_IDX_X2 2008
#define HARVEST_STACK_IDX_X8 2014
#define HARVEST_STACK_IDX_X9 2015
#define HARVEST_STACK_IDX_ESR 2036

/* Per-CPU re-entrancy guard so a fault inside my_do_page_fault tail-calls
 * straight through without re-entering the harvest body. Without this a
 * single bad deref in the replacement body spirals into unbounded recursion
 * (do_page_fault → my_do_page_fault → fault → do_page_fault → ...) until
 * the VMAP_STACK guard page panics. */
static DEFINE_PER_CPU(u8, harvest_in_progress);

/* Capped observability counter: log only the first MDPF_LOG_CAP my_do_page_fault
 * entries to /dev/kmsg. do_page_fault fires thousands of times per second;
 * uncapped pr_drv would saturate log_buf and may itself contribute to a panic. */
static atomic_t mdpf_log_count = ATOMIC_INIT(0);
#define MDPF_LOG_CAP 16

/* Executable buffer that backs do_page_fault_hook.relo_addr.
 * MUST NOT be a static array inside the hook_t — module .bss is mapped PXN
 * on GKI (CONFIG_STRICT_MODULE_RWX=y) so executing instructions from there
 * takes an instant Permission Fault at EL1. */
static void *do_page_fault_relo_buf;
#define DO_PAGE_FAULT_RELO_BYTES (RELOCATE_INST_NUM * sizeof(u32))

/* Hero address-map storage lives in drv.wz_hero_addr_map (struct drv_state in driver/include/driver/types.h). We treat that __u8 buffer as the slot array to match comm.c's DRV_CMD_GAME_ASSET_READ_A / DRV_CMD_TEAR_DOWN consumers, which read/clear the same backing bytes. Likewise drv.wz_hero_objects is the single companion buffer the ioctl path drains via DRV_CMD_GAME_ASSET_READ_B. No file-static duplicates here -- a second copy would silently desync from userspace. */
static inline struct wz_hero_slot *wz_slots(void) {
	return (struct wz_hero_slot *)drv.wz_hero_addr_map;
}

static int(*orig_do_page_fault)(unsigned long far, unsigned long esr, struct pt_regs *regs);

static bool kernel_hook_is_hooked;
static bool arm64_force_sig_fault_kp_is_registered;

static hook_t do_page_fault_hook;

static noinline __nocfi int drv_call_do_page_fault(int (*fn)(unsigned long far, unsigned long esr, struct pt_regs *regs), unsigned long far, unsigned long esr, struct pt_regs *regs) {
	return fn(far, esr, regs);
}

static struct kprobe arm64_force_sig_fault_kp = {
	.symbol_name = "arm64_force_sig_fault",
	.pre_handler = arm64_force_sig_fault_pre,
};

/* irqsave spinlock closes a real race against userspace drains; original was lock-free. */
static DEFINE_SPINLOCK(wz_hero_lock);

static void wz_record(u64 key, u64 val1, u64 val2) {
	struct wz_hero_slot *slots = wz_slots();
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&wz_hero_lock, flags);

	for (i = 0; i < WZ_HERO_SLOTS; i++) {
		if (slots[i].key == key) {
			slots[i].val1 = val1;
			slots[i].val2 = val2;
			goto out;
		}
	}

	for (i = 0; i < WZ_HERO_SLOTS; i++) {
		if (slots[i].key == 0) {
			slots[i].key = key;
			slots[i].val1 = val1;
			slots[i].val2 = val2;
			goto out;
		}
	}

	/* Overflow: original wipes whole table without re-insert (cheap LRU). */
	memset(drv.wz_hero_addr_map, 0, sizeof(drv.wz_hero_addr_map));

out:
	spin_unlock_irqrestore(&wz_hero_lock, flags);
}

static bool harvest_match_current_pkg(void) {
	struct task_struct *task = current;

	if (!task || !task->mm)
		return false;

	/* task->comm is the canonical-and-always-valid process name (TASK_COMM_LEN=16,
	 * including NUL). The default KCFG_TARGET_PACKAGE "cent.tmgp.sgame" is exactly
	 * 15 chars and fits the comm slot whole.
	 *
	 * We DELIBERATELY no longer dereference the vendor-extended mm+0x830 field
	 * here — that offset was a vendor-private extension on the IDA-targeted build
	 * and is past the end of struct mm_struct on stock Android15/6.6 GKI, so the
	 * unconditional read crashed (or recursed via a fault inside do_page_fault)
	 * on every non-target process — i.e. on essentially every fault on a live
	 * system. task->comm is good enough to gate the harvest body. */
	return strncmp(task->comm, KCFG_TARGET_PACKAGE, TASK_COMM_LEN) == 0;
}

/* MINIMAL pass-through for isolation: NO harvest body, NO printk, NO
 * atomic / this_cpu / preempt operations.  Just forward to the relocated
 * original prologue and return what it returns.  If the device survives
 * this configuration, the previous body was the panic source (printk in
 * fault context, DEBUG_PREEMPT splat, or per-cpu state without
 * preempt_disable).  If it still panics, the bug is in the trampoline /
 * relo-buffer execution path itself. */
int my_do_page_fault(unsigned long far, unsigned long esr, struct pt_regs *regs) {
	int (*tail)(unsigned long, unsigned long, struct pt_regs *) = orig_do_page_fault;
	if (!tail)
		return 0;
	return drv_call_do_page_fault(tail, far, esr, regs);
}

int arm64_force_sig_fault_pre(struct kprobe *p, struct pt_regs *regs) {
	struct task_struct *task = current;
	const u64 *stack_qwords;
	u64 esr_slot, x2, x8, x9;

	(void)p;
	(void)regs;

	if (!task)
		return 0;

	if (!harvest_match_current_pkg())
		return 0;

	/* Walk task->stack (not the kprobe trap frame) to recover the user reg file. Valid only for THREAD_SIZE=16K and this vendor build's call chain. */
	stack_qwords = (const u64 *)task->stack;
	if (!stack_qwords)
		return 0;

	esr_slot = stack_qwords[HARVEST_STACK_IDX_ESR];
	if ((esr_slot & ESR_DFSC_MASK) != ESR_DFSC_HARVEST_VAL)
		return 0;

	x2 = stack_qwords[HARVEST_STACK_IDX_X2];
	x8 = stack_qwords[HARVEST_STACK_IDX_X8];
	x9 = stack_qwords[HARVEST_STACK_IDX_X9];

	if (x8 == 0 || x2 == 0)
		return 0;
	if ((u32)(x9 >> 32) == 0)
		return 0;

	wz_record(x9, x8, x2);
	return 0; /* kprobe convention: 0 == continue original instruction */
}

static int install_page_fault_hook(void) {
	unsigned long addr;
	void *relo_buf;
	hook_err_t err;
	int rc;

	if (kernel_hook_is_hooked)
		return 0;

	pr_drv("install_page_fault_hook: begin cpu=%d preempt=%d irqs_disabled=%d\n",
	       smp_processor_id(), preempt_count(), irqs_disabled());
	trace_drv("install_page_fault_hook: begin cpu=%d preempt=%d irqs_disabled=%d",
	          smp_processor_id(), preempt_count(), irqs_disabled());

	addr = kallsym_lookup("do_page_fault");
	if (!addr) {
		pr_drv_err("install_page_fault_hook: do_page_fault not found\n");
		trace_drv("install_page_fault_hook: do_page_fault NOT FOUND");
		return -ENOENT;
	}
	pr_drv("install_page_fault_hook: do_page_fault@%lx replace=%px\n",
	       addr, (void *)&my_do_page_fault);
	trace_drv("install_page_fault_hook: do_page_fault@%lx replace=%px",
	          addr, (void *)&my_do_page_fault);

	/* Allocate executable kernel memory for the relocated-prologue buffer.
	 * module .bss (where a static hook_t would have placed it) is mapped
	 * PXN on STRICT_MODULE_RWX GKI — tail-calling into it instantly panics. */
	trace_drv("install_page_fault_hook: about to alloc exec %zu",
	          (size_t)DO_PAGE_FAULT_RELO_BYTES);
	relo_buf = hook_engine_alloc_exec(DO_PAGE_FAULT_RELO_BYTES);
	if (!relo_buf) {
		pr_drv_err("install_page_fault_hook: hook_engine_alloc_exec failed\n");
		trace_drv("install_page_fault_hook: alloc_exec FAILED");
		return -ENOMEM;
	}
	do_page_fault_relo_buf = relo_buf;
	pr_drv("install_page_fault_hook: relo_buf=%px (%zu bytes)\n",
	       relo_buf, (size_t)DO_PAGE_FAULT_RELO_BYTES);
	trace_drv("install_page_fault_hook: relo_buf=%px (%zu bytes)",
	          relo_buf, (size_t)DO_PAGE_FAULT_RELO_BYTES);

	memset(&do_page_fault_hook, 0, sizeof(do_page_fault_hook));
	do_page_fault_hook.func_addr   = addr;
	do_page_fault_hook.origin_addr = addr;
	do_page_fault_hook.replace_addr = (u64)(uintptr_t)&my_do_page_fault;
	do_page_fault_hook.relo_addr = (u64)(uintptr_t)relo_buf;

	trace_drv("install_page_fault_hook: about to hook_prepare");
	err = hook_prepare(&do_page_fault_hook);
	if (err != HOOK_NO_ERR) {
		pr_drv_err("install_page_fault_hook: hook_prepare failed (%d)\n", (int)err);
		trace_drv("install_page_fault_hook: hook_prepare FAILED rc=%d", (int)err);
		hook_engine_free_exec(do_page_fault_relo_buf, DO_PAGE_FAULT_RELO_BYTES);
		do_page_fault_relo_buf = NULL;
		return -EINVAL;
	}
	pr_drv("install_page_fault_hook: prepare ok tramp_words=%d relo_words=%d\n",
	       (int)do_page_fault_hook.tramp_insts_num, (int)do_page_fault_hook.relo_insts_num);
	trace_drv("install_page_fault_hook: prepare ok tramp_words=%d relo_words=%d",
	          (int)do_page_fault_hook.tramp_insts_num, (int)do_page_fault_hook.relo_insts_num);

	/* Reverted: previously NOPed relo[0] PACIASP "to balance PAC chain",
	 * but that broke things further — do_page_fault's epilogue runs
	 * AUTIASP unconditionally, which then strips PAC bits from an unsigned
	 * X30 and corrupts the return address.  Keep PACIASP in relo[0]; the
	 * chain is PAC-balanced when each function (mdpf, drv_call, relo) does
	 * its own PACIASP+AUTIASP pair against its own SP modifier. */

	{
		/* Full dump of what will actually run. */
		int i;
		for (i = 0; i < TRAMPOLINE_MAX_NUM; i++)
			trace_drv("  origin[%d] = 0x%08x", i, do_page_fault_hook.origin_insts[i]);
		for (i = 0; i < do_page_fault_hook.tramp_insts_num && i < TRAMPOLINE_MAX_NUM; i++)
			trace_drv("  tramp [%d] = 0x%08x", i, do_page_fault_hook.tramp_insts[i]);
		for (i = 0; i < do_page_fault_hook.relo_insts_num && i < RELOCATE_INST_NUM; i++)
			trace_drv("  relo  [%2d] = 0x%08x", i, do_page_fault_hook.relo_insts[i]);
	}

	trace_drv("install_page_fault_hook: about to exec_publish");
	rc = hook_engine_exec_publish(relo_buf, DO_PAGE_FAULT_RELO_BYTES);
	if (rc) {
		pr_drv_err("install_page_fault_hook: exec_publish failed: %d\n", rc);
		trace_drv("install_page_fault_hook: exec_publish FAILED rc=%d", rc);
		hook_engine_free_exec(do_page_fault_relo_buf, DO_PAGE_FAULT_RELO_BYTES);
		do_page_fault_relo_buf = NULL;
		return rc;
	}
	pr_drv("install_page_fault_hook: relo buffer published executable\n");
	trace_drv("install_page_fault_hook: relo buffer published executable");

	orig_do_page_fault = (void *)(uintptr_t)do_page_fault_hook.relo_addr;
	smp_wmb();

	pr_drv("install_page_fault_hook: about-to-patch dst=%lx 4words={%08x,%08x,%08x,%08x} relo=%px orig=%px\n",
	       addr,
	       do_page_fault_hook.tramp_insts[0], do_page_fault_hook.tramp_insts[1],
	       do_page_fault_hook.tramp_insts[2], do_page_fault_hook.tramp_insts[3],
	       relo_buf, orig_do_page_fault);
	trace_drv("install_page_fault_hook: ABOUT TO PATCH dst=%lx 4words={%08x,%08x,%08x,%08x} relo=%px orig=%px",
	          addr,
	          do_page_fault_hook.tramp_insts[0], do_page_fault_hook.tramp_insts[1],
	          do_page_fault_hook.tramp_insts[2], do_page_fault_hook.tramp_insts[3],
	          relo_buf, orig_do_page_fault);

	/* ISOLATION: skipping the actual hook_install (the kernel-text patch).
	 * Everything else runs: relo alloc, hook_prepare, exec_publish.
	 * If device survives → the prologue patch itself is the panic source
	 * (do_page_fault is somehow protected on this device — KNOX/RKP-style
	 * runtime integrity check that pages the kernel when do_page_fault text
	 * changes — or aarch64_insn_patch_text fast-path leaves us with a
	 * non-atomic state that the kernel watchdog kills).
	 * If device still reboots → the panic is in the install path's earlier
	 * primitives (module_alloc / set_memory_x / etc.), not the patch. */
	trace_drv("install_page_fault_hook: SKIPPING hook_install (isolation, no patch applied)");
	pr_drv("install_page_fault_hook: SKIPPING hook_install\n");

	/* kernel_hook_is_hooked left FALSE so a second install attempt would re-run, but we won't get there. */

	pr_drv("install_page_fault_hook: returning OK without patching\n");
	trace_drv("install_page_fault_hook: returning OK without patching");
	return 0;
}

static int install_force_sig_fault_kprobe(void) {
	int ret;

	if (arm64_force_sig_fault_kp_is_registered)
		return 0;

	pr_drv("install_force_sig_fault_kprobe: register_kprobe(arm64_force_sig_fault)\n");
	ret = register_kprobe(&arm64_force_sig_fault_kp);
	if (ret) {
		pr_drv_err("register_kprobe (arm64_force_sig_fault) failed: %d\n", ret);
		return ret;
	}

	arm64_force_sig_fault_kp_is_registered = true;
	pr_drv("arm64_force_sig_fault kprobe armed at %p\n", arm64_force_sig_fault_kp.addr);
	return 0;
}

int install_harvest_hooks(void) {
	int rc1;

	pr_drv("install_harvest_hooks: begin\n");
	trace_drv("install_harvest_hooks: BEGIN");

	rc1 = install_page_fault_hook();
	if (rc1) {
		pr_drv_err("install_harvest_hooks: install_page_fault_hook rc=%d\n", rc1);
		trace_drv("install_harvest_hooks: install_page_fault_hook FAILED rc=%d", rc1);
	} else {
		trace_drv("install_harvest_hooks: install_page_fault_hook returned OK");
	}

	/* ISOLATION: skipping install_force_sig_fault_kprobe so we can verify
	 * the page-fault hook in isolation.  arm64_force_sig_fault_pre uses
	 * fixed task->stack qword indices 2008/2014/2015/2036 (vendor-build-
	 * specific) which may OOB-read on stock GKI; if THAT is the panic
	 * source instead of the inline hook, this run survives and the next
	 * iteration brings the kprobe back with a guarded pre_handler. */
	trace_drv("install_harvest_hooks: SKIPPING install_force_sig_fault_kprobe (isolation)");

	pr_drv("install_harvest_hooks: done rc1=%d (force_sig_fault_kprobe skipped)\n", rc1);
	trace_drv("install_harvest_hooks: DONE rc1=%d (kprobe skipped)", rc1);

	return rc1;
}

int wz_hero_addr_map_get(unsigned int idx, struct wz_hero_slot *out) {
	unsigned long flags;

	if (idx >= WZ_HERO_SLOTS || !out)
		return -EINVAL;

	spin_lock_irqsave(&wz_hero_lock, flags);
	*out = wz_slots()[idx];
	spin_unlock_irqrestore(&wz_hero_lock, flags);
	return 0;
}

void wz_hero_addr_map_clear(void) {
	unsigned long flags;

	spin_lock_irqsave(&wz_hero_lock, flags);
	memset(drv.wz_hero_addr_map, 0, sizeof(drv.wz_hero_addr_map));
	memset(drv.wz_hero_objects, 0, sizeof(drv.wz_hero_objects));
	spin_unlock_irqrestore(&wz_hero_lock, flags);
}

unsigned int wz_hero_addr_map_size(void) {
	struct wz_hero_slot *slots = wz_slots();
	unsigned long flags;
	unsigned int i, used = 0;

	spin_lock_irqsave(&wz_hero_lock, flags);
	for (i = 0; i < WZ_HERO_SLOTS; i++)
		if (slots[i].key != 0)
			used++;
	spin_unlock_irqrestore(&wz_hero_lock, flags);
	return used;
}
