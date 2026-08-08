// SPDX-License-Identifier: GPL-2.0-only
// page-fault address harvest via kprobes on do_page_fault + arm64_force_sig_fault.
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

#include <driver/types.h>
#include <driver/uapi.h>

#include "harvest.h"
#include "kallsym.h"
#include "log.h"

#ifndef KCFG_TARGET_PACKAGE
#  define KCFG_TARGET_PACKAGE "cent.tmgp.sgame"
#endif

/* ARM64 ESR_ELx data-fault status code mask: bits 0..11 of the ISS field cover
 * {FSC, WnR, S1PTW, CM} for data aborts. The composite value 0x1F4 unpacks to
 * CM | S1PTW | WnR | permission-style FSC subset — the harvest tag the
 * original .ko keys off. */
#define ESR_DFSC_MASK 0xFFFu
#define ESR_DFSC_HARVEST_VAL 0x1F4u

/* drv.wz_hero_addr_map / drv.wz_hero_objects are the single source of truth
 * shared with comm.c's DRV_CMD_GAME_ASSET_READ_A / _B / TEAR_DOWN consumers
 * — a file-static duplicate would silently desync from userspace. */
static inline struct wz_hero_slot *wz_slots(void) {
	return (struct wz_hero_slot *)drv.wz_hero_addr_map;
}

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

	/* task->comm replaces the vendor mm+0x830 deref from the IDA original —
	 * that offset is past the end of struct mm_struct on stock GKI and
	 * recursed via faults inside do_page_fault on every non-target process. */
	return strncmp(task->comm, KCFG_TARGET_PACKAGE, TASK_COMM_LEN) == 0;
}

/* do_mem_abort pre_handler.
 *
 * do_page_fault itself is annotated `static __kprobes` and therefore lies in
 * the .kprobes.text section that arch_within_kprobe_blacklist() rejects via
 * linker-baked bounds (kallsym_disable_kprobe_blacklist cannot reach that
 * check).  do_mem_abort is the only caller of do_page_fault on arm64 and
 * shares the exact same signature — kprobing it is equivalent for our
 * purposes and is allowed by the kprobes core.
 *
 * `regs` is the kprobe trap frame captured at the BRK in do_mem_abort's
 * prologue; X0..X2 still hold the probed function's three incoming args:
 *   regs->regs[0] = far  (unsigned long)
 *   regs->regs[1] = esr  (unsigned long)
 *   regs->regs[2] = inner pt_regs *  — the FAULTING TASK's user-space reg
 *                                       file. Harvest's X2/X8/X9 come from
 *                                       inner->regs[*]. */
int do_mem_abort_pre(struct kprobe *p, struct pt_regs *regs) {
	struct pt_regs *inner;
	unsigned long esr;
	u64 x2, x8, x9;

	(void)p;

	if (!harvest_match_current_pkg())
		return 0;

	esr = regs->regs[1];
	if ((esr & ESR_DFSC_MASK) != ESR_DFSC_HARVEST_VAL)
		return 0;

	inner = (struct pt_regs *)regs->regs[2];
	if (!inner)
		return 0;

	x2 = inner->regs[2];
	x8 = inner->regs[8];
	x9 = inner->regs[9];

	if (x8 == 0 || x2 == 0 || (u32)(x9 >> 32) == 0)
		return 0;

	wz_record(x9, x8, x2);
	return 0;
}
NOKPROBE_SYMBOL(do_mem_abort_pre);

/* Backup harvest entry: arm64_force_sig_fault fires on the SIGSEGV escalation
 * path. The user reg-file is not available from this kprobe's arg list, so we
 * only confirm the target gate; do_page_fault_pre captures the actual register
 * state upstream. */
int arm64_force_sig_fault_pre(struct kprobe *p, struct pt_regs *regs) {
	(void)p;
	(void)regs;
	(void)harvest_match_current_pkg();
	return 0;
}
NOKPROBE_SYMBOL(arm64_force_sig_fault_pre);

static struct kprobe do_mem_abort_kp = {
	.symbol_name = "do_mem_abort",
	.pre_handler = do_mem_abort_pre,
};
static bool do_mem_abort_kp_registered;

static struct kprobe arm64_force_sig_fault_kp = {
	.symbol_name = "arm64_force_sig_fault",
	.pre_handler = arm64_force_sig_fault_pre,
};
static bool arm64_force_sig_fault_kp_registered;

static int install_mem_abort_kprobe(void) {
	int ret;

	if (do_mem_abort_kp_registered)
		return 0;

	/* do_mem_abort is annotated NOKPROBE_SYMBOL on every supported KMI
	 * (its entry is added to kprobe_blacklist at boot).  Zero the list so
	 * within_kprobe_blacklist() returns false and register_kprobe doesn't
	 * silently bail with -EINVAL.  This is the same call the original .ko
	 * makes; on a kernel where do_mem_abort is NOT blacklisted it's a
	 * harmless no-op on the rest of the list. */
	(void)kallsym_disable_kprobe_blacklist();

	ret = register_kprobe(&do_mem_abort_kp);
	if (ret) {
		LOGE("register_kprobe(do_mem_abort) failed: %d\n", ret);
		return ret;
	}
	do_mem_abort_kp_registered = true;
	return 0;
}

static int install_force_sig_fault_kprobe(void) {
	int ret;

	if (arm64_force_sig_fault_kp_registered)
		return 0;

	ret = register_kprobe(&arm64_force_sig_fault_kp);
	if (ret) {
		LOGE("register_kprobe(arm64_force_sig_fault) failed: %d\n", ret);
		return ret;
	}
	arm64_force_sig_fault_kp_registered = true;
	return 0;
}

int install_harvest_hooks(void) {
	int rc;

	rc = install_mem_abort_kprobe();
	if (rc)
		return rc;
	return install_force_sig_fault_kprobe();
}

void uninstall_harvest_hooks(void) {
	if (arm64_force_sig_fault_kp_registered) {
		unregister_kprobe(&arm64_force_sig_fault_kp);
		arm64_force_sig_fault_kp_registered = false;
	}
	if (do_mem_abort_kp_registered) {
		unregister_kprobe(&do_mem_abort_kp);
		do_mem_abort_kp_registered = false;
	}
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
