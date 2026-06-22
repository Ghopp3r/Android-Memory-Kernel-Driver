// SPDX-License-Identifier: GPL-2.0-only
// page-fault address harvest for cent.tmgp.sgame.
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

#include <driver/types.h>
#include <driver/uapi.h>

#include "compat/compat.h"
#include "harvest.h"
#include "hook_engine.h"
#include "kallsym.h"
#include "log.h"

#ifndef KCFG_TARGET_PACKAGE
#  define KCFG_TARGET_PACKAGE "cent.tmgp.sgame"
#endif

/* Vendor-extended mm_struct on this Android15/6.6 GKI build embeds a NUL-terminated package-name char[] at +0x830 inside struct mm_struct. Not a canonical upstream field, so it stays a numeric offset here. Confirmed by IDA decompile of my_do_page_fault and arm64_force_sig_fault_pre against the "cent.tmgp.sgame" literal. */
#define HARVEST_MM_PKG_OFFSET 0x830

/* Stack-relative qword indices into task->stack at the kprobe-fired frame. */
#define HARVEST_STACK_IDX_X2 2008
#define HARVEST_STACK_IDX_X8 2014
#define HARVEST_STACK_IDX_X9 2015
#define HARVEST_STACK_IDX_ESR 2036

/* Hero address-map storage lives in drv.wz_hero_addr_map (struct drv_state in driver/include/driver/types.h). We treat that __u8 buffer as the slot array to match comm.c's DRV_CMD_GAME_ASSET_READ_A / DRV_CMD_TEAR_DOWN consumers, which read/clear the same backing bytes. Likewise drv.wz_hero_objects is the single companion buffer the ioctl path drains via DRV_CMD_GAME_ASSET_READ_B. No file-static duplicates here -- a second copy would silently desync from userspace. */
static inline struct wz_hero_slot *wz_slots(void) {
	return (struct wz_hero_slot *)drv.wz_hero_addr_map;
}

static void(*orig_do_page_fault)(unsigned long addr, unsigned int esr, struct pt_regs *regs);

static bool kernel_hook_is_hooked;
static bool arm64_force_sig_fault_kp_is_registered;

static hook_t do_page_fault_hook;

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
	struct mm_struct *mm;
	const char *pkg;

	if (!task)
		return false;

	mm = task->mm;
	if (!mm)
		return false;

	pkg = (const char *)((u8 *)mm + HARVEST_MM_PKG_OFFSET);
	return strcmp(pkg, KCFG_TARGET_PACKAGE) == 0;
}

void my_do_page_fault(unsigned long addr, unsigned int esr, struct pt_regs *regs) {
	void(*tail)(unsigned long, unsigned int, struct pt_regs *);

	if (!regs)
		goto tail_call;

	if (!harvest_match_current_pkg())
		goto tail_call;

	/* regs[30] (X30/LR slot @ +0xF0) carries ESR-like fault status in this trampoline frame. */
	if ((((u64 *)regs)[30] & ESR_DFSC_MASK) != ESR_DFSC_HARVEST_VAL)
		goto tail_call;

	{
		u64 x2 = ((u64 *)regs)[2];
		u64 x8 = ((u64 *)regs)[8];
		u64 x9 = ((u64 *)regs)[9];

		if (x8 == 0 || x2 == 0)
			goto tail_call;
		/* Upper 32 bits of X9 encode the hero-id in a tagged pointer. */
		if ((u32)(x9 >> 32) == 0)
			goto tail_call;

		wz_record(x9, x8, x2);
	}

tail_call:
	tail = orig_do_page_fault;
	if (!tail)
		return;

	/* Trampoline buffer has no KCFI type-id prefix word; route the indirect call through DRV_NOCFI_CALL so the compiler-emitted KCFI check (CONFIG_CFI_CLANG=y on GKI 6.6) does not trap with BRK #0x8228. */
	DRV_NOCFI_CALL(tail, addr, esr, regs);
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
	hook_err_t err;

	if (kernel_hook_is_hooked)
		return 0;

	addr = kallsym_lookup("do_page_fault");
	if (!addr) {
		pr_drv_err("install_page_fault_hook: do_page_fault not found\n");
		return -ENOENT;
	}

	memset(&do_page_fault_hook, 0, sizeof(do_page_fault_hook));
	do_page_fault_hook.func_addr = addr;
	do_page_fault_hook.origin_addr = addr;
	do_page_fault_hook.replace_addr = (u64)(uintptr_t)&my_do_page_fault;
	/* relo_addr must point to the kernel VA of the relocated-prologue buffer BEFORE hook_prepare runs — hook_prepare's is_bad_address () check rejects zero, and back_src_addr is computed from this. */
	do_page_fault_hook.relo_addr = (u64)(uintptr_t)&do_page_fault_hook.relo_insts[0];

	err = hook_prepare(&do_page_fault_hook);
	if (err != HOOK_NO_ERR) {
		pr_drv_err("install_page_fault_hook: hook_prepare failed (%d)\n", (int)err);
		return -EINVAL;
	}

	/* Publish trampoline before flipping the patch live. */
	orig_do_page_fault = (void *)(uintptr_t)do_page_fault_hook.relo_addr;
	smp_wmb();

	hook_install(&do_page_fault_hook);
	kernel_hook_is_hooked = true;

	pr_drv("install_page_fault_hook: do_page_fault@%lx -> %p, orig=%p\n", addr, &my_do_page_fault, orig_do_page_fault);
	return 0;
}

static int install_force_sig_fault_kprobe(void) {
	int ret;

	if (arm64_force_sig_fault_kp_is_registered)
		return 0;

	ret = register_kprobe(&arm64_force_sig_fault_kp);
	if (ret) {
		pr_drv_err("register_kprobe (arm64_force_sig_fault) failed: %d\n", ret);
		return ret;
	}

	arm64_force_sig_fault_kp_is_registered = true;
	pr_drv("arm64_force_sig_fault kprobe armed\n");
	return 0;
}

int install_harvest_hooks(void) {
	int rc1, rc2;

	rc1 = install_page_fault_hook();
	rc2 = install_force_sig_fault_kprobe();

	if (rc1)
		return rc1;
	return rc2;
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
