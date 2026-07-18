// SPDX-License-Identifier: GPL-2.0-only
/* GPU(KGSL/Adreno) process concealment: unlink target PID from kgsl_driver
 * rbtrees. Offset table is keyed on LINUX_VERSION_CODE; source data comes
 * from reversal of the enen family (04_drivers/enen-android1{2,3,4,5,6}-*.ko),
 * and a runtime holder pointer sanity check turns a stale offset into
 * -EOPNOTSUPP rather than an rb_first/rb_next oops on whatever counter happens
 * to live at that slot. */

#include <linux/version.h>

#if KCFG_HIDE_KGSL

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include "kallsym.h"
#include "log.h"
#include "stealth.h"

/* Per-kernel layout of the downstream `struct kgsl_driver` and the `struct kgsl_process_private` reached through it. KGSL never exports either type, so offsets are reconstructed from binary layout. The 6.6 row is the one exercised on a real device; the others are extrapolated from the same reversal bank and the runtime holder_ptr_looks_valid () check below is the safety net if any BSP fork drifted. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
	/* 5.10 (Android 12): single holder only — second holder pointer did not
	 * yet exist in kgsl_driver on this era's msm-5.10 BSP. */
#	define KGSL_HOLDER_A_OFFSET		0x420
#	define KGSL_HAS_HOLDER_B		0
#	define KGSL_INNER_STATE_OFFSET		0x70
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	/* 5.15 / 6.1 (Android 13 / 14): second holder appeared adjacent to the
	 * first; kgsl_process_private layout unchanged from 5.10. */
#	define KGSL_HOLDER_A_OFFSET		0x430
#	define KGSL_HOLDER_B_OFFSET		0x428
#	define KGSL_HAS_HOLDER_B		1
#	define KGSL_INNER_STATE_OFFSET		0x70
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
	/* 6.6 (Android 15): kgsl_driver grew by 24 bytes ahead of both holders;
	 * kgsl_process_private layout still unchanged. This is the row that
	 * has been exercised end-to-end on a real device. */
#	define KGSL_HOLDER_A_OFFSET		0x448
#	define KGSL_HOLDER_B_OFFSET		0x440
#	define KGSL_HAS_HOLDER_B		1
#	define KGSL_INNER_STATE_OFFSET		0x70
#else
	/* 6.12+ (Android 16): holder offsets reverted to the 5.15/6.1 values,
	 * but the state word inside kgsl_process_private moved from +0x70 to
	 * +0x3C. */
#	define KGSL_HOLDER_A_OFFSET		0x430
#	define KGSL_HOLDER_B_OFFSET		0x428
#	define KGSL_HAS_HOLDER_B		1
#	define KGSL_INNER_STATE_OFFSET		0x3C
#endif

/* These inner offsets are stable across the rows above; the state offset is
 * selected separately because it moves on 6.12+. */
#define KGSL_HOLDER_INNER_OFFSET		0x30
#define KGSL_INNER_COUNT_OFFSET			0x40
#define KGSL_INNER_RBROOT_OFFSET		0x48
#define KGSL_INNER_STATE_READY_MASK		0x0F
#define KGSL_INNER_STATE_READY_VALUE		0x01

/* KGSL keeps the process' pid as a decimal string in the 8 bytes immediately preceding the embedded rb_node. */
#define KGSL_PROC_PRIVATE_NAME_FROM_NODE(node) (*(const char * const *)((char *)(node) - 8))

/* Resolved lazily: KGSL may load after us, and kallsyms_lookup_name is unexported on 6.x. */
static void *kgsl_driver_cache;

void *resolve_kgsl_driver(void) {
	unsigned long addr;

	if (kgsl_driver_cache)
		return kgsl_driver_cache;

	addr = kallsym_lookup("kgsl_driver");
	if (!addr)
		return NULL;

	kgsl_driver_cache = (void *)addr;
	return kgsl_driver_cache;
}

/* Plausibility check for a pointer pulled out of a downstream vendor struct via a hard-coded offset. NULL passes (an empty rbtree holder is a legitimate state). Non-NULL must have bit 63 set (ARM64 kernel VAs) AND be pointer-aligned. Used to bail out before dereferencing a stale offset — otherwise the rb_first/rb_next traversal would oops on whatever stats counter happens to live at that slot. */
static inline bool holder_ptr_looks_valid(const void *p) {
	uintptr_t v = (uintptr_t)p;
	return v == 0 || (((v >> 63) & 1u) && IS_ALIGNED(v, sizeof(void *)));
}

/* Walk one holder's rbtree; erase the node whose PID string matches @target_pid. No-op if the holder is empty, its inner is NULL, or the inner is not in the "ready" state — matches the enen decompile's early-return chain. */
static void erase_pid_from_holder(void *holder, int target_pid) {
	void *inner;
	struct rb_root *root;
	struct rb_node *node;
	u16 state;
	int parsed_pid = 0;

	if (!holder)
		return;

	inner = *(void **)((char *)holder + KGSL_HOLDER_INNER_OFFSET);
	if (!inner)
		return;

	state = *(const u16 *)((const char *)inner + KGSL_INNER_STATE_OFFSET);
	if ((state & KGSL_INNER_STATE_READY_MASK) != KGSL_INNER_STATE_READY_VALUE)
		return;

	root = (struct rb_root *)((char *)inner + KGSL_INNER_RBROOT_OFFSET);

	for (node = rb_first(root); node; node = rb_next(node)) {
		const char *name = KGSL_PROC_PRIVATE_NAME_FROM_NODE(node);

		if (kstrtoint(name, 10, &parsed_pid) == 0 && parsed_pid == target_pid) {
			rb_erase(node, root);
			(*(u64 *)((char *)inner + KGSL_INNER_COUNT_OFFSET))--;
			pr_drv("hid kgsl pid: %d\n", target_pid);
			return;
		}
	}
}

long hide_kgsl_by_pid(void *kgsl_driver, int target_pid) {
	void *holder_a;
#if KGSL_HAS_HOLDER_B
	void *holder_b;
#endif

	if (!kgsl_driver)
		return -EOPNOTSUPP;

	/* Validate BOTH holders before touching either — matches the previous
	 * "either bad → refuse both" semantics from comm.c and prevents a
	 * partial erase if only holder B has drifted. */
	holder_a = *(void **)((u8 *)kgsl_driver + KGSL_HOLDER_A_OFFSET);
	if (!holder_ptr_looks_valid(holder_a)) {
		pr_drv_warn("hide_kgsl_by_pid: holder A offset stale on this build (a=%p); refusing\n",
			    holder_a);
		return -EOPNOTSUPP;
	}

#if KGSL_HAS_HOLDER_B
	holder_b = *(void **)((u8 *)kgsl_driver + KGSL_HOLDER_B_OFFSET);
	if (!holder_ptr_looks_valid(holder_b)) {
		pr_drv_warn("hide_kgsl_by_pid: holder B offset stale on this build (b=%p); refusing\n",
			    holder_b);
		return -EOPNOTSUPP;
	}
#endif

	erase_pid_from_holder(holder_a, target_pid);
#if KGSL_HAS_HOLDER_B
	erase_pid_from_holder(holder_b, target_pid);
#endif

	return 0;
}

#endif /* KCFG_HIDE_KGSL */
