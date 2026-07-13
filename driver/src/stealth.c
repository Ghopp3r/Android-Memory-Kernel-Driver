// SPDX-License-Identifier: GPL-2.0-only
/* GPU(KGSL/Adreno) process concealment: unlink target PID from kgsl_driver rbtrees. */

#include <linux/version.h>

#if KCFG_HIDE_KGSL && LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)

#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include <driver/types.h>
#include <driver/uapi.h>

#include "kallsym.h"
#include "log.h"
#include "stealth.h"

/* KGSL never exports kgsl_process_private; layout is reconstructed from the
 * binary (page_fault_harvest / gpu_stealth dossiers). Vendor (Qualcomm) struct
 * kept private — no public header carries the layout. */
#define KGSL_HOLDER_INNER_OFFSET 0x30
#define KGSL_INNER_COUNT_OFFSET 0x40
#define KGSL_INNER_RBROOT_OFFSET 0x48
#define KGSL_INNER_STATE_OFFSET 0x70
#define KGSL_INNER_STATE_READY_MASK 0x0F
#define KGSL_INNER_STATE_READY_VALUE 0x01
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

/* Shared body for hide_kgsl/hide_kgsl2; wrappers kept so IDA fingerprints still match. */
static long __hide_kgsl_one(void *holder, int target_pid) {
	void *inner;
	struct rb_root *root;
	struct rb_node *node;
	u16 state;
	int parsed_pid = 0;
	long result = 0;

	if (!holder)
		return 0;

	inner = *(void **)((char *)holder + KGSL_HOLDER_INNER_OFFSET);
	if (!inner)
		return 0;

	state = *(const u16 *)((const char *)inner + KGSL_INNER_STATE_OFFSET);
	if ((state & KGSL_INNER_STATE_READY_MASK) != KGSL_INNER_STATE_READY_VALUE)
		return 0;

	root = (struct rb_root *)((char *)inner + KGSL_INNER_RBROOT_OFFSET);

	node = rb_first(root);
	result = (long)node;
	if (!node)
		return result;

	for (;;) {
		const char *name = KGSL_PROC_PRIVATE_NAME_FROM_NODE(node);

		if (kstrtoint(name, 10, &parsed_pid) == 0 && parsed_pid == target_pid)
			break;

		node = rb_next(node);
		result = (long)node;
		if (!node)
			return result;
	}

	rb_erase(node, root);
	(*(u64 *)((char *)inner + KGSL_INNER_COUNT_OFFSET))--;

	pr_drv("hid kgsl pid: %d\n", target_pid);
	result = 0;
	return result;
}

long hide_kgsl(void *kgsl_proc_list_root, int target_pid) {
	return __hide_kgsl_one(kgsl_proc_list_root, target_pid);
}

long hide_kgsl2(void *kgsl_proc_list_root, int target_pid) {
	return __hide_kgsl_one(kgsl_proc_list_root, target_pid);
}

#endif /* KCFG_HIDE_KGSL && kernel < 6.12 */
