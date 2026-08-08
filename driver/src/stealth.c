// SPDX-License-Identifier: GPL-2.0-only
// KGSL/Adreno concealment. STRENGTH 1: rb_erase on demand. STRENGTH 2: proactive kprobes that spoof -ENOMEM for hidden PIDs. STRENGTH 3: both.

#include <linux/version.h>

#if KCFG_HIDE_KGSL_STRENGTH != 0

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/kstrtox.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>

#include "hide_task.h"
#include "kallsym.h"
#include "log.h"
#include "stealth.h"

/* Per-kernel layout of the downstream struct kgsl_driver and struct kgsl_process_private reached through it. KGSL never exports either type — offsets from the enen reversal bank. The 6.6 row is device-tested; others are extrapolated with a runtime holder_ptr_looks_valid() safety net. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#define KGSL_HOLDER_A_OFFSET 0x420
#define KGSL_HAS_HOLDER_B 0
#define KGSL_INNER_STATE_OFFSET 0x70
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
#define KGSL_HOLDER_A_OFFSET 0x430
#define KGSL_HOLDER_B_OFFSET 0x428
#define KGSL_HAS_HOLDER_B 1
#define KGSL_INNER_STATE_OFFSET 0x70
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#define KGSL_HOLDER_A_OFFSET 0x448
#define KGSL_HOLDER_B_OFFSET 0x440
#define KGSL_HAS_HOLDER_B 1
#define KGSL_INNER_STATE_OFFSET 0x70
#else
#define KGSL_HOLDER_A_OFFSET 0x430
#define KGSL_HOLDER_B_OFFSET 0x428
#define KGSL_HAS_HOLDER_B 1
#define KGSL_INNER_STATE_OFFSET 0x3C
#endif

/* Inner offsets are stable across profiles (only state offset moved on 6.12+). */
#define KGSL_HOLDER_INNER_OFFSET 0x30
#define KGSL_INNER_COUNT_OFFSET 0x40
#define KGSL_INNER_RBROOT_OFFSET 0x48
#define KGSL_INNER_STATE_READY_MASK 0x0F
#define KGSL_INNER_STATE_READY_VALUE 0x01

/* KGSL keeps the process PID as decimal string in the 8 bytes preceding the embedded rb_node. */
#define KGSL_PROC_PRIVATE_NAME_FROM_NODE(node) (*(const char * const *)((char *)(node) - 8))

/* KGSL may load after us and kallsyms_lookup_name is unexported on 6.x — cache on first hit. */
static void *kgsl_driver_cache;

void *resolve_kgsl_driver(void) {
	unsigned long addr;
	if (kgsl_driver_cache) return kgsl_driver_cache;
	addr = kallsym_lookup("kgsl_driver");
	if (!addr) return NULL;
	kgsl_driver_cache = (void *)addr;
	return kgsl_driver_cache;
}

/* NULL passes (an empty holder is legitimate). Non-NULL must have bit 63 set (ARM64 kernel VA) AND be pointer-aligned — guards against stale offsets tearing through an unrelated stats slot. */
static inline bool holder_ptr_looks_valid(const void *p) {
	uintptr_t v = (uintptr_t)p;
	return v == 0 || (((v >> 63) & 1u) && IS_ALIGNED(v, sizeof(void *)));
}

/* Walk one holder's rbtree; erase the node whose PID string matches target_pid. No-op if the holder is empty, inner is NULL, or inner state is not "ready". */
static void erase_pid_from_holder(void *holder, int target_pid) {
	void *inner;
	struct rb_root *root;
	struct rb_node *node;
	u16 state;
	int parsed_pid = 0;

	if (!holder) return;
	inner = *(void **)((char *)holder + KGSL_HOLDER_INNER_OFFSET);
	if (!inner) return;
	state = *(const u16 *)((const char *)inner + KGSL_INNER_STATE_OFFSET);
	if ((state & KGSL_INNER_STATE_READY_MASK) != KGSL_INNER_STATE_READY_VALUE) return;

	root = (struct rb_root *)((char *)inner + KGSL_INNER_RBROOT_OFFSET);
	for (node = rb_first(root); node; node = rb_next(node)) {
		const char *name = KGSL_PROC_PRIVATE_NAME_FROM_NODE(node);
		if (kstrtoint(name, 10, &parsed_pid) == 0 && parsed_pid == target_pid) {
			rb_erase(node, root);
			(*(u64 *)((char *)inner + KGSL_INNER_COUNT_OFFSET))--;
			LOGI("kgsl: erased pid %d from holder\n", target_pid);
			return;
		}
	}
}

long hide_kgsl_by_pid(void *kgsl_driver, int target_pid) {
	void *holder_a;
#if KGSL_HAS_HOLDER_B
	void *holder_b;
#endif

	if (!kgsl_driver) return -EOPNOTSUPP;

	holder_a = *(void **)((u8 *)kgsl_driver + KGSL_HOLDER_A_OFFSET);
	if (!holder_ptr_looks_valid(holder_a)) { LOGW("kgsl: holder A stale (a=%p) — refusing\n", holder_a); return -EOPNOTSUPP; }

#if KGSL_HAS_HOLDER_B
	holder_b = *(void **)((u8 *)kgsl_driver + KGSL_HOLDER_B_OFFSET);
	if (!holder_ptr_looks_valid(holder_b)) { LOGW("kgsl: holder B stale (b=%p) — refusing\n", holder_b); return -EOPNOTSUPP; }
#endif

	erase_pid_from_holder(holder_a, target_pid);
#if KGSL_HAS_HOLDER_B
	erase_pid_from_holder(holder_b, target_pid);
#endif
	return 0;
}

#if KCFG_HIDE_KGSL_STRENGTH >= 2

/* Proactive kprobes: fire only for hidden PIDs, spoof -ENOMEM so KGSL never creates a /sys/class/kgsl/kgsl/proc/PID entry to begin with. */

static struct kprobe kp_kgsl_sysfs;
static struct kprobe kp_kgsl_debugfs;
static struct kprobe kp_sysfs_create_group;
static bool proactive_armed;

/* Skip original + return -ENOMEM (kgsl_process_init_* return int; -ENOMEM propagates cleanly). */
static void spoof_enomem_and_skip(struct pt_regs *regs) {
	regs->regs[0] = (unsigned long)(long)-ENOMEM;
	instruction_pointer_set(regs, procedure_link_pointer(regs));
}

static int kgsl_init_pre(struct kprobe *p, struct pt_regs *regs) {
	(void)p;
	if (!regs) return 0;
	if (!hide_task_contains((pid_t)current->tgid)) return 0;
	spoof_enomem_and_skip(regs);
	return 1;
}

/* sysfs_create_group(kobj, grp): scan up to 7 parents for a name containing "kgsl". Cheap fast-reject for non-hidden PIDs — check hide_task_contains first. */
static int sysfs_create_group_pre(struct kprobe *p, struct pt_regs *regs) {
	struct kobject *kobj;
	int i;

	(void)p;
	if (!regs) return 0;
	if (!hide_task_contains((pid_t)current->tgid)) return 0;

	kobj = (struct kobject *)regs->regs[0];
	for (i = 0; i < 7 && kobj; i++) {
		if (kobj->name && strstr(kobj->name, "kgsl")) {
			spoof_enomem_and_skip(regs);
			return 1;
		}
		kobj = kobj->parent;
	}
	return 0;
}

static int arm_one(struct kprobe *kp, const char *name, kprobe_pre_handler_t handler) {
	unsigned long addr;
	int rc;

	addr = kallsym_lookup(name);
	if (!addr) { LOGW("kgsl stealth: %s not in kallsyms\n", name); return -ENOENT; }
	memset(kp, 0, sizeof(*kp));
	kp->addr = (kprobe_opcode_t *)addr;
	kp->pre_handler = handler;
	rc = register_kprobe(kp);
	if (rc) { LOGE("kgsl stealth: register_kprobe(%s) failed: %d\n", name, rc); return rc; }
	LOGI("kgsl stealth: armed kprobe on %s @ %px\n", name, (void *)addr);
	return 0;
}

int kgsl_stealth_arm(void) {
	int rc;
	if (proactive_armed) return 0;
	rc = arm_one(&kp_kgsl_sysfs, "kgsl_process_init_sysfs", kgsl_init_pre);
	if (rc) return rc;
	rc = arm_one(&kp_kgsl_debugfs, "kgsl_process_init_debugfs", kgsl_init_pre);
	if (rc) { unregister_kprobe(&kp_kgsl_sysfs); return rc; }
	rc = arm_one(&kp_sysfs_create_group, "sysfs_create_group", sysfs_create_group_pre);
	if (rc) { unregister_kprobe(&kp_kgsl_sysfs); unregister_kprobe(&kp_kgsl_debugfs); return rc; }
	proactive_armed = true;
	return 0;
}

#endif /* KCFG_HIDE_KGSL_STRENGTH >= 2 */

#endif /* KCFG_HIDE_KGSL_STRENGTH != 0 */
