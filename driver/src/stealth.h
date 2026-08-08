// SPDX-License-Identifier: GPL-2.0
// GPU (KGSL/Adreno) process concealment. Two layers:
// - STRENGTH >= 1: retroactive rb_erase (hide_kgsl_by_pid) — one-shot per PID via ioctl.
// - STRENGTH >= 2: proactive kprobes on kgsl_process_init_sysfs/_debugfs + sysfs_create_group.
#ifndef DRIVER_STEALTH_H
#define DRIVER_STEALTH_H

#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#if KCFG_HIDE_KGSL_STRENGTH != 0
long hide_kgsl_by_pid(void *kgsl_driver, int target_pid);
void *resolve_kgsl_driver(void);
#else
static inline long hide_kgsl_by_pid(void *kgsl_driver, int target_pid) { (void)kgsl_driver; (void)target_pid; return -EOPNOTSUPP; }
static inline void *resolve_kgsl_driver(void) { return NULL; }
#endif

#if KCFG_HIDE_KGSL_STRENGTH >= 2
int kgsl_stealth_arm(void);
#else
static inline int kgsl_stealth_arm(void) { return 0; }
#endif

#endif /* DRIVER_STEALTH_H */
