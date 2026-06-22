// SPDX-License-Identifier: GPL-2.0
// userspace communication bootstrap: reboot () magic-handshake -> anon-inode fd.
#ifndef DRIVER_COMM_H
#define DRIVER_COMM_H

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/task_work.h>
#include <linux/types.h>

#include <driver/uapi.h>

#define COMM_REBOOT_MAGIC1 DRIVER_REBOOT_MAGIC1
#define COMM_REBOOT_MAGIC2 DRIVER_REBOOT_MAGIC2
#define COMM_PRCTL_MAGIC DRIVER_PRCTL_MAGIC

struct driver_install_work {
	struct callback_head head;
	void __user *reply; /* +0x10: user pointer where fd is written */
};

int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs);
int prctl_handler_pre(struct kprobe *p, struct pt_regs *regs);

/* Pre-resolve every kallsyms-shimmed function pointer reachable from a kprobe
   pre-handler. Must be called from init_driver() before any handler kprobe is
   armed; otherwise the first handshake re-enters register_kprobe in atomic
   context. */
int comm_warm_symbols(void);

void driver_install_fd_tw_func(struct callback_head *twork);

long dispatch_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

extern const struct file_operations inofile_fops;

extern struct kprobe reboot_kp;
extern struct kprobe prctl_kp;
extern bool prctl_kp_registered;

#endif /* DRIVER_COMM_H */
