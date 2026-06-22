// SPDX-License-Identifier: GPL-2.0
// /dev/input/event* read hijack (adapted from KernelSU vfs_read_hook).
#ifndef DRIVER_VFS_HIJACK_H
#define DRIVER_VFS_HIJACK_H

#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/workqueue.h>

/* Filters: uid == AID_SYSTEM(1000), fd resolves to /dev/input/event*, evdev exposes EV_ABS with both ABS_MT_POSITION_X/Y in absbit. On first match, memcpy 0x108 bytes of f_op into fops_proxy, redirect .read -> read_proxy, swap file->f_op. */
int sys_read_handler_pre(struct kprobe *p, struct pt_regs *regs);

/* Runs via system_wq because unregister_kprobe () sleeps. */
void do_stop_vfs_read_hook(struct work_struct *work);

/* Chains to orig_read with a KCFI type-hash check against 0xE866E2F4, then parses the input_event[] into the per-slot table and emits a normalized MT-B stream to userspace. */
ssize_t read_proxy(struct file *file, char __user *buf, size_t count, loff_t *ppos);

int install_vfs_read_hook(void);

void stop_vfs_read_hook(void);

#endif /* DRIVER_VFS_HIJACK_H */
