// SPDX-License-Identifier: GPL-2.0
//
// Kernel-side durable trace logger.
//
// printk + /dev/kmsg goes through a userspace reader (cat/dd) whose stdio
// buffer can hold ~16KB of unsynced data — exactly the window between a
// "we are about to do the dangerous thing" log and a panic. By writing
// straight to a file from kernel context with vfs_fsync after every line,
// we guarantee the pre-panic trail reaches the ext4 journal before any
// CPU notices the patch went wrong.
//
// Output: KDEBUG_TRACE_PATH (defaults to /data/local/tmp/test/driver-trace.log).
//
// Callers MUST be in process context (mutex + vfs_fsync sleep).  Atomic-
// context paths (kprobe pre-handlers, page-fault hooks) must keep using
// pr_drv() — they get duplicated into the trace from the install path that
// surrounds them.

#ifndef DRIVER_KDEBUG_H
#define DRIVER_KDEBUG_H

#ifndef KDEBUG_TRACE_PATH
#define KDEBUG_TRACE_PATH "/data/local/tmp/test/driver-trace.log"
#endif

void kdebug_init(const char *path);
void kdebug_close(void);
void kdebug_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Convenience macro mirroring pr_drv() but landing in the durable file. */
#define trace_drv(fmt, ...) kdebug_printf(fmt, ##__VA_ARGS__)

#endif /* DRIVER_KDEBUG_H */
