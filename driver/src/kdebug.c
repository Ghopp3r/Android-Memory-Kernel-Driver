// SPDX-License-Identifier: GPL-2.0
// Kernel-side durable trace logger. See kdebug.h.
//
// All filesystem helpers (filp_open / filp_close / kernel_write / vfs_fsync)
// are resolved through kallsym at runtime and dispatched through __nocfi
// trampolines.  On GKI 6.6 most of these are unexported or KMI-protected for
// modules, so the direct calls fail at insmod with:
//   my_driver: Unknown symbol filp_open (err -2)
//   my_driver: Protected symbol: kernel_write (err -13)
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/stdarg.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif
#ifndef __nocfi
#define __nocfi
#endif

#include "kallsym.h"
#include "kdebug.h"
#include "log.h"

typedef struct file *(*drv_filp_open_fn_t)(const char *filename, int flags, umode_t mode);
typedef int          (*drv_filp_close_fn_t)(struct file *filp, fl_owner_t id);
typedef ssize_t      (*drv_kernel_write_fn_t)(struct file *file, const void *buf, size_t count, loff_t *pos);
typedef int          (*drv_vfs_fsync_fn_t)(struct file *file, int datasync);

static drv_filp_open_fn_t    drv_filp_open_ptr;
static drv_filp_close_fn_t   drv_filp_close_ptr;
static drv_kernel_write_fn_t drv_kernel_write_ptr;
static drv_vfs_fsync_fn_t    drv_vfs_fsync_ptr;

static __nocfi noinline struct file *drv_call_filp_open(drv_filp_open_fn_t fn,
                                                        const char *p, int fl, umode_t m) {
	return fn(p, fl, m);
}
static __nocfi noinline int drv_call_filp_close(drv_filp_close_fn_t fn,
                                                struct file *f, fl_owner_t id) {
	return fn(f, id);
}
static __nocfi noinline ssize_t drv_call_kernel_write(drv_kernel_write_fn_t fn,
                                                      struct file *f, const void *b,
                                                      size_t c, loff_t *p) {
	return fn(f, b, c, p);
}
static __nocfi noinline int drv_call_vfs_fsync(drv_vfs_fsync_fn_t fn,
                                               struct file *f, int ds) {
	return fn(f, ds);
}

static struct file *trace_file;
static DEFINE_MUTEX(trace_lock);

static int kdebug_resolve(void) {
	if (drv_filp_open_ptr)
		return 0;
	drv_filp_open_ptr    = (drv_filp_open_fn_t)    kallsym_lookup("filp_open");
	drv_filp_close_ptr   = (drv_filp_close_fn_t)   kallsym_lookup("filp_close");
	drv_kernel_write_ptr = (drv_kernel_write_fn_t) kallsym_lookup("kernel_write");
	drv_vfs_fsync_ptr    = (drv_vfs_fsync_fn_t)    kallsym_lookup("vfs_fsync");

	pr_drv("kdebug resolve: filp_open=%p filp_close=%p kernel_write=%p vfs_fsync=%p\n",
	       drv_filp_open_ptr, drv_filp_close_ptr, drv_kernel_write_ptr, drv_vfs_fsync_ptr);

	if (!drv_filp_open_ptr || !drv_kernel_write_ptr)
		return -ENOENT;
	return 0;
}

void kdebug_init(const char *path) {
	struct file *f;
	const char *use = path ? path : KDEBUG_TRACE_PATH;

	if (trace_file)
		return;

	if (kdebug_resolve()) {
		pr_drv_err("kdebug_init: could not resolve fs helpers\n");
		return;
	}

	f = drv_call_filp_open(drv_filp_open_ptr, use,
	                       O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (IS_ERR(f)) {
		pr_drv_err("kdebug_init: filp_open(%s) failed: %ld\n", use, PTR_ERR(f));
		return;
	}
	trace_file = f;
	pr_drv("kdebug_init: trace -> %s (file=%px)\n", use, trace_file);
}

void kdebug_close(void) {
	struct file *f;

	mutex_lock(&trace_lock);
	f = trace_file;
	trace_file = NULL;
	mutex_unlock(&trace_lock);

	if (f && drv_filp_close_ptr)
		drv_call_filp_close(drv_filp_close_ptr, f, NULL);
}

void kdebug_printf(const char *fmt, ...) {
	char buf[256];
	va_list args;
	int len;
	struct file *f;
	loff_t pos;
	ssize_t wrote;

	f = trace_file;
	if (!f || !drv_kernel_write_ptr)
		return;

	va_start(args, fmt);
	len = vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	va_end(args);
	if (len <= 0)
		return;
	if (len >= (int)sizeof(buf) - 1)
		len = (int)sizeof(buf) - 2;
	if (buf[len - 1] != '\n') {
		buf[len++] = '\n';
	}

	mutex_lock(&trace_lock);
	f = trace_file;
	if (f) {
		pos = f->f_pos;
		wrote = drv_call_kernel_write(drv_kernel_write_ptr, f, buf, len, &pos);
		if (wrote > 0)
			f->f_pos = pos;
		if (drv_vfs_fsync_ptr)
			drv_call_vfs_fsync(drv_vfs_fsync_ptr, f, 0);
	}
	mutex_unlock(&trace_lock);
}
