// SPDX-License-Identifier: GPL-2.0
// Kernel-side durable trace logger. See kdebug.h.
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/stdarg.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/uaccess.h>

#include "kdebug.h"
#include "log.h"

static struct file *trace_file;
static DEFINE_MUTEX(trace_lock);

void kdebug_init(const char *path) {
	struct file *f;
	const char *use = path ? path : KDEBUG_TRACE_PATH;

	if (trace_file)
		return;

	f = filp_open(use, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
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

	if (f)
		filp_close(f, NULL);
}

void kdebug_printf(const char *fmt, ...) {
	char buf[256];
	va_list args;
	int len;
	struct file *f;
	loff_t pos;
	ssize_t wrote;

	f = trace_file;
	if (!f)
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
		wrote = kernel_write(f, buf, len, &pos);
		if (wrote > 0)
			f->f_pos = pos;
		vfs_fsync(f, 0);
	}
	mutex_unlock(&trace_lock);
}
