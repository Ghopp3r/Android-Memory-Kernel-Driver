// SPDX-License-Identifier: GPL-2.0
// logging wrappers; "[driver] " prefix used so dmesg lines are uniformly tagged.
#ifndef DRIVER_LOG_H
#define DRIVER_LOG_H

#include <linux/kernel.h>
#include <linux/printk.h>

#ifndef DRV_LOG_TAG
#define DRV_LOG_TAG "[driver]"
#endif

#define pr_drv(fmt, ...) printk(KERN_INFO "[driver] " fmt, ##__VA_ARGS__)
#define pr_drv_err(fmt, ...) printk(KERN_ERR "[driver] " fmt, ##__VA_ARGS__)
#define pr_drv_warn(fmt, ...) printk(KERN_WARNING "[driver] " fmt, ##__VA_ARGS__)
#define pr_drv_notice(fmt, ...) printk(KERN_NOTICE "[driver] " fmt, ##__VA_ARGS__)

#ifdef CONFIG_DRIVER_VERBOSE_DEBUG
#define pr_drv_dbg(fmt, ...) printk(KERN_DEBUG "[driver] " fmt, ##__VA_ARGS__)
#else
#define pr_drv_dbg(fmt, ...) do { } while (0)
#endif

#endif /* DRIVER_LOG_H */
