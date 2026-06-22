// SPDX-License-Identifier: GPL-2.0
// logging wrappers; DRV_LOG_TAG prefix used so dmesg lines are uniformly tagged.
#ifndef DRIVER_LOG_H
#define DRIVER_LOG_H

#include <linux/kernel.h>
#include <linux/printk.h>

#ifndef DRV_LOG_TAG
#define DRV_LOG_TAG "[memory-driver]"
#endif

#define pr_drv(fmt, ...) printk(KERN_INFO DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define pr_drv_err(fmt, ...) printk(KERN_ERR DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define pr_drv_warn(fmt, ...) printk(KERN_WARNING DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define pr_drv_notice(fmt, ...) printk(KERN_NOTICE DRV_LOG_TAG " " fmt, ##__VA_ARGS__)

#ifdef CONFIG_DRIVER_VERBOSE_DEBUG
#define pr_drv_dbg(fmt, ...) printk(KERN_DEBUG DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#else
#define pr_drv_dbg(fmt, ...) do { } while (0)
#endif

#endif /* DRIVER_LOG_H */
