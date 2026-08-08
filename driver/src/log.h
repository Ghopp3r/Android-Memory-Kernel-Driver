// SPDX-License-Identifier: GPL-2.0
// Compact log macros; every line is prefixed with DRV_LOG_TAG so dmesg is uniformly grep-able.
#ifndef DRIVER_LOG_H
#define DRIVER_LOG_H

#include <linux/kernel.h>
#include <linux/printk.h>

#ifndef DRV_LOG_TAG
#define DRV_LOG_TAG "[memory-driver]"
#endif

#define LOGE(fmt, ...) printk(KERN_ERR DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) printk(KERN_WARNING DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define LOGW_RL(fmt, ...) printk_ratelimited(KERN_WARNING DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define LOGN(fmt, ...) printk(KERN_NOTICE DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) printk(KERN_INFO DRV_LOG_TAG " " fmt, ##__VA_ARGS__)

#ifdef CONFIG_DRIVER_VERBOSE_DEBUG
#define LOGD(fmt, ...) printk(KERN_DEBUG DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#else
#define LOGD(fmt, ...) do { } while (0)
#endif

#endif /* DRIVER_LOG_H */
