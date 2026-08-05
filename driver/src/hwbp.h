// SPDX-License-Identifier: GPL-2.0-only
#ifndef DRIVER_HWBP_H
#define DRIVER_HWBP_H

#include <linux/types.h>

int hwbp_init(void);
long do_hwbp_cmd(unsigned int cmd, void __user *arg);

#endif /* DRIVER_HWBP_H */
