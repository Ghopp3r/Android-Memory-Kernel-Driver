// SPDX-License-Identifier: GPL-2.0
// ARM64 user-code constant-return hook dispatcher.
#ifndef DRIVER_USER_HOOK_H
#define DRIVER_USER_HOOK_H

#include <linux/types.h>

int user_hook_init(void);
long do_pte_hook_cmd(unsigned int cmd, void __user *arg);

#endif /* DRIVER_USER_HOOK_H */
