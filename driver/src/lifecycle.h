// SPDX-License-Identifier: GPL-2.0
// Module initialization and compile-time self-concealment.
#ifndef DRIVER_LIFECYCLE_H
#define DRIVER_LIFECYCLE_H

#include <linux/init.h>

int __init init_driver(void);

#endif /* DRIVER_LIFECYCLE_H */
