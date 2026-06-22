// SPDX-License-Identifier: GPL-2.0
// kallsyms_lookup_name shim for 6.x kernels (unexported since 5.7).
#ifndef DRIVER_KALLSYM_H
#define DRIVER_KALLSYM_H

#include <linux/types.h>

/* kprobe-on-the-symbol trick: register_kprobe sets kp.addr to the resolved address, which we read back and cache. Fails on CONFIG_KALLSYMS=n. */
int kallsym_init(void);

unsigned long kallsym_lookup(const char *name);

unsigned long kallsym_lookup_or_die(const char *name);

/* On kernels >= 6.1 the kprobes core gates register_kprobe () through the "kprobe_blacklist" list. Zero every entry's start_addr/end_addr so the range check accepts NOKPROBE_SYMBOL-marked arm64 trap entries. */
int kallsym_disable_kprobe_blacklist(void);

#endif /* DRIVER_KALLSYM_H */
