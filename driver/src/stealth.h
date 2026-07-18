// SPDX-License-Identifier: GPL-2.0
// GPU(KGSL/Adreno) process concealment via rbtree erase.
#ifndef DRIVER_STEALTH_H
#define DRIVER_STEALTH_H

#include <linux/pid.h>
#include <linux/rbtree.h>
#include <linux/types.h>

/* Erase @target_pid from every kgsl_process_private rbtree held by @kgsl_driver. Wraps the two-holder walk seen in the enen family (kernels 5.15+); on 5.10 the vendor KGSL had a single holder and the second call is compiled out. Holder / inner offsets are selected from LINUX_VERSION_CODE; see stealth.c for the layout table. Returns 0 on success (target erased, or pid was not present in the tree), -EOPNOTSUPP if @kgsl_driver is NULL or a compile-time holder offset dereferences to a value that fails the ARM64 kernel-VA sanity check (guards against stale offsets on an unfamiliar BSP fork). */
long hide_kgsl_by_pid(void *kgsl_driver, int target_pid);

/* Resolves the global kgsl_driver via kallsym (kallsyms_lookup_name is no longer exported on 6.x). Cached after first hit. Returns NULL when KGSL is not loaded (headless / non-Qualcomm devices). */
void *resolve_kgsl_driver(void);

#endif /* DRIVER_STEALTH_H */
