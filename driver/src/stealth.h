// SPDX-License-Identifier: GPL-2.0
// GPU(KGSL/Adreno) process concealment via rbtree erase.
#ifndef DRIVER_STEALTH_H
#define DRIVER_STEALTH_H

#include <linux/pid.h>
#include <linux/rbtree.h>
#include <linux/types.h>

/* Erase @target_pid from the rbtree reached via kgsl_driver+0x448 -> [+0x30] -> rbtree root @+0x48. PID is matched against the decimal string at offset -8 from the rb_node. */
long hide_kgsl(void *kgsl_proc_list_root, int target_pid);

/* Mirror of hide_kgsl for the kgsl_driver+0x440 rbtree. Both must be called to fully cloak the PID. Duplicated (not parameterised) because the original binary inlined both call sites — keep dup so IDA name fingerprints continue to match. */
long hide_kgsl2(void *kgsl_proc_list_root, int target_pid);

/* Resolves the global kgsl_driver via kallsym (kallsyms_lookup_name is no longer exported on 6.x). Cached after first hit. */
void *resolve_kgsl_driver(void);

#endif /* DRIVER_STEALTH_H */
