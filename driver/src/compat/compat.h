// SPDX-License-Identifier: GPL-2.0
/* compat.h - Minimal kernel-version compatibility surface. The DDK Docker image supplies KMI-pinned kernel headers; struct layouts come from <linux/sched.h>, <linux/mm_types.h>, <linux/input.h>, etc. and are referenced by field name throughout the driver. This header carries only: the canonical kernel header include set, the small handful of LINUX_VERSION_CODE-gated wrappers we cannot avoid (VMA walk on 6.1+, CFI-safe indirect call), and a few driver-private constants that are not kernel struct offsets. See docs/refactor/REFACTOR_PLAYBOOK.md sections 1, 3, 4. */

#ifndef _DRIVER_COMPAT_H
#define _DRIVER_COMPAT_H

#include <linux/version.h>

#include <asm/pgtable.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/input.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/pgtable.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>

/* mmap_lock wrappers — kept as named macros so call sites read intent at a glance. Our 5.10 floor means the legacy down_read(&mm->mmap_sem) branch is dead code; no gate needed. */
#define DRV_MM_READ_LOCK(mm) mmap_read_lock(mm)
#define DRV_MM_READ_UNLOCK(mm) mmap_read_unlock(mm)
#define DRV_MM_WRITE_LOCK(mm) mmap_write_lock(mm)
#define DRV_MM_WRITE_UNLOCK(mm) mmap_write_unlock(mm)

/* VMA traversal: the one unavoidable kernel-version gate on our matrix. v6.1 dropped mm->mmap + vm_next in favour of mm_mt + the iterator API. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#  define DRV_FOR_EACH_VMA(mm, vma) \
       VMA_ITERATOR(__vmi, (mm), 0); \
       for_each_vma(__vmi, vma)
#else
#  define DRV_FOR_EACH_VMA(mm, vma) \
       for ((vma) = (mm)->mmap; (vma); (vma) = (vma)->vm_next)
#endif

/* CFI-safe helpers for indirect calls through kallsyms-resolved function pointers. <linux/cfi.h> provides runtime CFI helpers on 5.13+; compiler-clang.h defines __nocfi as a function attribute when KCFI is enabled. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#  include <linux/cfi.h>
#endif
#ifndef __nocfi
#  define __nocfi
#endif

#define DRV_NOCFI_CALL(fn, ...) (fn)(__VA_ARGS__)

/* kallsyms_lookup_name was unexported in v5.7 (commit 0bd476e6c671). All our targets are >= 5.10 so the kprobe-trampoline path is always taken; the gate is kept as a guard for any future down-rev. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#  define DRV_KALLSYMS_VIA_KPROBE 1
#endif

/* KGSL_DRIVER_RBTREE_OFFSET — offset of the rb_root inside the global kgsl_driver pagetable cache reached via kallsyms_lookup_name("kgsl_driver"). Vendor (Qualcomm) struct kept private; no public header carries the layout. Derived from the page_fault_harvest / gpu_stealth dossiers. */
#define KGSL_DRIVER_RBTREE_OFFSET 72 /* 0x48 */

/* ESR_DFSC_MASK — ARM64 ESR_ELx data-fault status code mask. Bits 0..11 of the ISS field cover {FSC, WnR, S1PTW, CM} for data aborts; the driver applies this mask before comparing against the harvest tag. */
#define ESR_DFSC_MASK 0xFFFu

/* ESR_DFSC_HARVEST_VAL — composite value the page-fault-harvest path compares ESR & ESR_DFSC_MASK against. 0x1F4 unpacks to CM | S1PTW | WnR | permission-style FSC subset. */
#define ESR_DFSC_HARVEST_VAL 0x1F4u

/* KCFG_TARGET_PACKAGE_DEFAULT — default Android package name the driver activates on. The original binary keyed off "cent.tmgp.sgame"; downstream forks override via Kbuild -DKCFG_TARGET_PACKAGE=. */
#ifndef KCFG_TARGET_PACKAGE_DEFAULT
#  define KCFG_TARGET_PACKAGE_DEFAULT "cent.tmgp.sgame"
#endif

#ifndef KCFG_TARGET_PACKAGE
#  define KCFG_TARGET_PACKAGE KCFG_TARGET_PACKAGE_DEFAULT
#endif

#ifndef KCFG_HARVEST_TABLE_NAME
#  define KCFG_HARVEST_TABLE_NAME "wz_hero_addr_map"
#endif

#ifndef KCFG_DRIVER_NAME
#  define KCFG_DRIVER_NAME "my-driver"
#endif

#endif /* _DRIVER_COMPAT_H */
