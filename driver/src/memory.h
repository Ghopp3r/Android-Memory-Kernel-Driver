// SPDX-License-Identifier: GPL-2.0
// process memory read/write primitives (linear-map + vmap variants).
#ifndef DRIVER_MEMORY_H
#define DRIVER_MEMORY_H

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>

/* Walks @mm->pgd using m_page_level levels (derived from TCR_EL1). Honours block (hugepage) entries at any level. Page-offset bits merged into result so callers may pass an unaligned VA. */
int vaddr_to_phys(struct mm_struct *mm, u64 va, u64 *out_phys);

/* Linear-map (phys_to_virt) variants; clean+invalidate dcache around the access via FlushDCache.dcache_line_size. */
int read_process_memory_linear(struct mm_struct *target_mm, u64 target_va, void *local_kbuf, size_t len);
int write_process_memory_linear(struct mm_struct *target_mm, u64 target_va, const void *local_kbuf, size_t len);

/* vmap variants: required for pages whose linear-map alias is RO or not-present (some CMA / ION regions). */
int read_process_memory_vmap(struct mm_struct *target_mm, u64 target_va, void *local_kbuf, size_t len);
int write_process_memory_vmap(struct mm_struct *target_mm, u64 target_va, const void *local_kbuf, size_t len);

int kernel_rw(u64 kva, void *buf, size_t len, int do_write);

int multi_read_process_memory(struct mm_struct *target_mm, void __user *descs, unsigned int count);

/* Resolve aarch64_insn_patch_text_nosync and get_cmdline via kallsyms. Called
   once from lifecycle.c init_driver() AFTER kallsym_init(). Missing symbols
   are non-fatal: text writes retain their legacy fallback, while package
   lookup reports -EOPNOTSUPP when get_cmdline is unavailable. */
int memory_init(void);

/* Patch kernel text. Fast path: aarch64_insn_patch_text_nosync via kallsym
   (FIX_TEXT_POKE0, non-CONT fixmap slot — architecturally safe on Android 15
   / 6.6 GKI which maps .text with PTE_CONT). Fallback: legacy bespoke PGD
   walk + AP[2]/DBM flip + per-VA TLBI (only safe when target VA is NOT in a
   PTE_CONT block, e.g. byte-granular .rodata writes on non-hardened kernels).
   In-tree callers (hook_install / hook_remove) always pass 4-byte aligned
   dst + src + len, so the fast path is taken in production. NOT
   stop_machine'd — caller ensures target VA is quiescent. */
u64 write_ro_memory(u64 dst_kva, const void *src, u64 len);

u64 process_get_module_base(struct task_struct *task, const char *module_name);

/* DRV_CMD_READ_VMA_COOKIE(0x11): walks task mm_mt, strncmp (vma->anon_name, needle, 16); on hit returns *(u64 *)(vma + vma_cookie_off) where cookie_off is selected by the KPTI/non-KPTI struct vm_area_struct layout. Returns 0 on miss / failure. */
u64 process_read_vma_cookie(struct task_struct *task, const char *needle);

/* Reads task->thread.uw.tp_value (saved TPIDR_EL0 for non-current tasks). */
u64 process_get_tls(struct task_struct *task);

/* Caller must put_task_struct() on the non-NULL return. */
struct task_struct *process_find_task_by_comm(const char *comm);

/* Find an exact process argv[0] and return the smallest TGID visible in the
 * calling task's active PID namespace. get_cmdline() may sleep, so the
 * implementation snapshots task references under RCU and scans them after
 * leaving the read-side critical section. */
int process_find_pid_by_package(const char *package, pid_t *out_pid);

int process_maps_get_a(struct task_struct *task, void __user *u_buf, size_t cap);

#endif /* DRIVER_MEMORY_H */
