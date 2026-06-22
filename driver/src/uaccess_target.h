// SPDX-License-Identifier: GPL-2.0
// TTBR0_EL1 swap wrappers for cross-mm uaccess.
#ifndef DRIVER_UACCESS_TARGET_H
#define DRIVER_UACCESS_TARGET_H

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/uaccess.h>

/* One-time init of cached CTR_EL0-derived dcache line size; safe to call repeatedly (idempotent). */
void uaccess_target_init(void);

/* Returns the cached dcache line size in bytes; lazy-inits on first call. */
u32 uaccess_target_dcache_line_size(void);

/* Bracket cross-mm uaccess: inside the bracket, drv_copy_to_target_user / drv_copy_from_target_user route through @target_mm. @save_slot stores the previously-armed mm so the bracket can nest. */
void uaccess_target_arm(struct mm_struct *target_mm, struct mm_struct **save_slot);
void uaccess_target_disarm(struct mm_struct *prev);

/* TTBR0-swap uaccess wrappers, named to avoid colliding with the kernel's _copy_to_user / _copy_from_user static inlines in <linux/uaccess.h> (arm64 v6.6 sets INLINE_COPY_TO_USER / INLINE_COPY_FROM_USER). Route through the per-CPU armed-mm slot if set, else current->mm. Returns bytes NOT copied. */
unsigned long drv_copy_to_target_user(void __user *to, const void *from, unsigned long n);
unsigned long drv_copy_from_target_user(void *to, const void __user *from, unsigned long n);

/* One-shot uaccess from @target_mm. Internally: mask DAIF, load @target_mm->pgd into TTBR0_EL1 (ASID bits preserved in the high half of TTBR1_EL1 as the original binary does), ISB, call __arch_copy_*_user, restore TTBR0_EL1 to the reserved-zero-pgd trampoline page, unmask DAIF. Residue tail zeroed on partial copy_from. */
unsigned long copy_from_target_user(struct mm_struct *target_mm, void *dst, u64 src_va, unsigned long len);
unsigned long copy_to_target_user(struct mm_struct *target_mm, u64 dst_va, const void *src, unsigned long len);

/* copy_from_user with TLB drain + LDAPR-fenced walk; forces post-write_ro PTE update to retire before next uaccess. @walk_root is the page-walk root, pinned in x8 per the binary. */
size_t copy_from_user_tlb_drained(void *to, const void __user *from, size_t n, atomic64_t *walk_root);

/* BTI C landing pad before dispatch_ioctl in the binary; tail-calls into dispatch_ioctl. */
notrace long ioctl_entry(struct file *filp, unsigned int cmd, unsigned long arg);

#endif /* DRIVER_UACCESS_TARGET_H */
