// SPDX-License-Identifier: GPL-2.0
// TTBR0_EL1-swap uaccess wrappers.

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/irqflags.h>
#include <linux/mm_types.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/sysreg.h>

#include <driver/types.h>
#include <driver/uapi.h>

#include "comm.h"
#include "log.h"
#include "memory.h"
#include "uaccess_target.h"

/* GKI-6.6 user VA span (VA_BITS=39, T0SZ=25); LPA2 differs so do not use TASK_SIZE_MAX. */
#define UACCESS_TASK_SIZE_LIMIT 0x8000000000ULL

/* Strip bit 55 of a tagged user pointer (arm64 TBI canonical form). */
#define PAC_STRIP_MASK 0xFF7FFFFFFFFFFFFFULL

static u32 dcache_line_size;

/* Per-CPU armed-mm slot for the arm/disarm bracket API; one-shot variants bypass it. */
static DEFINE_PER_CPU(struct mm_struct *, uaccess_armed_mm);

void uaccess_target_init(void) {
	u64 ctr;

	if (READ_ONCE(dcache_line_size))
		return;

	ctr = read_sysreg(ctr_el0);
	WRITE_ONCE(dcache_line_size, 4U << ((u32)(ctr >> 16) & 0xFU));
}

u32 uaccess_target_dcache_line_size(void) {
	if (unlikely(!READ_ONCE(dcache_line_size)))
		uaccess_target_init();
	return READ_ONCE(dcache_line_size);
}

/* IRQs MUST be masked across this sequence — taking an exception with a half-programmed translation regime would fault. */
static __always_inline void uaccess_target_install_ttbr0(u64 ttbr0_val) {
	u64 ttbr1_low48;

	ttbr1_low48 = read_sysreg(ttbr1_el1) & 0xFFFFFFFFFFFFULL;
	write_sysreg((ttbr0_val & 0xFFFF000000000000ULL) | ttbr1_low48, ttbr1_el1);
	write_sysreg(ttbr0_val, ttbr0_el1);
	isb();
}

/* Reserved-zero-pgd page sits at(TTBR1_EL1 & 0xFFFFFFFFFFFF) - 0x1000 — arm64 KPTI trampoline. */
static __always_inline void uaccess_target_restore_reserved_ttbr0(void) {
	u64 ttbr1_low48 = read_sysreg(ttbr1_el1) & 0xFFFFFFFFFFFFULL;

	write_sysreg(ttbr1_low48 - 0x1000ULL, ttbr0_el1);
	write_sysreg(ttbr1_low48, ttbr1_el1);
	isb();
}

/* On non-KPTI the user pgd remains on TTBR0_EL1 in kernel mode, so the swap is a no-op. arm64_kernel_unmapped_at_el0 is a `static inline bool` helper in <asm/mmu.h>, not a macro — call it at runtime. */
static __always_inline bool uaccess_target_need_ttbr_swap(void) {
	return arm64_kernel_unmapped_at_el0();
}

static __always_inline u64 uaccess_target_strip_tag(u64 ptr) {
	/* Sign-extend bit 55 across the top byte; arm64 TBI canonical form. */
	return (u64)(((s64)(ptr << 8)) >> 8) & ptr;
}

static __always_inline u64 uaccess_target_ttbr0_for_mm(struct mm_struct *mm) {
	u64 pgd_phys = virt_to_phys(mm->pgd);
	u64 asid = (u64)atomic64_read(&mm->context.id) & 0xFFFFULL;

	return (asid << 48) | pgd_phys;
}

/* Resolve the mm whose pgd should be loaded into TTBR0_EL1: prefer the per-CPU armed slot (set by uaccess_target_arm), fall back to current->mm. Returns NULL only for kthreads with no active_mm — caller must refuse the copy in that case. */
static __always_inline struct mm_struct *uaccess_target_resolve_mm(void) {
	struct mm_struct *mm;

	mm = this_cpu_read(uaccess_armed_mm);
	if (mm)
		return mm;

	mm = current->mm;
	if (!mm)
		mm = current->active_mm;
	return mm;
}

unsigned long drv_copy_to_target_user(void __user *to, const void *from, unsigned long n) {
	unsigned long flags;
	struct mm_struct *target_mm;
	u64 ttbr0_val;
	u64 dst = (u64)to;
	u64 dst_for_check;
	bool need_swap;

	if (n > UACCESS_TASK_SIZE_LIMIT)
		return n;

	dst_for_check = uaccess_target_strip_tag(dst);
	if (UACCESS_TASK_SIZE_LIMIT - n < dst_for_check)
		return n;

	target_mm = uaccess_target_resolve_mm();
	if (!target_mm)
		return n;

	need_swap = uaccess_target_need_ttbr_swap();

	/* Single bracket: mask IRQs BEFORE the TTBR0 swap and unmask AFTER restoring TTBR0, so a preempt/IRQ mid-copy cannot reprogram TTBR0_EL1 out from under us. */
	if (need_swap) {
		ttbr0_val = uaccess_target_ttbr0_for_mm(target_mm);
		local_irq_save(flags);
		uaccess_target_install_ttbr0(ttbr0_val);
	}

	n = __arch_copy_to_user((void __user *)(dst & PAC_STRIP_MASK), from, n);

	if (need_swap) {
		uaccess_target_restore_reserved_ttbr0();
		local_irq_restore(flags);
	}

	return n;
}

unsigned long drv_copy_from_target_user(void *to, const void __user *from, unsigned long n) {
	unsigned long flags;
	unsigned long residue = n;
	struct mm_struct *target_mm;
	u64 ttbr0_val;
	u64 src = (u64)from;
	u64 src_for_check;
	bool need_swap;

	if (n > UACCESS_TASK_SIZE_LIMIT)
		goto zero_tail;

	src_for_check = uaccess_target_strip_tag(src);
	if (UACCESS_TASK_SIZE_LIMIT - n < src_for_check)
		goto zero_tail;

	target_mm = uaccess_target_resolve_mm();
	if (!target_mm)
		goto zero_tail;

	need_swap = uaccess_target_need_ttbr_swap();

	/* Single bracket: mask IRQs BEFORE the TTBR0 swap and unmask AFTER restoring TTBR0. */
	if (need_swap) {
		ttbr0_val = uaccess_target_ttbr0_for_mm(target_mm);
		local_irq_save(flags);
		uaccess_target_install_ttbr0(ttbr0_val);
	}

	residue = __arch_copy_from_user(to, (const void __user *)(src & PAC_STRIP_MASK), n);

	if (need_swap) {
		uaccess_target_restore_reserved_ttbr0();
		local_irq_restore(flags);
	}

zero_tail:
	/* post-5.7 copy_from_user contract: zero the residue tail. */
	if (residue != 0)
		memset((u8 *)to + n - residue, 0, residue);
	return residue;
}

/* copy_from_user with TLB drain + acquire-load fenced walk; forces post-write_ro PTE update to retire before next uaccess. @walk_root is the page-walk root, pinned in x8 per the binary. */
size_t copy_from_user_tlb_drained(void *to, const void __user *from, size_t n, atomic64_t *walk_root) {
	register unsigned long _x8 __asm__("x8") = (unsigned long)walk_root;
	unsigned long sink;

	asm volatile(
		"dsb    ish\n\t"
		"tlbi   vmalle1is\n\t"
		"ldar   %[s], [%[r]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"dsb    ish\n\t"
		"tlbi   vaale1is, %[r]\n\t"
		"ldar   %[s], [%[r]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"ldar   %[s], [%[r]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"ldar   %[s], [%[r]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"ldar   %[s], [%[r]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"ldar   %[s], [%[r]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"ldar   %[s], [%[s]]\n\t"
		"dsb    ish\n\t"
		"isb"
		: [s] "=&r"(sink)
		: [r] "r"(_x8)
		: "memory");

	return drv_copy_from_target_user(to, from, n);
}

/* BTI C landing pad before dispatch_ioctl in the binary; notrace+used emits the equivalent tail call. */
notrace long ioctl_entry(struct file *filp, unsigned int cmd, unsigned long arg) {
	return dispatch_ioctl(filp, cmd, arg);
}

void uaccess_target_arm(struct mm_struct *target_mm, struct mm_struct **save_slot) {
	struct mm_struct **slot;

	preempt_disable();
	slot = this_cpu_ptr(&uaccess_armed_mm);
	if (save_slot)
		*save_slot = *slot;
	*slot = target_mm;
	preempt_enable();
}

void uaccess_target_disarm(struct mm_struct *prev) {
	struct mm_struct **slot;

	preempt_disable();
	slot = this_cpu_ptr(&uaccess_armed_mm);
	*slot = prev;
	preempt_enable();
}

unsigned long copy_from_target_user(struct mm_struct *target_mm, void *dst, u64 src_va, unsigned long len) {
	unsigned long flags;
	unsigned long residue = len;
	u64 ttbr0_val;
	u64 src_for_check = src_va;

	if (!target_mm || !dst)
		return len;

	if (len > UACCESS_TASK_SIZE_LIMIT)
		return len;

	if (UACCESS_TASK_SIZE_LIMIT - len < src_for_check)
		return len;

	ttbr0_val = uaccess_target_ttbr0_for_mm(target_mm);

	local_irq_save(flags);
	uaccess_target_install_ttbr0(ttbr0_val);
	residue = __arch_copy_from_user(dst, (const void __user *)(src_va & PAC_STRIP_MASK), len);
	uaccess_target_restore_reserved_ttbr0();
	local_irq_restore(flags);

	if (residue != 0)
		memset((u8 *)dst + len - residue, 0, residue);
	return residue;
}

unsigned long copy_to_target_user(struct mm_struct *target_mm, u64 dst_va, const void *src, unsigned long len) {
	unsigned long flags;
	unsigned long residue;
	u64 ttbr0_val;
	u64 dst_for_check = dst_va;

	if (!target_mm || !src)
		return len;

	if (len > UACCESS_TASK_SIZE_LIMIT)
		return len;

	if (UACCESS_TASK_SIZE_LIMIT - len < dst_for_check)
		return len;

	ttbr0_val = uaccess_target_ttbr0_for_mm(target_mm);

	local_irq_save(flags);
	uaccess_target_install_ttbr0(ttbr0_val);
	residue = __arch_copy_to_user((void __user *)(dst_va & PAC_STRIP_MASK), src, len);
	uaccess_target_restore_reserved_ttbr0();
	local_irq_restore(flags);

	return residue;
}
