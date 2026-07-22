// SPDX-License-Identifier: GPL-2.0-only
// process memory primitives: pagewalk, linear/vmap copy, RO patcher, VMA walkers.

#include <linux/atomic.h>
#include <linux/cpufeature.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <linux/maple_tree.h>
#endif
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/mmzone.h>
#include <linux/numa.h>
#include <linux/path.h>
#include <linux/pgtable.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/memory.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pointer_auth.h>
#include <asm/processor.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>

#include <driver/types.h>
#include <driver/uapi.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif
#ifndef __nocfi
#define __nocfi
#endif

#include "kallsym.h"
#include "log.h"
#include "memory.h"
#include "uaccess_target.h"

/* ARM64 pagewalk arithmetic. PA extraction uses the kernel's own primitives
 * (__pte_to_phys, PHYS_MASK) so the driver is correct across
 * CONFIG_ARM64_PA_BITS_48 (GKI default) and CONFIG_ARM64_PA_BITS_52 (LPA2)
 * without per-version literals. PAGE_OFFSET is intentionally NOT hardcoded;
 * phys_to_virt() honours vabits_actual. */
/* Strip ARMv8 TBI / PAC byte from a user VA before handing to uaccess. */
#define DRV_TBI_PAC_STRIP_MASK 0xFF7FFFFFFFFFFFFFULL
/* write_ro_memory PTE bit-flip: clear PTE_RDONLY(bit 7), set PTE_DBM(bit 51). */
#define DRV_PTE_RDONLY_CLEAR 0xFFF7FFFFFFFFFF7FULL
#define DRV_PTE_DBM_SET 0x0008000000000000ULL

/* Two distinct dcache-line caches — one for linear-map, one for vmap. */
static u32 dcache_line_size_linear;
static u32 dcache_line_size_vmap;

/* Resolved once at module init via kallsym_lookup. The kernel's own
   self-modifying-text primitive: installs the target PFN in FIX_TEXT_POKE0
   (a single fixmap page, allocated WITHOUT PTE_CONT by construction),
   writes the u32 through the RW fixmap alias, performs the architectural
   caches_clean_inval_pou + broadcast IS TLBI, then tears the fixmap down.
   Eliminates the contig-block BBM hazard that broke the bespoke PTE-flip
   path on Android 15 / 6.6 GKI (kernel .text is mapped with PTE_CONT, so a
   per-VA TLBI cannot evict the 64 KiB amalgamated TLB entry — see pstore
   evidence: pte=0x00580000A90D0703 has bit 7=0 (writable per our flip), bit
   51=1 (DBM set), and bit 52=1 (PTE_CONT) — the in-memory leaf was correct
   but the TLB held a stale RO entry tagged with a sibling VA in the contig
   group). The same primitive is used by ftrace, jump_label, static_call,
   KernelPatch, and KernelSU. */
typedef int (*drv_insn_patch_text_nosync_fn_t)(void *addr, u32 insn);
static drv_insn_patch_text_nosync_fn_t drv_insn_patch_text_nosync;

/* get_cmdline() has kept this signature across every supported Android GKI
 * (5.10 through 6.12), but is not consistently exported to GKI modules.
 * Resolve it once through the driver's existing kallsyms bridge so
 * modpost/KMI allowlists do not gain a version-specific dependency. */
typedef int (*drv_get_cmdline_fn_t)(struct task_struct *task, char *buffer, int buflen);
static drv_get_cmdline_fn_t drv_get_cmdline;

/* CFI-safe trampoline — mirrors kallsym_call_resolved in kallsym.c. The
   kallsyms-resolved address was not built with caller-side CFI metadata
   matching this typedef, so the indirect call must bypass kCFI. */
static __nocfi int drv_call_insn_patch_text_nosync(drv_insn_patch_text_nosync_fn_t fn, void *addr, u32 insn) {
	return fn(addr, insn);
}

static noinline __nocfi int drv_call_get_cmdline(drv_get_cmdline_fn_t fn,
						  struct task_struct *task,
						  char *buffer, int buflen) {
	return fn(task, buffer, buflen);
}

int memory_init(void) {
	unsigned long addr;

	addr = kallsym_lookup("aarch64_insn_patch_text_nosync");
	if (!addr) {
#if PAGE_SHIFT == 12
		if (drv.m_page_level >= 3 && drv.m_page_level <= 4)
			pr_drv_warn("memory_init: aarch64_insn_patch_text_nosync not in kallsyms; using legacy PTE-flip fallback (unsafe on PTE_CONT-mapped text)\n");
		else
			pr_drv_warn("memory_init: aarch64_insn_patch_text_nosync not in kallsyms; legacy PTE-flip is disabled for page-table depth %u\n",
				    drv.m_page_level);
#else
		pr_drv_warn("memory_init: aarch64_insn_patch_text_nosync not in kallsyms; legacy PTE-flip is disabled for PAGE_SHIFT=%u\n",
			    (unsigned int)PAGE_SHIFT);
#endif
	} else {
		drv_insn_patch_text_nosync = (drv_insn_patch_text_nosync_fn_t)addr;
	}

	addr = kallsym_lookup("get_cmdline");
	if (!addr) {
		pr_drv_warn("memory_init: get_cmdline not in kallsyms; package lookup disabled\n");
	} else {
		drv_get_cmdline = (drv_get_cmdline_fn_t)addr;
	}

	return 0;
}

/* phys_to_virt() lives in <asm/memory.h>; honours vabits_actual so the linear-map VA is correct on every supported KMI without per-version PAGE_OFFSET constants. */

static inline u32 drv_ctr_dcache_line_size(void) {
	u64 ctr = read_sysreg(ctr_el0);

	/* CTR_EL0[19:16] = log2(DminLine in words); one word == 4 bytes. */
	return 4u << ((ctr >> 16) & 0xFu);
}

static void drv_flush_dcache_range(u64 va, size_t len, u32 *cache_slot) {
	u64 end, line, line_size, p;

	if (*cache_slot == 0)
		*cache_slot = drv_ctr_dcache_line_size();
	line_size = *cache_slot;

	dmb(ish);
	dsb(ish);
	isb();

	if (va > 0xFFFFFFFFFFFFEFFFULL)
		return;

	line = va & ~(u64)(line_size - 1);
	end = (va + len + line_size - 1) & ~(u64)(line_size - 1);

	/* Double DC CIVAC per line is paranoid but matches the original 1:1. */
	for (p = line; p < end; p += line_size) {
		asm volatile("dc civac, %0" :: "r"(p) : "memory");
		dmb(ish);
		dsb(ish);
		isb();
		asm volatile("dc civac, %0" :: "r"(p) : "memory");
		dmb(ish);
		dsb(ish);
		isb();
	}

	dmb(ish);
	dsb(ish);
	isb();
}

static inline u64 drv_lm_va_from_phys(u64 phys) {
	/* Page-align; phys_to_virt() handles vabits_actual + CONFIG_ARM64_PA_BITS internally. */
	return (u64)(uintptr_t)phys_to_virt(phys & PAGE_MASK);
}

/* Canonical pagewalk: caller holds mmap_read_lock(mm). Folded levels are
 * handled by the kernel helpers; PUD/PMD leaves use the configured granule's
 * block sizes. pte_offset_kernel avoids the 6.5 failable/RCU map API rework. */
int vaddr_to_phys(struct mm_struct *mm, u64 va, u64 *out_phys) {
	unsigned long addr = (unsigned long)va;
	unsigned long pfn;
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;
	pgd_t pgd;
	p4d_t p4d;
	pud_t pud;
	pmd_t pmd;
	pte_t pte;

	if (!mm || !out_phys)
		return -EFAULT;

	if (!mm->pgd)
		return -EFAULT;

	/* The caller holds mmap_read_lock(mm). Read each descriptor once so the
	 * validation and PA extraction use the same hardware-updatable value.
	 * Folded levels become passthroughs on the relevant arm64 configs. */
	pgdp = pgd_offset(mm, addr);
	pgd = READ_ONCE(*pgdp);
	if (pgd_none(pgd) || pgd_bad(pgd))
		return -EFAULT;

	p4dp = p4d_offset(pgdp, addr);
	p4d = READ_ONCE(*p4dp);
	if (p4d_none(p4d) || p4d_bad(p4d))
		return -EFAULT;

	pudp = pud_offset(p4dp, addr);
	pud = READ_ONCE(*pudp);
	if (pud_none(pud))
		return -EFAULT;

	/* A valid arm64 block descriptor is not a next-level table descriptor,
	 * so pud_bad()/pmd_bad() report it as bad. Test leaves first and add the
	 * base-page index inside the complete block mapping. */
	if (pud_leaf(pud)) {
		if (!pud_present(pud))
			return -EFAULT;
		pfn = pud_pfn(pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
		goto resolved;
	}
	if (pud_bad(pud))
		return -EFAULT;

	pmdp = pmd_offset(pudp, addr);
	pmd = READ_ONCE(*pmdp);
	if (pmd_none(pmd))
		return -EFAULT;
	if (pmd_leaf(pmd)) {
		if (!pmd_present(pmd))
			return -EFAULT;
		pfn = pmd_pfn(pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
		goto resolved;
	}
	if (pmd_bad(pmd))
		return -EFAULT;

	/* arm64 has no highmem page-table pages. Keep pte_offset_kernel() here to
	 * avoid the failable pte_offset_map() API transition in Linux 6.5. */
	ptep = pte_offset_kernel(pmdp, addr);
	if (!ptep)
		return -EFAULT;

	pte = READ_ONCE(*ptep);
	if (!pte_present(pte))
		return -EFAULT;
	pfn = pte_pfn(pte);

resolved:
	if (!pfn_valid(pfn))
		return -EOPNOTSUPP;

	*out_phys = ((u64)pfn << PAGE_SHIFT) | offset_in_page(va);
	return 0;
}

/* Reject obviously-bogus user pointers via the kernel's per-task access_ok().
 *
 * Replaces the hand-rolled `(DRV_TASK_SIZE_64 - size) >= ptr` guard that used a
 * baked-in 0x8000000000 (39-bit VA) constant.  When the caller's buffer sat in
 * the top of the 39-bit user VA — exactly where arm64 main-thread stacks live —
 * adding a multi-MiB length crossed the constant and the guard silently rejected
 * valid buffers, leaving DRV_CMD_READ_MEM_* returning size_back=0 with no error
 * propagated past comm.c.  access_ok() consults TASK_SIZE_MAX (vabits_actual)
 * and matches whatever VA layout the running kernel actually uses. */
static inline bool drv_user_ptr_in_range(u64 ptr, u64 size) {
	return access_ok((const void __user *)(uintptr_t)ptr, (size_t)size);
}

int read_process_memory_linear(struct mm_struct *target_mm, u64 target_va, void *local_kbuf, size_t len) {
	u64 user_dst;
	size_t remain = len;

	if (!target_mm || !local_kbuf || len == 0)
		return 0;

	user_dst = (u64)(uintptr_t)local_kbuf;
	if (!drv_user_ptr_in_range(user_dst, len))
		return -EFAULT;

	mmap_read_lock(target_mm);
	while (remain) {
		u64 phys, lm_va;
		size_t off = offset_in_page(target_va);
		size_t chunk = min_t(size_t, remain, PAGE_SIZE - off);

		if (vaddr_to_phys(target_mm, target_va, &phys) != 0)
			goto skip;

		lm_va = drv_lm_va_from_phys(phys);

		/* drv_lm_va_from_phys returns the page-aligned linear-map VA;
		 * the in-page offset must be re-added here. The previous code
		 * silently copied from the start of every source page, hiding
		 * the bug behind write-then-read tests (both sides skipped the
		 * offset and matched) but breaking MULTI_READ which honoured it. */
		if (copy_to_user((void __user *)(uintptr_t)user_dst,
		                 (const void *)(uintptr_t)lm_va + off, chunk) != 0)
			pr_drv_err("copy_to_user failed: %s\n", __func__);

		/* No dcache maintenance here. Pure data reads through the linear-map
		 * alias are CPU-coherent — copy_to_user's uaccess epilogue drains the
		 * store buffer for the destination, and the linear-map and user view
		 * of the source page are the same physical line on a coherent ARMv8
		 * SoC. The DC CIVAC ladder is only required when the source has been
		 * mutated as data and will be fetched as instructions (write_ro_memory
		 * / hook installation) — which has its own cache-maintenance step in
		 * hook_engine.c. Removing the per-page flush gives ~8× speedup on
		 * bulk reads (per drv_bench: 1 MiB 9.5 ms → ~1.1 ms). */

skip:
		remain -= chunk;
		target_va += chunk;
		user_dst += chunk;
	}
	mmap_read_unlock(target_mm);
	return 0;
}

int write_process_memory_linear(struct mm_struct *target_mm, u64 target_va, const void *local_kbuf, size_t len) {
	u64 user_src;
	size_t remain = len;
	bool copy_failed = false;

	if (!target_mm)
		return -EINVAL;
	if (len == 0)
		return 0;
	if (!local_kbuf)
		return -EFAULT;
	target_va = (u64)untagged_addr(target_va);
	if (target_va >= (u64)target_mm->task_size ||
	    (u64)len > (u64)target_mm->task_size - target_va)
		return -EFAULT;

	user_src = (u64)(uintptr_t)local_kbuf;
	if (!drv_user_ptr_in_range(user_src, len))
		return -EFAULT;

	mmap_read_lock(target_mm);
	while (remain) {
		u64 phys, lm_va;
		size_t off = offset_in_page(target_va);
		size_t chunk = min_t(size_t, remain, PAGE_SIZE - off);

		if (vaddr_to_phys(target_mm, target_va, &phys) != 0)
			goto skip;

		lm_va = drv_lm_va_from_phys(phys);

		if (copy_from_user((void *)(uintptr_t)lm_va + off,
		                   (const void __user *)(uintptr_t)user_src, chunk) != 0 &&
		    !copy_failed) {
			pr_drv_err("copy_from_user failed: %s\n", __func__);
			copy_failed = true;
		}
skip:
		remain -= chunk;
		target_va += chunk;
		user_src += chunk;
	}
	mmap_read_unlock(target_mm);
	return 0;
}

int read_process_memory_vmap(struct mm_struct *target_mm, u64 target_va, void *local_kbuf, size_t len) {
	u64 user_dst;
	size_t remain = len;

	if (!target_mm || !local_kbuf || len == 0)
		return 0;

	user_dst = (u64)(uintptr_t)local_kbuf;
	if (!drv_user_ptr_in_range(user_dst, len))
		return -EFAULT;

	mmap_read_lock(target_mm);
	while (remain) {
		u64 phys;
		struct page *pages[1];
		void *mapped;
		size_t off = offset_in_page(target_va);
		size_t chunk = min_t(size_t, remain, PAGE_SIZE - off);

		if (vaddr_to_phys(target_mm, target_va, &phys) != 0)
			goto skip;

		if (!pfn_valid(phys >> PAGE_SHIFT))
			goto skip;

		pages[0] = pfn_to_page(phys >> PAGE_SHIFT);
		if (!pages[0])
			goto skip;

		/* Let the running arm64 kernel provide the correct writable mapping
		 * attributes (including its KPTI nG policy). */
		mapped = vmap(pages, 1, VM_MAP, PAGE_KERNEL);
		if (!mapped)
			goto skip;

		/* See read_process_memory_linear for why the DC CIVAC ladder is gone. */

		if (copy_to_user((void __user *)(uintptr_t)user_dst, (char *)mapped + off, chunk) != 0)
			pr_drv_err("copy_to_user failed: %s\n", __func__);

		vunmap(mapped);
skip:
		remain -= chunk;
		target_va += chunk;
		user_dst += chunk;
	}
	mmap_read_unlock(target_mm);
	return 0;
}

int write_process_memory_vmap(struct mm_struct *target_mm, u64 target_va, const void *local_kbuf, size_t len) {
	u64 user_src;
	size_t remain = len;
	bool copy_failed = false;

	if (!target_mm)
		return -EINVAL;
	if (len == 0)
		return 0;
	if (!local_kbuf)
		return -EFAULT;
	target_va = (u64)untagged_addr(target_va);
	if (target_va >= (u64)target_mm->task_size ||
	    (u64)len > (u64)target_mm->task_size - target_va)
		return -EFAULT;

	user_src = (u64)(uintptr_t)local_kbuf;
	if (!drv_user_ptr_in_range(user_src, len))
		return -EFAULT;

	mmap_read_lock(target_mm);
	while (remain) {
		u64 phys;
		struct page *pages[1];
		void *mapped;
		size_t off = offset_in_page(target_va);
		size_t chunk = min_t(size_t, remain, PAGE_SIZE - off);

		if (vaddr_to_phys(target_mm, target_va, &phys) != 0)
			goto skip;

		if (!pfn_valid(phys >> PAGE_SHIFT))
			goto skip;

		pages[0] = pfn_to_page(phys >> PAGE_SHIFT);
		if (!pages[0])
			goto skip;

		mapped = vmap(pages, 1, VM_MAP, PAGE_KERNEL);
		if (!mapped)
			goto skip;

		if (copy_from_user((char *)mapped + off,
		                   (const void __user *)(uintptr_t)user_src, chunk) != 0 &&
		    !copy_failed) {
			pr_drv_err("copy_from_user failed: %s\n", __func__);
			copy_failed = true;
		}
		vunmap(mapped);
skip:
		remain -= chunk;
		target_va += chunk;
		user_src += chunk;
	}
	mmap_read_unlock(target_mm);
	return 0;
}

/* Write path routes through write_ro_memory so RO sections become writable. */
int kernel_rw(u64 kva, void *buf, size_t len, int do_write) {
	if (!buf || !len)
		return -EINVAL;

	if (do_write) {
		write_ro_memory(kva, buf, len);
		return 0;
	}

	memcpy(buf, (void *)(uintptr_t)kva, len);
	return 0;
}

#define DRV_MULTI_READ_MAX_COUNT 4096u   /* hard ceiling so attacker-controlled
                                           count cannot DoS the system via a
                                           ~96 KiB+ kvmalloc staging spike. */

int multi_read_process_memory(struct mm_struct *target_mm, void __user *descs, unsigned int count) {
	struct drv_multi_read_req *staging;
	size_t bytes;
	unsigned int i;

	if (!target_mm || !descs || !count || count > DRV_MULTI_READ_MAX_COUNT)
		return -EINVAL;

	bytes = (size_t)count * sizeof(*staging);
	staging = kvmalloc_node(bytes, GFP_KERNEL_ACCOUNT, NUMA_NO_NODE);
	if (!staging)
		return -ENOMEM;

	if (copy_from_user(staging, descs, bytes) != 0) {
		kvfree(staging);
		return -EFAULT;
	}

	mmap_read_lock(target_mm);
	for (i = 0; i < count; i++) {
		u64 src_va = staging[i].src_va;
		u64 user_dst = staging[i].user_dst;
		size_t len = staging[i].len;
		size_t remain = len;

		if (!len)
			continue;

		while (remain) {
			u64 phys, lm_va;
			size_t off = offset_in_page(src_va);
			size_t chunk = min_t(size_t, remain, PAGE_SIZE - off);

			if (vaddr_to_phys(target_mm, src_va, &phys) != 0)
				goto next;

			/* Linear-map alias (same primitive read_process_memory_linear uses).
			 * The page-aligned lm_va must be offset back to the actual source
			 * byte via `+ off`. The earlier vmap+pfn_valid path failed silently
			 * on vendor kernels where anonymous user pages didn't pass pfn_valid. */
			lm_va = drv_lm_va_from_phys(phys);

			(void)copy_to_user((void __user *)(uintptr_t)user_dst,
			                   (const void *)(uintptr_t)lm_va + off, chunk);
next:
			remain -= chunk;
			src_va += chunk;
			user_dst += chunk;
		}
	}
	mmap_read_unlock(target_mm);

	kvfree(staging);
	return 1;
}

#if PAGE_SHIFT == 12
/* Legacy bespoke RO patcher: walks drv.m_pgd_va, flips PTE_RDONLY/PTE_DBM
   around a byte copy, restores. Verbatim 1:1 with the original .ko. UNSAFE
   on PTE_CONT-mapped text (Android 15 / 6.6 GKI maps kernel .text with the
   contiguous hint — a per-VA TLBI cannot evict the amalgamated 64 KiB TLB
   entry). Kept as the fallback path when aarch64_insn_patch_text_nosync is
   not resolvable via kallsyms. Reachable today only on stripped kernels or
   for byte-granular non-CONT writes on legacy KMIs. */
static u64 write_ro_memory_pte_flip(u64 dst_kva, const void *src, u64 len) {
	u64 result = dst_kva;
	const u8 *end = (const u8 *)(uintptr_t)dst_kva + len;
	long diff = (long)(uintptr_t)src - (long)result;

	if (end <= (const u8 *)(uintptr_t)result)
		return result;

	while (result < (u64)(uintptr_t)end) {
		u64 *leaf = NULL;
		u64 page_remain = PAGE_SIZE - offset_in_page(result);
		u64 chunk = min_t(u64, page_remain, (u64)(uintptr_t)end - result);
		unsigned int level_start;
		unsigned int level_count = drv.m_page_level;
		u64 saved_pte;
		u64 i;

		if (level_count < 3 || level_count > 4) {
			/* The module remains usable on LPA2, but this legacy fallback
			 * only understands the 3/4-level 4 KiB format. Abort before
			 * dereferencing the captured root on any other depth. */
			pr_drv_err("write_ro_memory_pte_flip: unexpected page level %u; aborting\n", level_count);
			return result;
		}

		/* shift = 39 - 9*(4 - m_page_level); for m_page_level=3 that's 39, 30, 21, 12. */
		level_start = (4u - level_count);
		{
			u8 mask_width = 9 * (4 - level_count) + 9;
			u8 shift = 39 - 9 * (4 - level_count);
			u64 table = drv.m_pgd_va;
			unsigned int lvl;

			for (lvl = level_start; lvl < 4; lvl++) {
				u64 *entry = (u64 *)(uintptr_t)(table + 8 * ((result >> shift) & 0x1FF));
				u64 e;
				u64 next_pa;

				if (!entry) {
					leaf = NULL;
					break;
				}
				leaf = entry;
				e = *entry;

				if ((e & 3) == 1) {
					/* Block (hugepage) leaf — only valid at non-final levels. */
					if (lvl + 1 != 4)
						break;
					next_pa = e & (~(-1LL << mask_width) << shift);
				} else if ((e & 3) == 3) {
					/* Table descriptor — OA encoding is identical to a PTE
					 * leaf, so reuse the kernel's own PA extractor. Correct
					 * across PA_BITS_48/52 unlike a hand-rolled bit mask. */
					next_pa = (u64)__pte_to_phys(__pte(e));
				} else {
					leaf = NULL;
					break;
				}

				table = (u64)(uintptr_t)phys_to_virt(next_pa);
				mask_width += 9;
				shift -= 9;
			}
		}

		if (!leaf) {
			result += chunk;
			continue;
		}

		saved_pte = *leaf;
		*leaf = (saved_pte & DRV_PTE_RDONLY_CLEAR) | DRV_PTE_DBM_SET;

		dsb(ishst);
		asm volatile("tlbi vaae1is, %0" :: "r"(result >> PAGE_SHIFT) : "memory");
		dsb(ish);
		isb();

		for (i = 0; i < chunk; i++) {
			u8 *dst = (u8 *)(uintptr_t)(result + i);
			*dst = ((const u8 *)dst)[diff];
		}

		dsb(ish);
		asm volatile("ic ialluis" ::: "memory");
		dsb(ish);
		isb();

		*leaf = saved_pte;

		dsb(ishst);
		asm volatile("tlbi vaae1is, %0" :: "r"(result >> PAGE_SHIFT) : "memory");
		dsb(ish);
		isb();

		result += chunk;
	}

	return result;
}
#else
/* The legacy walker hard-codes a 9-bit index per level, which is only valid
 * for a 4 KiB arm64 granule. Keep the normal vmap/linear-map paths available
 * on 16/64 KiB kernels, but never mutate a guessed kernel page-table entry. */
static u64 write_ro_memory_pte_flip(u64 dst_kva, const void *src, u64 len) {
	(void)src;
	(void)len;
	pr_drv_err("write_ro_memory: legacy PTE-flip unavailable for PAGE_SHIFT=%u\n",
		   (unsigned int)PAGE_SHIFT);
	return dst_kva;
}
#endif

/* Patch kernel text. Fast path: aarch64_insn_patch_text_nosync (resolved
   once at init via kallsym_lookup) — routes the write through FIX_TEXT_POKE0
   (a non-CONT fixmap slot) + caches_clean_inval_pou + broadcast IS TLBI.
   Architecturally safe on PTE_CONT-mapped kernel text.

   Fallback: legacy bespoke PTE-flip when the kernel symbol is not in
   kallsyms (downgraded KMI, stripped kernel) or when caller hands unaligned
   data. In-tree callers (hook_install / hook_remove) always pass 4-byte
   aligned dst (function entry), 4-byte aligned src (u32 tramp_insts[]), and
   a 4-byte-multiple len, so the fast path is taken in production. */
u64 write_ro_memory(u64 dst_kva, const void *src, u64 len) {
	drv_insn_patch_text_nosync_fn_t patch = READ_ONCE(drv_insn_patch_text_nosync);
	const u32 *src_u32;
	u64 i, words;

	if (len == 0)
		return dst_kva;

	if (!patch || (dst_kva & 3u) || ((uintptr_t)src & 3u) || (len & 3u))
		return write_ro_memory_pte_flip(dst_kva, src, len);

	src_u32 = (const u32 *)src;
	words = len >> 2;
	for (i = 0; i < words; i++) {
		u32 insn;

		memcpy(&insn, &src_u32[i], sizeof(insn));
		if (drv_call_insn_patch_text_nosync(patch, (void *)(uintptr_t)(dst_kva + (i << 2)), insn)) {
			pr_drv_err("write_ro_memory: aarch64_insn_patch_text_nosync(%llx) failed\n",
				   (unsigned long long)(dst_kva + (i << 2)));
			break;
		}
	}
	return dst_kva + (i << 2);
}

u64 process_get_module_base(struct task_struct *task, const char *module_name) {
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	u64 result = 0;

	if (!task || !module_name || !module_name[0])
		return 0;

	mm = get_task_mm(task);
	if (!mm)
		return 0;

	mmap_read_lock(mm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	{
		VMA_ITERATOR(vmi, mm, 0);
		for_each_vma(vmi, vma) {
#else
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
		struct file *file = vma->vm_file;
		const char *name;

		if (!file)
			continue;
		if (!file->f_path.dentry)
			continue;

		name = file->f_path.dentry->d_name.name;
		if (!name || !name[0])
			continue;

		if (strcmp(name, module_name) == 0) {
			result = (u64)vma->vm_start;
			break;
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	}
#endif

	mmap_read_unlock(mm);
	mmput(mm);
	return result;
}

/* Also searches non-leader threads; caller must put_task_struct() on success. */
struct task_struct *process_find_task_by_comm(const char *comm) {
	struct task_struct *p, *t;

	if (!comm || !comm[0])
		return NULL;

	rcu_read_lock();
	for_each_process(p) {
		for_each_thread(p, t) {
			if (strncmp(t->comm, comm, sizeof(t->comm)) == 0) {
				get_task_struct(t);
				rcu_read_unlock();
				return t;
			}
		}
	}
	rcu_read_unlock();
	return NULL;
}

/* A pathological process storm must not turn one ioctl into an unbounded
 * allocation. Android devices normally have hundreds of process leaders;
 * 65,536 still leaves ample headroom while bounding the snapshot at 512 KiB
 * on arm64. */
#define DRV_PROCESS_SNAPSHOT_MAX 65536u

static int process_snapshot_tasks(struct task_struct ***out_tasks,
					  size_t *out_count) {
	struct task_struct **tasks;
	struct task_struct *p;
	size_t capacity = 0;
	size_t count = 0;
	size_t i;
	bool overflow = false;

	if (!out_tasks || !out_count)
		return -EINVAL;

	*out_tasks = NULL;
	*out_count = 0;

	/* First pass only sizes the allocation. No sleeping operation is allowed
	 * while walking the RCU-protected global task list. */
	rcu_read_lock();
	for_each_process(p) {
		if (capacity == DRV_PROCESS_SNAPSHOT_MAX) {
			overflow = true;
			break;
		}
		capacity++;
	}
	rcu_read_unlock();

	if (overflow)
		return -E2BIG;
	if (!capacity)
		return 0;

	tasks = kvmalloc_array(capacity, sizeof(*tasks), GFP_KERNEL);
	if (!tasks)
		return -ENOMEM;

	/* A second short RCU pass pins each leader. get_cmdline() is deliberately
	 * deferred until after rcu_read_unlock() because it may take mmap locks
	 * and sleep through access_process_vm(). */
	overflow = false;
	rcu_read_lock();
	for_each_process(p) {
		if (count == capacity) {
			overflow = true;
			break;
		}
		get_task_struct(p);
		tasks[count++] = p;
	}
	rcu_read_unlock();

	if (overflow) {
		for (i = 0; i < count; i++)
			put_task_struct(tasks[i]);
		kvfree(tasks);
		return -EAGAIN;
	}

	*out_tasks = tasks;
	*out_count = count;
	return 0;
}

int process_find_pid_by_package(const char *package, pid_t *out_pid) {
	struct task_struct **tasks = NULL;
	struct pid_namespace *pid_ns;
	char cmdline[DRV_PACKAGE_NAME_MAX + 1u];
	size_t package_len;
	size_t task_count = 0;
	size_t i;
	pid_t best_pid = 0;
	unsigned int attempt;
	int rc;

	if (!package || !out_pid)
		return -EINVAL;

	*out_pid = 0;
	package_len = strnlen(package, DRV_PACKAGE_NAME_MAX + 1u);
	if (!package_len)
		return -EINVAL;
	if (package_len > DRV_PACKAGE_NAME_MAX)
		return -ENAMETOOLONG;
	if (!drv_get_cmdline)
		return -EOPNOTSUPP;

	for (attempt = 0; attempt < 3; attempt++) {
		rc = process_snapshot_tasks(&tasks, &task_count);
		if (rc != -EAGAIN)
			break;
	}
	if (rc)
		return rc;

	pid_ns = task_active_pid_ns(current);
	for (i = 0; i < task_count; i++) {
		struct task_struct *task = tasks[i];
		size_t valid;
		size_t argv0_len;
		pid_t pid;
		int nread;

		nread = drv_call_get_cmdline(drv_get_cmdline, task, cmdline,
						     (int)sizeof(cmdline));
		if (nread > 0) {
			valid = min_t(size_t, (size_t)nread, sizeof(cmdline));
			argv0_len = strnlen(cmdline, valid);
			if (argv0_len == package_len &&
			    memcmp(cmdline, package, package_len) == 0) {
				pid = task_tgid_nr_ns(task, pid_ns);
				if (pid > 0 && (!best_pid || pid < best_pid))
					best_pid = pid;
			}
		}

		put_task_struct(task);
	}
	kvfree(tasks);

	if (!best_pid)
		return -ESRCH;

	*out_pid = best_pid;
	return 0;
}

int process_maps_get_a(struct task_struct *task, void __user *u_buf, size_t cap) {
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	u64 __user *u_ptr = u_buf;
	size_t emitted = 0;
	int rc = 0;

	if (!task || !u_buf || !cap)
		return -EINVAL;

	mm = get_task_mm(task);
	if (!mm)
		return -ESRCH;

	mmap_read_lock(mm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	{
		VMA_ITERATOR(vmi, mm, 0);
		for_each_vma(vmi, vma) {
#else
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
		struct {
			u64 start;
			u64 end;
		} rec;

		if (!vma->vm_file)
			continue;

		/* file-backed, not the main executable, pgoff == 0, VM_READ. */
		if (!(vma->vm_flags & VM_READ))
			continue;
		if (vma->vm_pgoff != 0)
			continue;
		if (vma->vm_start <= mm->start_code && vma->vm_end >= mm->end_code)
			continue;

		if (emitted + sizeof(rec) > cap)
			break;

		rec.start = (u64)vma->vm_start;
		rec.end = (u64)vma->vm_end;

		if (copy_to_user((void __user *)u_ptr, &rec, sizeof(rec)) != 0) {
			rc = -EFAULT;
			break;
		}

		u_ptr += 2;
		emitted += sizeof(rec);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	}
#endif

	mmap_read_unlock(mm);
	mmput(mm);
	return rc < 0 ? rc : (int)emitted;
}

u64 process_get_tls(struct task_struct *task) {
	if (!task)
		return 0;

	/* AArch32 compat tasks store tp_value in thread.uw.tp_value at the same field name — the per-arch struct already accounts for the layout shift. */
	return (u64)task->thread.uw.tp_value;
}

/* Read target APGA keys as a best-effort snapshot. */
int process_get_apga(struct task_struct *task, u64 *lo, u64 *hi) {
	if (!task || !lo || !hi)
		return -EINVAL;

#if IS_ENABLED(CONFIG_ARM64_PTR_AUTH)
	if (!system_supports_generic_auth())
		return -EOPNOTSUPP;
#if IS_ENABLED(CONFIG_COMPAT)
	if (is_compat_thread(task_thread_info(task)))
		return -EOPNOTSUPP;
#endif
	*lo = READ_ONCE(task->thread.keys_user.apga.lo);
	*hi = READ_ONCE(task->thread.keys_user.apga.hi);
	return 0;
#else
	*lo = 0;
	*hi = 0;
	return -EOPNOTSUPP;
#endif
}

/* DRV_CMD_READ_VMA_COOKIE walks the target's VMA tree, matches anon_vma_name
 * against the userspace-supplied needle, and returns the matching VMA's
 * start address as the canonical 64-bit cookie. The original .ko's raw
 * offsets (vma+344 for the name, vma+2008/+2016 for a cookie u64) walked
 * past the end of struct vm_area_struct into adjacent slab objects and
 * were UB on every kernel — replaced with the kernel's anon_vma_name() API
 * (CONFIG_ANON_VMA_NAME, available since 5.17) and vma->vm_start (stable on
 * every KMI).
 *
 * On kernels older than 5.17 OR where CONFIG_ANON_VMA_NAME is disabled
 * (default off on GKI Android 15 / 6.6), the feature is unavailable and
 * we return 0 (no match). */
u64 process_read_vma_cookie(struct task_struct *task, const char *needle) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) && IS_ENABLED(CONFIG_ANON_VMA_NAME)
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	u64 cookie = 0;
	size_t nlen;

	if (!task || !needle || !*needle)
		return 0;

	nlen = strnlen(needle, 80);

	mm = get_task_mm(task);
	if (!mm)
		return 0;

	mmap_read_lock(mm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	{
		VMA_ITERATOR(vmi, mm, 0);
		for_each_vma(vmi, vma) {
#else
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
		struct anon_vma_name *avn = anon_vma_name(vma);
		if (avn && strncmp(avn->name, needle, nlen) == 0 && avn->name[nlen] == '\0') {
			cookie = (u64)vma->vm_start;
			break;
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	}
#endif

	mmap_read_unlock(mm);
	mmput(mm);
	return cookie;
#else
	(void)task;
	(void)needle;
	return 0;
#endif
}

/* TTBR0-swap uaccess helpers live in uaccess_target.c (copy_to_target_user/copy_from_target_user). Use them for cross-mm copies; for copies against `current`'s userspace, fall back to the kernel-provided copy_to_user / copy_from_user. */
