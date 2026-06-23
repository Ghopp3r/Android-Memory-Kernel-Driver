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
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/mmzone.h>
#include <linux/numa.h>
#include <linux/path.h>
#include <linux/pgtable.h>
#include <linux/pid.h>
#include <linux/preempt.h>
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

#include "compat/compat.h"
#include "kallsym.h"
#include "log.h"
#include "memory.h"
#include "uaccess_target.h"

/* ARM64 pagewalk arithmetic constants — invariant across the supported kernel range. PAGE_OFFSET is intentionally NOT hardcoded; phys_to_virt() honours vabits_actual. The binary's `(pa - memstart) | 0xFFFFFF80_00000000` was specific to a VA_BITS=40 layout and walks garbage on standard 39-bit GKI 6.6 builds (which is exactly the failure mode in pstore: write_ro_memory's PTE flip lands on the wrong leaf and the subsequent byte-store faults on the still-RO target). */
#define DRV_PTE_OA_MASK 0x0000007FFFFFF000ULL
#define DRV_PTE_PA_MASK 0x0000FFFFFFFFF000ULL
/* 512 GiB user-space limit on this kernel. */
#define DRV_TASK_SIZE_64 0x0000008000000000ULL
/* Strip ARMv8 TBI / PAC byte from a user VA before handing to uaccess. */
#define DRV_TBI_PAC_STRIP_MASK 0xFF7FFFFFFFFFFFFFULL
/* write_ro_memory PTE bit-flip: clear PTE_RDONLY(bit 7), set PTE_DBM(bit 51). */
#define DRV_PTE_RDONLY_CLEAR 0xFFF7FFFFFFFFFF7FULL
#define DRV_PTE_DBM_SET 0x0008000000000000ULL
/* vmap prot: PTE_VALID|PTE_AF|PTE_SHARED|PTE_PXN|PTE_UXN|PTE_TYPE_PAGE; KPTI adds PTE_NG. */
#define DRV_VMAP_PROT_KPTI_OFF 0x6800000000070BULL
#define DRV_VMAP_PROT_KPTI_ON 0x68000000000F0BULL

/* Two distinct dcache-line caches — one for linear-map, one for vmap. */
static u32 dcache_line_size_linear;
static u32 dcache_line_size_vmap;

extern bool arm64_use_ng_mappings;

/* Resolved once at module init via kallsym_lookup. The kernel's own
   self-modifying-text primitive: installs the target PFN in FIX_TEXT_POKE0
   (a single 4 KiB fixmap slot, allocated WITHOUT PTE_CONT by construction),
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

/* CFI-safe trampoline — mirrors kallsym_call_resolved in kallsym.c. The
   kallsyms-resolved address was not built with caller-side CFI metadata
   matching this typedef, so the indirect call must bypass kCFI. */
static __nocfi int drv_call_insn_patch_text_nosync(drv_insn_patch_text_nosync_fn_t fn, void *addr, u32 insn) {
	return fn(addr, insn);
}

int memory_init(void) {
	unsigned long addr = kallsym_lookup("aarch64_insn_patch_text_nosync");

	if (!addr) {
		pr_drv_warn("memory_init: aarch64_insn_patch_text_nosync not in kallsyms; using legacy PTE-flip fallback (unsafe on PTE_CONT-mapped text)\n");
		return 0; /* non-fatal: fallback path still works on non-CONT kernels */
	}

	drv_insn_patch_text_nosync = (drv_insn_patch_text_nosync_fn_t)addr;
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
	return (u64)(uintptr_t)phys_to_virt(phys & DRV_PTE_OA_MASK);
}

static bool drv_section_online(u64 page_pa) {
	unsigned long pfn = page_pa >> PAGE_SHIFT;
	bool online;

	/* preempt_disable bracketing matches the binary's RCU-equivalent quiescence. */
	preempt_disable();
	online = pfn_valid(pfn);
	preempt_enable();
	return online;
}

/* Canonical pagewalk: caller must hold mmap_read_lock(mm) for a user mm. p4d_offset is unconditional; pgtable-nop4d.h folds it to a passthrough on 3-level configs. pud_leaf/pmd_leaf early-exits cover 1G/2M hugepages. pte_offset_kernel — NOT pte_offset_map — to side-step the 6.5 failable/RCU rework. */
static pte_t *drv_pte_lookup(struct mm_struct *mm, unsigned long addr) {
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return (pte_t *)pud;
#endif

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return (pte_t *)pmd;
#endif

	return pte_offset_kernel(pmd, addr);
}

int vaddr_to_phys(struct mm_struct *mm, u64 va, u64 *out_phys) {
	pte_t *ptep;
	pte_t pte;
	u64 phys;

	if (!mm || !out_phys)
		return -EFAULT;

	if (!mm->pgd)
		return -EFAULT;

	ptep = drv_pte_lookup(mm, (unsigned long)va);
	if (!ptep)
		return -EFAULT;

	pte = READ_ONCE(*ptep);
	if (!pte_present(pte))
		return -EFAULT;

#if defined(__pte_to_phys)
	phys = (u64)__pte_to_phys(pte) | (va & ~PAGE_MASK);
#else
	phys = ((u64)pte_pfn(pte) << PAGE_SHIFT) | (va & ~PAGE_MASK);
#endif

	if (!phys)
		return -EFAULT;

	if (!drv_section_online(phys & DRV_PTE_PA_MASK))
		return -EFAULT;

	*out_phys = phys;
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
		size_t chunk = min_t(size_t, remain, 4096 - (size_t)(target_va & 0xFFF));

		if (vaddr_to_phys(target_mm, target_va, &phys) != 0)
			goto skip;

		lm_va = drv_lm_va_from_phys(phys);

		if (copy_to_user((void __user *)(uintptr_t)user_dst, (const void *)(uintptr_t)lm_va, chunk) != 0)
			pr_drv_err("copy_to_user failed: %s\n", __func__);

		/* Flush dcache around the linear-map alias to defeat stale-cache reads of patched code. */
		drv_flush_dcache_range(lm_va, chunk, &dcache_line_size_linear);

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

	if (!target_mm || !local_kbuf || len == 0)
		return 0;

	user_src = (u64)(uintptr_t)local_kbuf;
	if (!drv_user_ptr_in_range(user_src, len))
		return -EFAULT;

	mmap_read_lock(target_mm);
	while (remain) {
		u64 phys, lm_va;
		size_t chunk = min_t(size_t, remain, 4096 - (size_t)(target_va & 0xFFF));

		if (vaddr_to_phys(target_mm, target_va, &phys) != 0)
			goto skip;

		lm_va = drv_lm_va_from_phys(phys);

		(void)copy_from_user((void *)(uintptr_t)lm_va, (const void __user *)(uintptr_t)user_src, chunk);
skip:
		remain -= chunk;
		target_va += chunk;
		user_src += chunk;
	}
	mmap_read_unlock(target_mm);
	return 0;
}

static u64 drv_vmap_prot(void) {
	return arm64_use_ng_mappings ? DRV_VMAP_PROT_KPTI_ON : DRV_VMAP_PROT_KPTI_OFF;
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
		size_t chunk = min_t(size_t, remain, 4096 - (size_t)(target_va & 0xFFF));

		if (vaddr_to_phys(target_mm, target_va, &phys) != 0)
			goto skip;

		if (!pfn_valid(phys >> PAGE_SHIFT))
			goto skip;

		pages[0] = pfn_to_page(phys >> PAGE_SHIFT);
		if (!pages[0])
			goto skip;

		mapped = vmap(pages, 1, VM_MAP, __pgprot(drv_vmap_prot()));
		if (!mapped)
			goto skip;

		drv_flush_dcache_range((u64)(uintptr_t)mapped + (target_va & 0xFFF), chunk, &dcache_line_size_vmap);

		if (copy_to_user((void __user *)(uintptr_t)user_dst, (char *)mapped + (target_va & 0xFFF), chunk) != 0)
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

	if (!target_mm || !local_kbuf || len == 0)
		return 0;

	user_src = (u64)(uintptr_t)local_kbuf;
	if (!drv_user_ptr_in_range(user_src, len))
		return -EFAULT;

	mmap_read_lock(target_mm);
	while (remain) {
		u64 phys;
		struct page *pages[1];
		void *mapped;
		size_t chunk = min_t(size_t, remain, 4096 - (size_t)(target_va & 0xFFF));

		if (vaddr_to_phys(target_mm, target_va, &phys) != 0)
			goto skip;

		if (!pfn_valid(phys >> PAGE_SHIFT))
			goto skip;

		pages[0] = pfn_to_page(phys >> PAGE_SHIFT);
		if (!pages[0])
			goto skip;

		mapped = vmap(pages, 1, VM_MAP, __pgprot(drv_vmap_prot()));
		if (!mapped)
			goto skip;

		(void)copy_from_user((char *)mapped + (target_va & 0xFFF), (const void __user *)(uintptr_t)user_src, chunk);
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
			size_t chunk = min_t(size_t, remain, 4096 - (size_t)(src_va & 0xFFF));

			if (vaddr_to_phys(target_mm, src_va, &phys) != 0)
				goto next;

			/* Linear-map alias of the source page (same primitive
			 * read_process_memory_linear uses). The previous vmap+pfn_valid
			 * path silently returned empty buffers when pfn_valid() rejected
			 * anonymous user pages on vendor kernels — drv_probe's MULTI_READ
			 * caught it: rc=0, size_back=1, but dst stayed zero. */
			lm_va = drv_lm_va_from_phys(phys);

			(void)copy_to_user((void __user *)(uintptr_t)user_dst,
			                   (const void *)(uintptr_t)lm_va + (src_va & 0xFFF),
			                   chunk);
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
		u64 page_remain = 4096 - (result & 0xFFF);
		u64 chunk = min_t(u64, page_remain, (u64)(uintptr_t)end - result);
		unsigned int level_start;
		unsigned int level_count = drv.m_page_level;
		u64 saved_pte;
		u64 i;

		if (level_count == 0 || level_count > 4) {
			result += chunk;
			continue;
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
					next_pa = e & DRV_PTE_OA_MASK;
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
		asm volatile("tlbi vaae1is, %0" :: "r"(result >> 12) : "memory");
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

		result += chunk;

		dsb(ishst);
		asm volatile("tlbi vaae1is, %0" :: "r"(result >> 12) : "memory");
		dsb(ish);
		isb();
	}

	return result;
}

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

/* Caller must put_task_struct() on the non-NULL return. */
struct task_struct *process_find_task_by_comm(const char *comm) {
	struct task_struct *p;

	if (!comm || !comm[0])
		return NULL;

	rcu_read_lock();
	for_each_process(p) {
		if (strncmp(p->comm, comm, sizeof(p->comm)) == 0) {
			get_task_struct(p);
			rcu_read_unlock();
			return p;
		}
	}
	rcu_read_unlock();
	return NULL;
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

/* The two raw byte offsets here (344 for anon-vma-name, 2008/2016 for the per-VMA driver-private cookie) are NOT standard struct vm_area_struct fields — the original .ko reads driver-private slots appended past the end of the kernel vma. Kept as inline literals with names; do not promote back into compat.h. */
u64 process_read_vma_cookie(struct task_struct *task, const char *needle) {
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	u64 cookie = 0;
	unsigned long cookie_off;

	if (!task || !needle)
		return 0;

	/* 32-bit (AArch32 compat) target tasks shift the driver-appended vma layout by 8 bytes — select via TIF_32BIT on the owning task. */
	cookie_off = test_tsk_thread_flag(task, TIF_32BIT) ? 2016UL : 2008UL;

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
		const char *aname = (const char *)((char *)vma + 344);
		if (strncmp(aname, needle, 16) == 0) {
			cookie = *(u64 *)((char *)vma + cookie_off);
			break;
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	}
#endif

	mmap_read_unlock(mm);
	mmput(mm);
	return cookie;
}

/* TTBR0-swap uaccess helpers live in uaccess_target.c (copy_to_target_user/copy_from_target_user). Use them for cross-mm copies; for copies against `current`'s userspace, fall back to the kernel-provided copy_to_user / copy_from_user. */
