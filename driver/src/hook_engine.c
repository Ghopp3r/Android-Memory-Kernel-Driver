// SPDX-License-Identifier: GPL-2.0-only
/* ARM64 inline-hook engine (KernelPatch port). */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/version.h>

#include <driver/types.h>

#include "hook_engine.h"
#include "kallsym.h"
#include "log.h"
#include "memory.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif
#ifndef __nocfi
#define __nocfi
#endif

/* -------- Exec-buffer + atomic patch primitives (resolved via kallsyms) -------- */

typedef void *(*drv_module_alloc_fn_t)(unsigned long size);
typedef void  (*drv_vfree_fn_t)(const void *addr);
typedef int   (*drv_set_memory_fn_t)(unsigned long addr, int numpages);
typedef int   (*drv_aarch64_insn_patch_text_fn_t)(void *addrs[], u32 insns[], int cnt);
typedef void  (*drv_caches_clean_inval_pou_fn_t)(unsigned long start, unsigned long end);

static drv_module_alloc_fn_t            drv_module_alloc_ptr;
static drv_vfree_fn_t                   drv_vfree_ptr;
static drv_set_memory_fn_t              drv_set_memory_x_ptr;
static drv_set_memory_fn_t              drv_set_memory_ro_ptr;
static drv_set_memory_fn_t              drv_set_memory_nx_ptr;
static drv_aarch64_insn_patch_text_fn_t drv_aarch64_insn_patch_text_ptr;
static drv_caches_clean_inval_pou_fn_t  drv_caches_clean_inval_pou_ptr;

static __nocfi noinline void *drv_call_module_alloc(drv_module_alloc_fn_t fn, unsigned long size) {
	return fn(size);
}
static __nocfi noinline void drv_call_vfree(drv_vfree_fn_t fn, const void *p) {
	fn(p);
}
static __nocfi noinline int drv_call_set_memory(drv_set_memory_fn_t fn, unsigned long a, int n) {
	return fn(a, n);
}
static __nocfi noinline int drv_call_aarch64_insn_patch_text(drv_aarch64_insn_patch_text_fn_t fn,
                                                             void *addrs[], u32 insns[], int cnt) {
	return fn(addrs, insns, cnt);
}
static __nocfi noinline void drv_call_caches_clean_inval_pou(drv_caches_clean_inval_pou_fn_t fn,
                                                             unsigned long s, unsigned long e) {
	fn(s, e);
}

/* Resolve all hook-engine-only kernel symbols on first call (lazily, from
 * process context — never from atomic context). Logged once. */
static int hook_engine_resolve_symbols(void) {
	if (drv_module_alloc_ptr)
		return 0;

	drv_module_alloc_ptr            = (drv_module_alloc_fn_t)            kallsym_lookup("module_alloc");
	drv_vfree_ptr                   = (drv_vfree_fn_t)                   kallsym_lookup("vfree");
	drv_set_memory_x_ptr            = (drv_set_memory_fn_t)              kallsym_lookup("set_memory_x");
	drv_set_memory_ro_ptr           = (drv_set_memory_fn_t)              kallsym_lookup("set_memory_ro");
	drv_set_memory_nx_ptr           = (drv_set_memory_fn_t)              kallsym_lookup("set_memory_nx");
	drv_aarch64_insn_patch_text_ptr = (drv_aarch64_insn_patch_text_fn_t) kallsym_lookup("aarch64_insn_patch_text");
	drv_caches_clean_inval_pou_ptr  = (drv_caches_clean_inval_pou_fn_t)  kallsym_lookup("caches_clean_inval_pou");

	pr_drv("hook_engine resolve: module_alloc=%p vfree=%p set_x=%p set_ro=%p set_nx=%p insn_patch=%p caches=%p\n",
	       drv_module_alloc_ptr, drv_vfree_ptr,
	       drv_set_memory_x_ptr, drv_set_memory_ro_ptr, drv_set_memory_nx_ptr,
	       drv_aarch64_insn_patch_text_ptr, drv_caches_clean_inval_pou_ptr);

	if (!drv_module_alloc_ptr || !drv_vfree_ptr || !drv_set_memory_x_ptr) {
		pr_drv_err("hook_engine: cannot resolve required symbols\n");
		return -ENOENT;
	}
	return 0;
}

void *hook_engine_alloc_exec(size_t bytes) {
	void *p;
	if (hook_engine_resolve_symbols())
		return NULL;
	p = drv_call_module_alloc(drv_module_alloc_ptr, (unsigned long)bytes);
	if (!p)
		pr_drv_err("hook_engine_alloc_exec: module_alloc(%zu) failed\n", bytes);
	return p;
}

int hook_engine_exec_publish(void *buf, size_t bytes) {
	unsigned long addr = (unsigned long)buf;
	int npages = (int)((bytes + PAGE_SIZE - 1u) / PAGE_SIZE);
	int ret;

	if (!buf)
		return -EINVAL;
	if (hook_engine_resolve_symbols())
		return -ENOSYS;

	/* Push every store to PoU and broadcast-invalidate the I-cache over the
	 * range so any remote CPU re-fetches the freshly-written instructions. */
	if (drv_caches_clean_inval_pou_ptr) {
		drv_call_caches_clean_inval_pou(drv_caches_clean_inval_pou_ptr, addr, addr + bytes);
	} else {
		asm volatile("dsb ish" ::: "memory");
		asm volatile("ic ialluis" ::: "memory");
		asm volatile("dsb ish" ::: "memory");
		asm volatile("isb" ::: "memory");
	}

	/* module_alloc returns RW+NX on arm64 GKI — flip to executable. */
	ret = drv_call_set_memory(drv_set_memory_x_ptr, addr, npages);
	if (ret) {
		pr_drv_err("hook_engine_exec_publish: set_memory_x(%lx,%d) failed: %d\n", addr, npages, ret);
		return ret;
	}
	if (drv_set_memory_ro_ptr) {
		ret = drv_call_set_memory(drv_set_memory_ro_ptr, addr, npages);
		if (ret)
			pr_drv_warn("hook_engine_exec_publish: set_memory_ro(%lx,%d) failed: %d (continuing)\n",
			            addr, npages, ret);
	}
	return 0;
}

void hook_engine_free_exec(void *buf, size_t bytes) {
	unsigned long addr = (unsigned long)buf;
	int npages = (int)((bytes + PAGE_SIZE - 1u) / PAGE_SIZE);
	if (!buf || !drv_vfree_ptr)
		return;
	/* Restore RW+NX so the page is safe to recycle. */
	if (drv_set_memory_nx_ptr)
		(void)drv_call_set_memory(drv_set_memory_nx_ptr, addr, npages);
	drv_call_vfree(drv_vfree_ptr, buf);
}

/* Top-bits values that identify the encoding class once masked with inst_masks[]. */
#define INST_B 0x14000000u
#define INST_BC 0x54000000u
#define INST_BL 0x94000000u
#define INST_ADR 0x10000000u
#define INST_ADRP 0x90000000u
#define INST_LDR_32 0x18000000u
#define INST_LDR_64 0x58000000u
#define INST_LDRSW_LIT 0x98000000u
#define INST_PRFM_LIT 0xD8000000u
#define INST_LDR_SIMD_32 0x1C000000u
#define INST_LDR_SIMD_64 0x5C000000u
#define INST_LDR_SIMD_128 0x9C000000u
#define INST_CBZ 0x34000000u
#define INST_CBNZ 0x35000000u
#define INST_TBZ 0x36000000u
#define INST_TBNZ 0x37000000u
#define INST_IGNORE 0x00000000u

#define MASK_B 0xFC000000u
#define MASK_BC 0xFF000010u
#define MASK_BL 0xFC000000u
#define MASK_ADR 0x9F000000u
#define MASK_ADRP 0x9F000000u
#define MASK_LDR_LIT 0xFF000000u /* shared by LDR/LDRSW/PRFM/SIMD */
#define MASK_CBTB 0x7F000000u
#define MASK_IGNORE 0x00000000u

/* Order MUST match relo_len[] - any reorder breaks the tramp-cursor math. */
enum hook_inst_class {
	HC_B = 0,
	HC_BC,
	HC_BL,
	HC_ADR,
	HC_ADRP,
	HC_LDR_32,
	HC_LDR_64,
	HC_LDRSW_LIT,
	HC_PRFM_LIT,
	HC_LDR_SIMD_32,
	HC_LDR_SIMD_64,
	HC_LDR_SIMD_128,
	HC_CBZ,
	HC_CBNZ,
	HC_TBZ,
	HC_TBNZ,
	HC_IGNORE,
	HC_COUNT,
};

/* Per-class trampoline output length, in 4-byte instruction units. */
const s32 relo_len[17] = {
	6, 8, 8, 4, 4, 6, 6, 6, 8, 8, 8, 8, 6, 6, 6, 6, 2,
};

static const u32 inst_masks[HC_COUNT] = {
	MASK_B, MASK_BC, MASK_BL,
	MASK_ADR, MASK_ADRP,
	MASK_LDR_LIT, MASK_LDR_LIT, MASK_LDR_LIT, MASK_LDR_LIT,
	MASK_LDR_LIT, MASK_LDR_LIT, MASK_LDR_LIT,
	MASK_CBTB, MASK_CBTB, MASK_CBTB, MASK_CBTB,
	MASK_IGNORE,
};

static const u32 inst_types[HC_COUNT] = {
	INST_B, INST_BC, INST_BL,
	INST_ADR, INST_ADRP,
	INST_LDR_32, INST_LDR_64, INST_LDRSW_LIT, INST_PRFM_LIT,
	INST_LDR_SIMD_32, INST_LDR_SIMD_64, INST_LDR_SIMD_128,
	INST_CBZ, INST_CBNZ, INST_TBZ, INST_TBNZ,
	INST_IGNORE,
};

/* Cursor wall matches the relo_insts[] array size (41 slots / 164 bytes). */
#define RELO_CURSOR_MAX 0x29

static inline u32 bits32(u32 n, u32 high, u32 low) {
	return (n << (31u - high)) >> (31u - high + low);
}

static inline u64 sign64_extend(u64 n, u32 len) {
	return ((n >> (len - 1)) & 1u)
		? (n | (0xFFFFFFFFFFFFFFFFull << len))
		: n;
}

static inline int is_in_tramp(hook_t *hook, u64 addr) {
	u64 start = hook->origin_addr;
	u64 end = start + (u64)hook->tramp_insts_num * 4u;

	return (addr >= start) && (addr < end);
}

u64 relo_in_tramp(hook_t *hook, u64 addr) {
	u64 start = hook->origin_addr;
	u64 end = start + (u64)hook->tramp_insts_num * 4u;
	u32 idx;
	u64 fix_addr;
	int i, j;

	if (!(addr >= start && addr < end))
		return addr;

	idx = (u32)((addr - start) / 4u);
	fix_addr = hook->relo_addr;

	for (i = 0; i < (int)idx; i++) {
		u32 inst = hook->origin_insts[i];
		for (j = 0; j < HC_COUNT; j++) {
			if ((inst & inst_masks[j]) == inst_types[j]) {
				fix_addr += (u64)relo_len[j] * 4u;
				break;
			}
		}
	}
	return fix_addr;
}

int relo_b(hook_t *hook, u64 inst_addr, u32 inst, int class_top) {
	u32 *buf;
	u64 imm64;
	u64 addr;
	u32 idx;

	if ((u32)hook->relo_insts_num >= RELO_CURSOR_MAX)
		return -HOOK_BAD_RELO;

	buf = hook->relo_insts + hook->relo_insts_num;

	if (class_top == (int)INST_BC) {
		u64 imm19 = bits32(inst, 23, 5);
		imm64 = sign64_extend(imm19 << 2u, 21u);
	} else {
		u64 imm26 = bits32(inst, 25, 0);
		imm64 = sign64_extend(imm26 << 2u, 28u);
	}

	addr = inst_addr + imm64;
	addr = relo_in_tramp(hook, addr);

	idx = 0;
	if (class_top == (int)INST_BC) {
		buf[idx++] = (inst & 0xFF00001Fu) | 0x40u;
		buf[idx++] = 0x14000006u;
	}
	buf[idx++] = 0x58000051u;
	buf[idx++] = 0x14000003u;
	buf[idx++] = (u32)(addr & 0xFFFFFFFFu);
	buf[idx++] = (u32)(addr >> 32u);
	if (class_top == (int)INST_BL) {
		buf[idx++] = 0x1000001Eu;
		buf[idx++] = 0x910033DEu;
		buf[idx++] = 0xD65F0220u;
	} else {
		buf[idx++] = 0xD65F0220u;
	}
	buf[idx++] = ARM64_NOP;
	return HOOK_NO_ERR;
}

int relo_adr(hook_t *hook, u64 inst_addr, u32 inst, int class_top) {
	u32 *buf;
	u32 xd;
	u64 immlo, immhi;
	u64 addr;

	if ((u32)hook->relo_insts_num >= RELO_CURSOR_MAX)
		return -HOOK_BAD_RELO;

	buf = hook->relo_insts + hook->relo_insts_num;
	xd = bits32(inst, 4, 0);
	immlo = bits32(inst, 30, 29);
	immhi = bits32(inst, 23, 5);

	if (class_top == (int)INST_ADR) {
		addr = inst_addr + sign64_extend((immhi << 2u) | immlo, 21u);
	} else {
		addr = (inst_addr + sign64_extend((immhi << 14u) | (immlo << 12u), 33u)) & 0xFFFFFFFFFFFFF000ull;
		if (is_in_tramp(hook, addr))
			return -HOOK_BAD_RELO;
	}

	buf[0] = 0x58000040u | xd;
	buf[1] = 0x14000003u;
	buf[2] = (u32)(addr & 0xFFFFFFFFu);
	buf[3] = (u32)(addr >> 32u);
	return HOOK_NO_ERR;
}

int relo_ldr(hook_t *hook, u64 inst_addr, u32 inst, int class_top) {
	u32 *buf;
	u32 rt;
	u64 imm19, offset, addr;

	if ((u32)hook->relo_insts_num >= RELO_CURSOR_MAX)
		return -HOOK_BAD_RELO;

	buf = hook->relo_insts + hook->relo_insts_num;
	rt = bits32(inst, 4, 0);
	imm19 = bits32(inst, 23, 5);
	offset = sign64_extend(imm19 << 2u, 21u);
	addr = inst_addr + offset;

	/* PRFM has no side-effect on the value so it's the only literal we can move with the code. */
	if (is_in_tramp(hook, addr) && class_top != (int)INST_PRFM_LIT)
		return -HOOK_BAD_RELO;

	addr = relo_in_tramp(hook, addr);

	if (class_top == (int)INST_LDR_32 || class_top == (int)INST_LDR_64 || class_top == (int)INST_LDRSW_LIT) {
		buf[0] = 0x58000060u | rt;
		if (class_top == (int)INST_LDR_32)
			buf[1] = 0xB9400000u | rt | (rt << 5u);
		else if (class_top == (int)INST_LDR_64)
			buf[1] = 0xF9400000u | rt | (rt << 5u);
		else
			buf[1] = 0xB9800000u | rt | (rt << 5u);
		buf[2] = 0x14000004u;
		buf[3] = ARM64_NOP;
		buf[4] = (u32)(addr & 0xFFFFFFFFu);
		buf[5] = (u32)(addr >> 32u);
	} else {
		buf[0] = 0xA93F47F0u;
		buf[1] = 0x58000091u;
		if (class_top == (int)INST_PRFM_LIT)
			buf[2] = 0xF9800220u | rt;
		else if (class_top == (int)INST_LDR_SIMD_32)
			buf[2] = 0xBD400220u | rt;
		else if (class_top == (int)INST_LDR_SIMD_64)
			buf[2] = 0xFD400220u | rt;
		else
			buf[2] = 0x3DC00220u | rt;
		buf[3] = 0xF85F83F1u;
		buf[4] = 0x14000004u;
		buf[5] = ARM64_NOP;
		buf[6] = (u32)(addr & 0xFFFFFFFFu);
		buf[7] = (u32)(addr >> 32u);
	}
	return HOOK_NO_ERR;
}

int relo_cb(hook_t *hook, u64 inst_addr, u32 inst) {
	u32 *buf;
	u64 imm19, offset, addr;

	if ((u32)hook->relo_insts_num >= RELO_CURSOR_MAX)
		return -HOOK_BAD_RELO;

	buf = hook->relo_insts + hook->relo_insts_num;
	imm19 = bits32(inst, 23, 5);
	offset = sign64_extend(imm19 << 2u, 21u);
	addr = relo_in_tramp(hook, inst_addr + offset);

	buf[0] = (inst & 0xFF00001Fu) | 0x40u;
	buf[1] = 0x14000005u;
	buf[2] = 0x58000051u;
	buf[3] = 0xD65F0220u;
	buf[4] = (u32)(addr & 0xFFFFFFFFu);
	buf[5] = (u32)(addr >> 32u);
	return HOOK_NO_ERR;
}

int relo_tb(hook_t *hook, u64 inst_addr, u32 inst) {
	u32 *buf;
	u64 imm14, offset, addr;

	if ((u32)hook->relo_insts_num >= RELO_CURSOR_MAX)
		return -HOOK_BAD_RELO;

	buf = hook->relo_insts + hook->relo_insts_num;
	imm14 = bits32(inst, 18, 5);
	offset = sign64_extend(imm14 << 2u, 16u);
	addr = relo_in_tramp(hook, inst_addr + offset);

	buf[0] = (inst & 0xFFF8001Fu) | 0x40u;
	buf[1] = 0x14000005u;
	buf[2] = 0x58000051u;
	/* BR(not RET) X17: TB(N)Z is not a call so LR doesn't matter. */
	buf[3] = 0xD61F0220u;
	buf[4] = (u32)(addr & 0xFFFFFFFFu);
	buf[5] = (u32)(addr >> 32u);
	return HOOK_NO_ERR;
}

int relo_ignore(hook_t *hook, u32 inst) {
	u32 *buf;

	if ((u32)hook->relo_insts_num >= RELO_CURSOR_MAX)
		return -HOOK_BAD_RELO;

	buf = hook->relo_insts + hook->relo_insts_num;
	buf[0] = inst;
	buf[1] = ARM64_NOP;
	return HOOK_NO_ERR;
}

int relocate_inst(hook_t *hook, u64 inst_addr, u32 inst) {
	int rc = HOOK_NO_ERR;
	u32 it = INST_IGNORE;
	int len = 1;
	int j;

	for (j = 0; j < HC_COUNT; j++) {
		if ((inst & inst_masks[j]) == inst_types[j]) {
			it = inst_types[j];
			len = relo_len[j];
			break;
		}
	}

	switch (it) {
	case INST_B:
	case INST_BC:
	case INST_BL:
		rc = relo_b(hook, inst_addr, inst, (int)it);
		break;
	case INST_ADR:
	case INST_ADRP:
		rc = relo_adr(hook, inst_addr, inst, (int)it);
		break;
	case INST_LDR_32:
	case INST_LDR_64:
	case INST_LDRSW_LIT:
	case INST_PRFM_LIT:
	case INST_LDR_SIMD_32:
	case INST_LDR_SIMD_64:
	case INST_LDR_SIMD_128:
		rc = relo_ldr(hook, inst_addr, inst, (int)it);
		break;
	case INST_CBZ:
	case INST_CBNZ:
		rc = relo_cb(hook, inst_addr, inst);
		break;
	case INST_TBZ:
	case INST_TBNZ:
		rc = relo_tb(hook, inst_addr, inst);
		break;
	case INST_IGNORE:
	default:
		rc = relo_ignore(hook, inst);
		break;
	}

	hook->relo_insts_num += len;
	return rc;
}

#define B_REL_RANGE ((1u << 25) << 2)

static u32 can_b_rel(u64 src_addr, u64 dst_addr) {
	return ((dst_addr >= src_addr) && (dst_addr - src_addr <= B_REL_RANGE)) ||
	       ((src_addr >= dst_addr) && (src_addr - dst_addr <= B_REL_RANGE));
}

s32 branch_relative(u32 *buf, u64 src_addr, u64 dst_addr) {
	if (can_b_rel(src_addr, dst_addr)) {
		buf[0] = 0x14000000u | (((u32)(dst_addr - src_addr) & 0x0FFFFFFFu) >> 2u);
		buf[1] = ARM64_NOP;
		return 2;
	}
	return 0;
}

s32 branch_absolute(u32 *buf, u64 addr) {
	buf[0] = 0x58000051u;
	buf[1] = 0xD61F0220u;
	buf[2] = (u32)(addr & 0xFFFFFFFFu);
	buf[3] = (u32)(addr >> 32u);
	return 4;
}

s32 ret_absolute(u32 *buf, u64 addr) {
	buf[0] = 0x58000051u;
	buf[1] = 0xD65F0220u;
	buf[2] = (u32)(addr & 0xFFFFFFFFu);
	buf[3] = (u32)(addr >> 32u);
	return 4;
}

s32 branch_from_to(u32 *tramp_buf, u64 src_addr, u64 dst_addr) {
	/* Hard-wired to ret_absolute: overwritten prologue is LDR+RET pointing at the replacement. */
	(void)src_addr;
	return ret_absolute(tramp_buf, dst_addr);
}

static inline int is_bad_address(void *addr) {
	/* Kernel VAs have the top bit set on aarch64. */
	return ((u64)addr & 0x8000000000000000ull) != 0x8000000000000000ull;
}

hook_err_t hook_prepare(hook_t *hook) {
	u64 back_src_addr, back_dst_addr;
	u32 *buf;
	int i;

	if (is_bad_address((void *)(uintptr_t)hook->func_addr)) return -HOOK_BAD_ADDRESS;
	if (is_bad_address((void *)(uintptr_t)hook->origin_addr)) return -HOOK_BAD_ADDRESS;
	if (is_bad_address((void *)(uintptr_t)hook->replace_addr)) return -HOOK_BAD_ADDRESS;
	if (is_bad_address((void *)(uintptr_t)hook->relo_addr)) return -HOOK_BAD_ADDRESS;

	for (i = 0; i < TRAMPOLINE_MAX_NUM; i++)
		hook->origin_insts[i] = ((u32 *)(uintptr_t)hook->origin_addr)[i];

	/* PAC prologue (PACIASP/PACIBSP) needs a BTI JC landing pad before the indirect branch. */
	if (hook->origin_insts[0] == ARM64_PACIASP || hook->origin_insts[0] == ARM64_PACIBSP) {
		hook->tramp_insts_num = branch_from_to(&hook->tramp_insts[1], hook->origin_addr, hook->replace_addr);
		hook->tramp_insts[0] = ARM64_BTI_JC;
		hook->tramp_insts_num++;
	} else {
		hook->tramp_insts_num = branch_from_to(hook->tramp_insts, hook->origin_addr, hook->replace_addr);
	}

	for (i = 0; i < RELOCATE_INST_NUM; i++)
		hook->relo_insts[i] = ARM64_NOP;
	hook->relo_insts_num = 0;

	for (i = 0; i < hook->tramp_insts_num; i++) {
		u64 inst_addr = hook->origin_addr + (u64)i * 4u;
		u32 inst = hook->origin_insts[i];
		int rc = relocate_inst(hook, inst_addr, inst);
		if (rc)
			return -HOOK_BAD_RELO;
	}

	back_src_addr = hook->relo_addr + (u64)hook->relo_insts_num * 4u;
	back_dst_addr = hook->origin_addr + (u64)hook->tramp_insts_num * 4u;
	buf = hook->relo_insts + hook->relo_insts_num;
	hook->relo_insts_num += branch_from_to(buf, back_src_addr, back_dst_addr);

	return HOOK_NO_ERR;
}

/* Apply the trampoline atomically across the multi-word patch window.
 *
 * Fast path: aarch64_insn_patch_text(addrs[], insns[], cnt) — the kernel's
 * canonical batched-poke primitive.  It internally stop_machine()'s, applies
 * every word, then issues a broadcast IC IALLUIS + ISB on every CPU.  Using
 * it is what KernelPatch's hotpatch_cb pattern is doing under the hood.
 *
 * Fallback (older / locked-down kernels where the symbol is hidden): plain
 * write_ro_memory then a manual DSB ISH + IC IALLUIS + DSB ISH + ISB — closes
 * the I-cache incoherence window but does NOT close the torn-fetch window;
 * acceptable only when the symbol genuinely isn't available. */
static void hook_engine_patch_window(u64 dst, u32 *insns, int cnt, const char *label) {
	void *addrs[TRAMPOLINE_MAX_NUM];
	int i, rc;

	(void)hook_engine_resolve_symbols();

	pr_drv("hook_engine_patch_window[%s]: dst=%llx cnt=%d insn_patch=%p\n",
	       label, (unsigned long long)dst, cnt, drv_aarch64_insn_patch_text_ptr);

	if (cnt <= 0 || cnt > TRAMPOLINE_MAX_NUM) {
		pr_drv_err("hook_engine_patch_window[%s]: bad cnt=%d\n", label, cnt);
		return;
	}

	for (i = 0; i < cnt; i++)
		addrs[i] = (void *)(uintptr_t)(dst + (u64)i * 4u);

	if (drv_aarch64_insn_patch_text_ptr) {
		rc = drv_call_aarch64_insn_patch_text(drv_aarch64_insn_patch_text_ptr, addrs, insns, cnt);
		if (rc)
			pr_drv_err("hook_engine_patch_window[%s]: aarch64_insn_patch_text rc=%d\n", label, rc);
	} else {
		(void)write_ro_memory(dst, insns, (u64)cnt * 4u);
		asm volatile("dsb ish" ::: "memory");
		asm volatile("ic ialluis" ::: "memory");
		asm volatile("dsb ish" ::: "memory");
		asm volatile("isb" ::: "memory");
	}
}

void hook_install(hook_t *hook) {
	pr_drv("hook_install: enter func=%llx dst=%llx repl=%llx relo=%llx tramp_words=%d\n",
	       (unsigned long long)hook->func_addr,
	       (unsigned long long)hook->origin_addr,
	       (unsigned long long)hook->replace_addr,
	       (unsigned long long)hook->relo_addr,
	       (int)hook->tramp_insts_num);

	hook_engine_patch_window(hook->origin_addr, hook->tramp_insts, hook->tramp_insts_num, "install");

	pr_drv("hook_install: done func=%llx\n", (unsigned long long)hook->func_addr);
}

void hook_remove(hook_t *hook) {
	pr_drv("hook_remove: enter func=%llx\n", (unsigned long long)hook->func_addr);

	hook_engine_patch_window(hook->origin_addr, hook->origin_insts, hook->tramp_insts_num, "remove");

	pr_drv("hook_remove: done func=%llx\n", (unsigned long long)hook->func_addr);
}
