// SPDX-License-Identifier: GPL-2.0
// ARM64 inline-hook engine (KernelPatch port, GPL-2.0).
#ifndef DRIVER_HOOK_ENGINE_H
#define DRIVER_HOOK_ENGINE_H

#include <linux/types.h>

#define TRAMPOLINE_MAX_NUM 6
/* 41 slots / 164 bytes, matches RELO_CURSOR_MAX (0x29) and the original .ko layout. */
#define RELOCATE_INST_NUM 41
#define HOOK_CHAIN_NUM 0x10
#define TRANSIT_INST_NUM 0x60
#define FP_HOOK_CHAIN_NUM 0x20

#define ARM64_NOP 0xd503201fu
#define ARM64_BTI_C 0xd503245fu
#define ARM64_BTI_J 0xd503249fu
#define ARM64_BTI_JC 0xd50324dfu
#define ARM64_PACIASP 0xd503233fu
#define ARM64_PACIBSP 0xd503237fu

typedef enum {
	HOOK_NO_ERR         = 0,
	HOOK_BAD_ADDRESS    = 4095,
	HOOK_DUPLICATED     = 4094,
	HOOK_NO_MEM         = 4093,
	HOOK_BAD_RELO       = 4092,
	HOOK_TRANSIT_NO_MEM = 4091,
	HOOK_CHAIN_FULL     = 4090,
} hook_err_t;

/* Layout MUST byte-match KernelPatch hook.h: relo_* rewriters index into this struct at fixed offsets (cursor at +0x24, saved insns +0x28, tramp buffer +0x40, relo buffer +0x58, 41-slot/164-byte trampoline window). */
typedef struct {
	/* in */
	u64 func_addr;                                    /* +0x00 */
	u64 origin_addr;                                  /* +0x08 */
	u64 replace_addr;                                 /* +0x10 */
	u64 relo_addr;                                    /* +0x18 */
	/* out */
	s32 tramp_insts_num;                              /* +0x20 */
	s32 relo_insts_num;                               /* +0x24 (cursor) */
	u32 origin_insts[TRAMPOLINE_MAX_NUM]              /* +0x28 */
	    __attribute__((aligned(8)));
	u32 tramp_insts [TRAMPOLINE_MAX_NUM]
	    __attribute__((aligned(8)));
	u32 relo_insts  [RELOCATE_INST_NUM]
	    __attribute__((aligned(8)));
} hook_t __attribute__((aligned(8)));

int relocate_inst(hook_t *ctx, u64 src_pc, u32 inst);

int relo_b(hook_t *ctx, u64 src_pc, u32 inst, int class_top);
int relo_adr(hook_t *ctx, u64 src_pc, u32 inst, int class_top);
int relo_ldr(hook_t *ctx, u64 src_pc, u32 inst, int class_top);
int relo_cb(hook_t *ctx, u64 src_pc, u32 inst);
int relo_tb(hook_t *ctx, u64 src_pc, u32 inst);
int relo_ignore(hook_t *ctx, u32 inst);

u64 relo_in_tramp(hook_t *ctx, u64 target_pc);

s32 branch_from_to(u32 *tramp_buf, u64 src_addr, u64 dst_addr);
s32 branch_relative(u32 *buf,        u64 src_addr, u64 dst_addr);
s32 branch_absolute(u32 *buf,        u64 addr);
s32 ret_absolute(u32 *buf,        u64 addr);

hook_err_t hook_prepare(hook_t *hook);

/* Uses write_ro_memory () (NOT stop_machine); target must be quiescent. */
void hook_install(hook_t *hook);

void hook_remove(hook_t *hook);

/* Per-class trampoline length (4-byte units), indexed by class id: 0 B  / 1 B.cond / 2 BL / 3 ADR / 4 ADRP / 5..11 LDR variants / 12 CBZ / 13 CBNZ / 14 TBZ / 15 TBNZ / 16 IGNORE Initialiser: { 6,8,8,4,4,6,6,6,8,8,8,8,6,6,6,6,2 }. */
extern const s32 relo_len[17];

#endif /* DRIVER_HOOK_ENGINE_H */
