// SPDX-License-Identifier: GPL-2.0
// page-fault address harvest for cent.tmgp.sgame.
#ifndef DRIVER_HARVEST_H
#define DRIVER_HARVEST_H

#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/types.h>

/* 32-byte stride observed in both handlers; slot is in-use when key != 0. */
struct wz_hero_slot {
	u64 key;     /* X9 from faulting regs (sign-key) */
	u64 val1;    /* X8 */
	u64 val2;    /* X2 */
	u64 _pad;
};

#define WZ_HERO_SLOTS 50
#define WZ_TARGET_PKG "cent.tmgp.sgame"
#define WZ_ESR_LOW12 0x1F4u

/* Installed via hook_engine; tail-calls orig_do_page_fault after a KCFI type-id check (prefix word 0x6651B8C2). */
void my_do_page_fault(unsigned long addr, unsigned int esr, struct pt_regs *regs);

/* Kprobe fallback: reads user-mode reg file from task->stack at fixed byte offsets (0x3EC0..0x3FA0) — NOT the kprobe trap frame. */
int arm64_force_sig_fault_pre(struct kprobe *p, struct pt_regs *regs);

int install_harvest_hooks(void);

int wz_hero_addr_map_get(unsigned int idx, struct wz_hero_slot *out);
void wz_hero_addr_map_clear(void);
unsigned int wz_hero_addr_map_size(void);

#endif /* DRIVER_HARVEST_H */
