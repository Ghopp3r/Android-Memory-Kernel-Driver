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

/* Both harvest entry points are kprobe pre_handlers.  We probe do_mem_abort
 * (not do_page_fault, which is __kprobes-blacklisted) — same signature, same
 * arg layout (X0=far, X1=esr, X2=inner pt_regs *), and do_mem_abort dispatches
 * to do_page_fault unconditionally on arm64 so coverage is identical. */
int do_mem_abort_pre(struct kprobe *p, struct pt_regs *regs);
int arm64_force_sig_fault_pre(struct kprobe *p, struct pt_regs *regs);

int install_harvest_hooks(void);
void uninstall_harvest_hooks(void);

int wz_hero_addr_map_get(unsigned int idx, struct wz_hero_slot *out);
void wz_hero_addr_map_clear(void);
unsigned int wz_hero_addr_map_size(void);

#endif /* DRIVER_HARVEST_H */
