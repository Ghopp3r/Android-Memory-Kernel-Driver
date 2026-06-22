// SPDX-License-Identifier: GPL-2.0
// synthetic multitouch event injection (drained on host SYN_REPORT).
#ifndef DRIVER_INPUT_SYNTH_H
#define DRIVER_INPUT_SYNTH_H

#include <linux/input.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/* struct evpool / struct mt_slot live in <driver/types.h> — single source of truth. */
#include <driver/types.h>

int input_handle_event_handler_pre(struct kprobe *p, struct pt_regs *regs);

/* Like above, but first arg is input_handle * — deref handle->dev at +0x18. */
int input_handle_event_handler2_pre(struct kprobe *p, struct pt_regs *regs);

/* Acquires pool->lock then dev->event_lock (both irq-saved). Hard-capped at 0x401 with a BUG()-style trap to match the original BRK #0x5512. */
void handle_cache_events(struct input_dev *dev);

int input_mt_report_slot_state_with_id_cache(int id);

void touch_down(int slot, int x, int y, int pressure);
void touch_move(int slot, int x, int y);
void touch_up(int slot);

int install_input_hooks(void);

#endif /* DRIVER_INPUT_SYNTH_H */
